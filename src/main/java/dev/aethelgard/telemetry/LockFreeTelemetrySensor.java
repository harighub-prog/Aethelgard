package dev.aethelgard.telemetry;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Concrete Perceive organ. Lock-free per-peer counters organized as ring
 * buckets for windowed rate computation.
 *
 * Concurrency design:
 * - The outer registry is a ConcurrentHashMap created once per peer on first
 *   sight (computeIfAbsent — at most one allocation per peer lifetime).
 * - Event totals are LongAdders: contention-free increments from any number
 *   of event loops, no CAS loops on hot counters.
 * - Windowed rates use a fixed ring of atomic long buckets indexed by
 *   (currentTimeMillis / bucketMillis) % BUCKETS. A write to a stale bucket
 *   (index older than the current epoch) is treated as a fresh window: the
 *   CAS-based rollover in {@link Bucket#add} resets it before incrementing.
 *   No sweep thread, no locks, O(1) per event, O(BUCKETS) per snapshot.
 * - Latency EWMA is stored bit-packed in an AtomicLong
 *   (Double.doubleToLongBits) and updated with a CAS retry loop — an
 *   occasional lost update is statistically irrelevant for an EWMA.
 *
 * Snapshot rule: {@link #snapshot(String)} reads counters into an immutable
 * PeerMetrics on the CALLING thread (the decision loop's virtual thread);
 * event-loop threads never wait on it because every primitive they touch is
 * non-blocking.
 */
public final class LockFreeTelemetrySensor implements PeerTelemetrySensor {

    static final int BUCKETS = 16; // ring size; window = BUCKETS * bucketMillis

    private final long bucketMillis;
    private final long spikeThresholdNanos;
    private static final double EWMA_ALPHA = 0.25;

    private final ConcurrentHashMap<String, PeerCounters> peers = new ConcurrentHashMap<>();

    /** One peer's counter block. Created under computeIfAbsent, then lock-free. */
    private static final class PeerCounters {
        final LongAdder malformed = new LongAdder();
        final LongAdder resourceAbuse = new LongAdder();
        final LongAdder handshakeFailures = new LongAdder();
        final LongAdder handshakeSuccesses = new LongAdder();
        final LongAdder framesSent = new LongAdder();
        final Bucket malformedWindow = new Bucket();
        final Bucket abuseWindow = new Bucket();
        final Bucket hsFailureWindow = new Bucket();
        final Bucket framesGoodWindow = new Bucket();
        final Bucket spikesWindow = new Bucket();
        final AtomicLong latencyEwmaMillisBits = new AtomicLong(0); // 0.0 = unknown
        final AtomicLong lastSentNanos = new AtomicLong(0);         // ack-matcher anchor
    }

    /** Ring bucket with lock-free stale-window rollover. */
    private static final class Bucket {
        private final AtomicLong[] slots = new AtomicLong[BUCKETS];
        {
            for (int i = 0; i < BUCKETS; i++) {
                slots[i] = new AtomicLong();
            }
        }

        void add(long bucketMillis, long delta) {
            long fullEpoch = System.currentTimeMillis() / bucketMillis;
            // Stamp only the low 32 bits: full epoch (~2.8e10 for 62 ms buckets)
            // overflows the stamp field. The index uses the full epoch; the age
            // comparison uses unsigned subtraction, which survives wraparound.
            long stamp = fullEpoch & 0xFFFFFFFFL;
            AtomicLong slot = slots[(int) (fullEpoch % BUCKETS)];
            long v = slot.get();
            if ((v >>> 32) != stamp) {
                // Stale slot: restamp it to the current epoch before counting.
                slot.compareAndSet(v, stamp << 32);
            }
            slot.incrementAndGet(); // low 32 bits: count; high 32 bits: epoch stamp
        }

        /** Sum of the buckets covering the last (BUCKETS-1) epochs + current. */
        long sum(long bucketMillis) {
            long fullEpoch = System.currentTimeMillis() / bucketMillis;
            long stamp = fullEpoch & 0xFFFFFFFFL;
            long total = 0;
            for (AtomicLong slot : slots) {
                long v = slot.get();
                long age = (stamp - (v >>> 32)) & 0xFFFFFFFFL; // unsigned: old stamps -> huge age
                if (age < BUCKETS) {
                    total += v & 0xFFFFFFFFL;
                }
            }
            return total;
        }
    }

    public LockFreeTelemetrySensor(long windowMillis, long spikeThresholdMillis) {
        if (windowMillis <= 0) {
            throw new IllegalArgumentException("windowMillis must be positive");
        }
        this.bucketMillis = Math.max(1, windowMillis / BUCKETS);
        this.spikeThresholdNanos = spikeThresholdMillis * 1_000_000L;
    }

    /* ── Ingestion: event-loop threads only, all non-blocking ─────────────── */

    @Override
    public void recordMalformedFrame(String peerKey) {
        PeerCounters c = countersFor(peerKey);
        c.malformed.increment();
        c.malformedWindow.add(bucketMillis, 1);
    }

    @Override
    public void recordResourceAbuse(String peerKey) {
        PeerCounters c = countersFor(peerKey);
        c.resourceAbuse.increment();
        c.abuseWindow.add(bucketMillis, 1);
    }

    @Override
    public void recordHandshakeSuccess(String peerKey) {
        countersFor(peerKey).handshakeSuccesses.increment();
    }

    @Override
    public void recordHandshakeFailure(String peerKey) {
        PeerCounters c = countersFor(peerKey);
        c.handshakeFailures.increment();
        c.hsFailureWindow.add(bucketMillis, 1);
    }

    /**
     * Records an inbound frame. latencyNanos == 0 delegates RTT computation to
     * the ack-matcher: the delta between now and this peer's last outbound
     * frame (recorded by {@link #recordFrameSent}). A sender that receives an
     * application-level response therefore yields a true round-trip sample
     * without any protocol change.
     */
    @Override
    public void recordFrameReceived(String peerKey, long latencyNanos) {
        PeerCounters c = countersFor(peerKey);
        c.framesGoodWindow.add(bucketMillis, 1);
        long latency = latencyNanos;
        if (latency == 0) {
            long lastSent = c.lastSentNanos.get();
            if (lastSent > 0) {
                latency = System.nanoTime() - lastSent;
            }
        }
        if (latency > spikeThresholdNanos) {
            c.spikesWindow.add(bucketMillis, 1);
        }
        if (latency > 0) {
            updateEwma(c, latency / 1_000_000.0);
        }
    }

    @Override
    public void recordFrameSent(String peerKey) {
        PeerCounters c = countersFor(peerKey);
        c.framesSent.increment();
        c.lastSentNanos.set(System.nanoTime());
    }

    private void updateEwma(PeerCounters c, double sampleMillis) {
        while (true) {
            long bits = c.latencyEwmaMillisBits.get();
            double current = Double.longBitsToDouble(bits);
            double updated = (bits == 0) ? sampleMillis
                    : EWMA_ALPHA * sampleMillis + (1 - EWMA_ALPHA) * current;
            long newBits = Double.doubleToRawLongBits(updated);
            if (c.latencyEwmaMillisBits.compareAndSet(bits, newBits)) {
                return;
            }
        }
    }

    private PeerCounters countersFor(String peerKey) {
        return peers.computeIfAbsent(peerKey, k -> new PeerCounters());
    }

    /* ── Extraction: any thread (decision loop) ───────────────────────────── */

    @Override
    public PeerMetrics snapshot(String peerKey) {
        PeerCounters c = peers.get(peerKey);
        long windowMillis = bucketMillis * BUCKETS;
        if (c == null) {
            return PeerMetrics.empty(peerKey, windowMillis);
        }
        long malformed = c.malformedWindow.sum(bucketMillis);
        long abuse = c.abuseWindow.sum(bucketMillis);
        long hsFail = c.hsFailureWindow.sum(bucketMillis);
        long good = c.framesGoodWindow.sum(bucketMillis);

        double windowSeconds = windowMillis / 1000.0;
        double hygiene = (good + malformed) == 0 ? 1.0 : (double) good / (good + malformed);

        double ewma = Double.longBitsToDouble(c.latencyEwmaMillisBits.get());
        return new PeerMetrics(
                peerKey,
                windowMillis,
                malformed,
                abuse,
                malformed / windowSeconds,
                hsFail,
                c.handshakeSuccesses.sum(),
                good,
                c.framesSent.sum(),
                ewma,
                c.spikesWindow.sum(bucketMillis),
                hygiene);
    }

    @Override
    public Iterable<String> activePeers() {
        List<String> keys = new ArrayList<>(peers.size());
        for (String k : peers.keySet()) {
            keys.add(k);
        }
        return keys;
    }

    @Override
    public void evict(String peerKey) {
        peers.remove(peerKey);
    }
}
