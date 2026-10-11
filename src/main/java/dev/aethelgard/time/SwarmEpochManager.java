package dev.aethelgard.time;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Layer 7: Swarm Clock Convergence Manager.
 *
 * Maintains a localized offset (in nanoseconds) from the host system clock to the
 * estimated true swarm time. Each call to {@link #adjustOffset} feeds one peer
 * clock sample into a trust-weighted Fault-Tolerant Average (FTA) algorithm, pulling
 * the local offset toward the swarm centroid while discarding adversarial extremes.
 *
 * <h3>Algorithm: Trust-Weighted Fault-Tolerant Average (WTFA)</h3>
 * <p>
 * Classic FTA (Byzantine fault tolerance) filters outliers beyond a deviation
 * threshold before computing the centroid. This implementation extends that model
 * by scaling each sample's influence by the submitting peer's normalized trust weight,
 * making the convergence resistant to Sybil-style clock poisoning:
 * <ul>
 *   <li>Samples whose absolute deviation from the running swarm estimate exceeds
 *       {@link #MAX_ACCEPTABLE_SKEW_NS} are unconditionally rejected, regardless
 *       of reported trust. This provides hard Byzantine fault containment.</li>
 *   <li>Accepted samples are blended into the running offset using an exponentially-
 *       weighted moving average (EWMA) where the alpha is scaled by the peer's
 *       trust weight, clamped to [{@code MIN_ALPHA}, {@code MAX_ALPHA}]. High-trust
 *       peers pull the clock faster; low-trust peers apply negligible influence.</li>
 * </ul>
 *
 * <h3>Zero-Heap Allocation Contract</h3>
 * <p>
 * All state is held in {@link AtomicLong} primitives packed via
 * {@link Double#doubleToRawLongBits} / {@link Double#longBitsToDouble}. No
 * {@code Double} boxes, no intermediate arrays. The CAS retry loop in
 * {@link #adjustOffset} is O(1) amortized — contention on the clock-update path
 * is inherently rare (one update per incoming peer heartbeat).
 *
 * <h3>Swarm Time API</h3>
 * <ul>
 *   <li>{@link #swarmNanoTime()} — corrected monotonic nanoseconds; replaces every
 *       bare {@code System.nanoTime()} call inside epoch-sensitive subsystems.</li>
 *   <li>{@link #swarmEpochMillis()} — corrected wall-clock milliseconds aligned to
 *       swarm time; safe for window boundary calculations.</li>
 * </ul>
 */
public final class SwarmEpochManager {

    /**
     * Maximum acceptable clock skew from the current swarm estimate.
     * Samples more than 120 seconds off the local estimate are unconditionally
     * rejected as Byzantine / adversarial. Value in nanoseconds.
     */
    public static final long MAX_ACCEPTABLE_SKEW_NS = 120_000_000_000L; // 120 s

    /**
     * Minimum EWMA blending alpha: a zero-trust peer still contributes 1% weight
     * to prevent complete starvation of new information from recovering peers.
     */
    private static final double MIN_ALPHA = 0.01;

    /**
     * Maximum EWMA blending alpha: even a fully trusted peer's single sample is
     * capped at 25% influence per adjustment to prevent single-sample jumps.
     */
    private static final double MAX_ALPHA = 0.25;

    /**
     * Swarm-level offset from {@code System.nanoTime()}, stored as raw
     * {@code long} bits via {@link Double#doubleToRawLongBits} to allow
     * lock-free CAS updates. The initial value is {@code 0.0}, meaning the
     * local clock exactly equals the swarm estimate until peer samples arrive.
     */
    private final AtomicLong offsetNanosBits = new AtomicLong(Double.doubleToRawLongBits(0.0));

    /** Monotonically increasing count of samples accepted into the convergence model. */
    private final LongAdder acceptedSamples = new LongAdder();

    /** Monotonically increasing count of samples rejected for excessive skew. */
    private final LongAdder rejectedSamples = new LongAdder();

    /** Monotonically increasing count of samples rejected for invalid trust weight. */
    private final LongAdder invalidWeightRejections = new LongAdder();

    public SwarmEpochManager() {
    }

    /**
     * Feeds one peer clock offset sample into the trust-weighted FTA convergence model.
     *
     * <p>This is the sole mutation point for the swarm offset. All reads use the
     * resulting atomic long directly — no locks are held across the CAS loop.
     *
     * @param peerOffsetSampleNanos the peer's reported offset from the local host
     *                              {@code System.nanoTime()}, in nanoseconds. Positive
     *                              values mean the peer believes the local clock is slow.
     * @param peerTrustWeight       a normalized trust weight in the range {@code [0.0, 1.0]},
     *                              where {@code 1.0} is full trust and {@code 0.0} is minimal.
     *                              Values outside this range are rejected.
     * @return {@code true} if the sample was accepted and folded into the offset;
     *         {@code false} if it was rejected (adversarial skew or invalid weight).
     */
    public boolean adjustOffset(long peerOffsetSampleNanos, double peerTrustWeight) {
        // Guard 1: trust weight must be normalized
        if (peerTrustWeight < 0.0 || peerTrustWeight > 1.0 || Double.isNaN(peerTrustWeight)) {
            invalidWeightRejections.increment();
            return false;
        }

        // Guard 2: Fault-Tolerant Average outlier rejection
        // Compute deviation against the current running estimate to detect adversarial samples.
        long currentBits = offsetNanosBits.get();
        double currentOffsetNanos = Double.longBitsToDouble(currentBits);
        long deviation = Math.abs(peerOffsetSampleNanos - (long) currentOffsetNanos);
        if (deviation > MAX_ACCEPTABLE_SKEW_NS) {
            rejectedSamples.increment();
            return false;
        }

        // Compute trust-scaled EWMA alpha: alpha = MIN_ALPHA + peerTrustWeight * (MAX_ALPHA - MIN_ALPHA)
        // This maps [0.0, 1.0] trust → [0.01, 0.25] alpha, preserving monotonicity.
        double alpha = MIN_ALPHA + peerTrustWeight * (MAX_ALPHA - MIN_ALPHA);

        // CAS retry loop: update the packed double via lock-free compare-and-set.
        // Contention probability is negligible — clock adjustment is a low-frequency
        // control-plane event, not a data-plane hot path.
        while (true) {
            long prevBits = offsetNanosBits.get();
            double prevOffset = Double.longBitsToDouble(prevBits);

            // Trust-weighted EWMA: newOffset = alpha * sample + (1 - alpha) * previous
            double newOffset = alpha * (double) peerOffsetSampleNanos + (1.0 - alpha) * prevOffset;
            long newBits = Double.doubleToRawLongBits(newOffset);

            if (offsetNanosBits.compareAndSet(prevBits, newBits)) {
                acceptedSamples.increment();
                return true;
            }
            // Another thread raced us — re-read and retry. The retry
            // inherently incorporates the concurrent update, keeping
            // convergence monotonically consistent.
        }
    }

    /**
     * Returns the current swarm-corrected monotonic nanosecond timestamp.
     *
     * <p>Replaces bare {@code System.nanoTime()} calls inside any subsystem that
     * must align to the swarm epoch (e.g., telemetry window boundaries,
     * deterministic trigger gates, gossip heartbeat scheduling).
     *
     * <p>This method performs a single volatile read plus a long addition — O(1),
     * branch-free, zero heap allocation.
     *
     * @return swarm-aligned nanosecond time, as {@code System.nanoTime() + offsetNanos}.
     */
    public long swarmNanoTime() {
        long offsetNanos = (long) Double.longBitsToDouble(offsetNanosBits.get());
        return System.nanoTime() + offsetNanos;
    }

    /**
     * Returns the current swarm-corrected wall-clock epoch in milliseconds.
     *
     * <p>Uses the offset derived from nanosecond samples converted to milliseconds.
     * Suitable for logging, window key computation, and cross-node timestamp comparison.
     */
    public long swarmEpochMillis() {
        long offsetNanos = (long) Double.longBitsToDouble(offsetNanosBits.get());
        long offsetMillis = offsetNanos / 1_000_000L;
        return System.currentTimeMillis() + offsetMillis;
    }

    /**
     * Returns the current raw swarm offset from the host clock, in nanoseconds.
     * Useful for diagnostics and testing; not intended for time-critical hot paths.
     */
    public long currentOffsetNanos() {
        return (long) Double.longBitsToDouble(offsetNanosBits.get());
    }

    /**
     * Number of peer samples successfully incorporated into the convergence model.
     */
    public long acceptedSamples() {
        return acceptedSamples.sum();
    }

    /**
     * Number of peer samples rejected due to excessive clock skew deviation
     * (exceeding {@link #MAX_ACCEPTABLE_SKEW_NS}).
     */
    public long rejectedSamples() {
        return rejectedSamples.sum();
    }

    /**
     * Number of peer samples rejected due to an invalid trust weight parameter
     * (outside {@code [0.0, 1.0]} or NaN).
     */
    public long invalidWeightRejections() {
        return invalidWeightRejections.sum();
    }

    /**
     * Resets the swarm offset to zero (local clock == swarm estimate).
     *
     * <p>Should only be used during initialization or after a full swarm restart
     * where no prior offset data is meaningful. Never call this on a live node
     * with active peer connections.
     */
    public void resetOffset() {
        offsetNanosBits.set(Double.doubleToRawLongBits(0.0));
    }
}
