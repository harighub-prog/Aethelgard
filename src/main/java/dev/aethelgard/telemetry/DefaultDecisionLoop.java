package dev.aethelgard.telemetry;

import dev.aethelgard.crypto.AethelgardTrustManager;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Concrete Act organ. One ScheduledExecutorService (virtual-thread factory)
 * drives the Perceive → Decide → Act cycle at a fixed cadence.
 *
 * Threading discipline:
 * - The cycle runs on a virtual thread, NEVER on a Netty event loop.
 * - Sensor snapshots are plain reads of atomics — off-loop polling is safe by
 *   the sensor's contract.
 * - Trust-registry updates (revoke/trust) are lock-free CAS operations on the
 *   ConcurrentHashMap inside AethelgardTrustManager — safe from any thread,
 *   so no EventExecutor hop is required for them. The executor hop
 *   (per the architectural contract) is reserved for actions that touch
 *   sockets — Layer 4's severance — surfaced here as the quarantineListener
 *   callback which the gossip engine will register.
 *
 * Weight persistence: the loop owns the authoritative weight table
 * (ConcurrentHashMap, single-writer by cycle design). Seed weights start at
 * NEUTRAL.
 */
public final class DefaultDecisionLoop implements DecisionLoop {

    private final PeerTelemetrySensor sensor;
    private final BehaviorScorer scorer;
    private final AethelgardTrustManager trustManager;
    private final long cycleIntervalMillis;
    private final Consumer<String> quarantineListener; // Layer 4 hook, may be null

    private final Map<String, Float> weights = new ConcurrentHashMap<>();
    private final Map<String, BehaviorScorer.ScoredVerdict.Action> lastActions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public DefaultDecisionLoop(PeerTelemetrySensor sensor,
                               BehaviorScorer scorer,
                               AethelgardTrustManager trustManager,
                               long cycleIntervalMillis,
                               Consumer<String> quarantineListener) {
        this.sensor = sensor;
        this.scorer = scorer;
        this.trustManager = trustManager;
        this.cycleIntervalMillis = cycleIntervalMillis;
        this.quarantineListener = quarantineListener;
        // Virtual threads: the cycle blocks trivially on snapshot reads and is
        // cheap to schedule; carrier threads are never pinned by our code.
        this.scheduler = Executors.newSingleThreadScheduledExecutor(
                Thread.ofVirtual().name("aethelgard-decision-", 0).factory());
    }

    @Override
    public void start() {
        if (running.compareAndSet(false, true)) {
            scheduler.scheduleWithFixedDelay(
                    this::runSingleCycleGuarded,
                    cycleIntervalMillis,
                    cycleIntervalMillis,
                    TimeUnit.MILLISECONDS);
        }
    }

    @Override
    public void runSingleCycle() {
        for (String peerKey : sensor.activePeers()) {
            PeerMetrics metrics = sensor.snapshot(peerKey);   // Perceive (off-loop, immutable copy)
            float previous = weights.getOrDefault(peerKey, BehaviorScorer.NEUTRAL_WEIGHT);
            BehaviorScorer.ScoredVerdict verdict = scorer.evaluate(previous, metrics); // Decide (pure)
            weights.put(peerKey, verdict.updatedWeight());
            act(peerKey, verdict, lastActions.get(peerKey));  // Act
            lastActions.put(peerKey, verdict.action());
        }
    }

    private void runSingleCycleGuarded() {
        try {
            runSingleCycle();
        } catch (Throwable t) {
            // A cycle failure must never kill the scheduler thread.
            System.err.println("[DecisionLoop] cycle failed: " + t);
        }
    }

    private void act(String peerKey, BehaviorScorer.ScoredVerdict verdict,
                     BehaviorScorer.ScoredVerdict.Action previousAction) {
        switch (verdict.action()) {
            case NONE -> { /* healthy; nothing to do */ }
            case DEMOTE -> System.out.printf("[DecisionLoop] DEMOTE %s: %s%n", peerKey, verdict.rationale());
            case REVOKE -> {
                // Lock-free registry mutation: blocks the peer's FUTURE TLS
                // handshakes instantly (Layer 2 verified). No event-loop hop
                // needed — ConcurrentHashMap CAS from this virtual thread.
                trustManager.revokeKeyId(peerKey);
                System.out.printf("[DecisionLoop] REVOKE %s: %s%n", peerKey, verdict.rationale());
            }
            case QUARANTINE_NOMINATE -> {
                trustManager.revokeKeyId(peerKey);
                System.out.printf("[DecisionLoop] QUARANTINE_NOMINATE %s: %s%n", peerKey, verdict.rationale());
                if (quarantineListener != null) {
                    // Layer 4 seam: sign + gossip the quarantine statement.
                    quarantineListener.accept(peerKey);
                }
            }
            case READMIT -> {
                trustManager.admitKeyId(peerKey);
                System.out.printf("[DecisionLoop] READMIT %s: %s%n", peerKey, verdict.rationale());
            }
        }
    }

    /** Current authoritative weight for a peer (observability + tests). */
    public float weightOf(String peerKey) {
        return weights.getOrDefault(peerKey, BehaviorScorer.NEUTRAL_WEIGHT);
    }

    @Override
    public void close() {
        running.set(false);
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scheduler.shutdownNow();
        }
    }
}
