package dev.aethelgard.telemetry;

/**
 * The Decide organ: converts an immutable {@link PeerMetrics} snapshot into a
 * bounded trust weight and a recommended action.
 *
 * Contract:
 * - PURE FUNCTION. Implementations must be stateless (or carry only immutable
 *   configuration) and side-effect free. All thread-safety concerns vanish;
 *   the decision loop can call it from a Virtual Thread without coordination.
 *   This is what makes scoring unit-testable: feed synthetic PeerMetrics,
 *   assert the verdict, no sockets involved.
 * - DETERMINISTIC. Same snapshot ⇒ same verdict. Any randomness (e.g. for
 *   adversarial robustness later) must be injected as an explicit parameter.
 *
 * Scoring model (to be tuned in implementation):
 *   weight' = clamp(weight + Σ penalties − Σ rewards, MIN_WEIGHT, MAX_WEIGHT)
 * Penalties scale with severity (resource abuse > malformed > handshake
 * failure > latency), rewards decay toward a neutral baseline so a peer that
 * reforms can recover — but never above its admitted ceiling.
 */
public interface BehaviorScorer {

    /** Trust weight bounds. Zero or below ⇒ quarantine-eligible (Layer 4 signal). */
    float MIN_WEIGHT = -100.0f;
    float MAX_WEIGHT = 100.0f;
    float NEUTRAL_WEIGHT = 0.0f;

    /**
     * Evaluates one observation window.
     *
     * @param previousWeight the peer's current trust weight (NEUTRAL_WEIGHT if unknown)
     * @param metrics        immutable snapshot from the telemetry sensor
     * @return the recommended action with the updated weight
     */
    ScoredVerdict evaluate(float previousWeight, PeerMetrics metrics);

    /**
     * Result of one scoring cycle: the updated weight and the action the
     * decision loop should take. The loop is free to defer or escalate the
     * action (e.g. quarantine requires Layer 4 consensus — the scorer only
     * NOMINATES a peer for it).
     */
    record ScoredVerdict(float updatedWeight, Action action, String rationale) {

        public enum Action {
            /** Weight healthy — no-op. */
            NONE,
            /** Weight declining — tighten observation, optionally probe the peer. */
            DEMOTE,
            /** Weight below soft floor — block new handshakes via trustManager.revoke(). */
            REVOKE,
            /** Weight at/below zero — nominate for Layer 4 quarantine gossip. */
            QUARANTINE_NOMINATE,
            /** Weight recovered past the hysteresis band — re-admit via trustManager.trust(). */
            READMIT
        }
    }
}
