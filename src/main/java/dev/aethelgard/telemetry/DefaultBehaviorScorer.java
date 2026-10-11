package dev.aethelgard.telemetry;

/**
 * Concrete Decide organ. PURE FUNCTION: no mutable state, no I/O, no clocks —
 * deterministic given (previousWeight, metrics). Unit-testable with synthetic
 * metrics and zero sockets.
 *
 * Scoring model:
 *   penalty = malformedRate·W_MALFORMED + abuseRate·W_ABUSE
 *           + handshakeFailureRate·W_HS_FAIL + spikeRate·W_SPIKE
 *   reward  = W_CLEAN (only if the window was fully clean and traffic existed)
 *   weight' = clamp(previousWeight + reward − penalty, MIN, MAX)
 *
 * Escalation ladder with hysteresis (enter/exit thresholds separated by a wide
 * dead-band so a borderline peer cannot flap between states):
 *
 *   weight >  50  ................ NONE
 *    10 < weight ≤ 50 ............ DEMOTE
 *    0 < weight ≤ 10 ............. REVOKE      (enter band)
 *   weight ≤ 0 ................... QUARANTINE_NOMINATE
 *   recovery: weight ≥ 40 AND clean window ... READMIT  (exit band)
 *
 * The 30-point gap between REVOKE (≤10) and READMIT (≥40) IS the hysteresis:
 * a peer recovering from 12 → 15 stays revoked until its behavior carries it
 * clearly past 40, eliminating state-flapping on noisy metrics.
 */
public final class DefaultBehaviorScorer implements BehaviorScorer {

    /** Tunable thresholds and weights; immutable, safe to share. */
    public record Thresholds(
            float demoteCeiling,        // above: NONE
            float revokeFloor,          // at/below: REVOKE band
            float readmitCeiling,       // recovery exit band (hysteresis)
            double malformedRateLimit,  // events/sec tolerated
            double abuseRateLimit,
            double hsFailureRateLimit,
            long spikeTolerance,
            double weightMalformed,
            double weightAbuse,
            double weightHsFailure,
            double weightSpike,
            float cleanReward) {

        public static Thresholds defaults() {
            return new Thresholds(
                    50.0f,   // demoteCeiling
                    10.0f,   // revokeFloor
                    40.0f,   // readmitCeiling — 30-pt hysteresis dead-band
                    5.0,     // malformedRateLimit  (> 5/sec is abusive)
                    0.5,     // abuseRateLimit      (any real abuse is severe)
                    2.0,     // hsFailureRateLimit
                    3,       // spikeTolerance per window
                    3.0,     // weightMalformed per event/sec
                    15.0,    // weightAbuse per event/sec
                    5.0,     // weightHsFailure per event/sec
                    2.0,     // weightSpike per spike
                    2.0f);   // cleanReward per clean window
        }
    }

    private final Thresholds t;

    public DefaultBehaviorScorer(Thresholds thresholds) {
        this.t = thresholds;
    }

    public DefaultBehaviorScorer() {
        this(Thresholds.defaults());
    }

    @Override
    public ScoredVerdict evaluate(float previousWeight, PeerMetrics m) {
        boolean clean = m.malformedFrames() == 0
                && m.resourceAbuseEvents() == 0
                && m.handshakeFailures() == 0
                && m.latencySpikeCount() <= t.spikeTolerance();

        float updated = previousWeight;
        double penalty = 0;
        if (clean && !m.isIdle()) {
            // Well-behaved traffic: recover toward the ceiling.
            updated = clamp(updated + t.cleanReward());
        } else {
            penalty =
                    Math.max(0, m.malformedFrameRate() - t.malformedRateLimit()) * t.weightMalformed()
                            + Math.max(0, rateOf(m.resourceAbuseEvents(), m.observationWindowMillis()) - t.abuseRateLimit()) * t.weightAbuse()
                            + Math.max(0, rateOf(m.handshakeFailures(), m.observationWindowMillis()) - t.hsFailureRateLimit()) * t.weightHsFailure()
                            + Math.max(0, m.latencySpikeCount() - t.spikeTolerance()) * t.weightSpike();
            updated = clamp(updated - (float) penalty);
        }

        // ── Action selection: penalty-anchored ladder with hysteresis ──────
        // Bands anchor on the OBSERVED WINDOW, not the absolute weight: a
        // fresh peer at NEUTRAL with a clean window must never be revoked
        // merely because its weight sits near 0.
        ScoredVerdict.Action action;
        String rationale;
        if (penalty > 0) {
            // Punishing window: escalate by the post-penalty weight.
            if (updated <= NEUTRAL_WEIGHT) {
                action = ScoredVerdict.Action.QUARANTINE_NOMINATE;
                rationale = "weight %.1f ≤ 0 under active penalties: nominated for Layer 4 quarantine consensus".formatted(updated);
            } else if (updated <= t.revokeFloor()) {
                action = ScoredVerdict.Action.REVOKE;
                rationale = "weight %.1f in revoke band (0, %,.0f]: blocking future handshakes"
                        .formatted(updated, t.revokeFloor());
            } else {
                action = ScoredVerdict.Action.DEMOTE;
                rationale = "penalty %.1f applied, weight now %.1f: tightening observation"
                        .formatted(penalty, updated);
            }
        } else if (clean && !m.isIdle()) {
            if (previousWeight < t.readmitCeiling() && updated >= t.readmitCeiling()) {
                // Hysteresis exit: re-admission fires exactly when a CLEAN
                // window carries the weight across the readmit ceiling from
                // below. The crossing is the hysteresis: flapping back under
                // it requires dirty windows (which penalize), so a borderline
                // peer cannot oscillate between REVOKE and READMIT.
                action = ScoredVerdict.Action.READMIT;
                rationale = "recovered to %.1f ≥ %,.0f with clean window: re-admitting"
                        .formatted(updated, t.readmitCeiling());
            } else {
                action = ScoredVerdict.Action.NONE;
                rationale = "weight %.1f healthy".formatted(updated);
            }
        } else {
            // Idle or exactly-at-limit: hold position, no reward, no penalty.
            action = ScoredVerdict.Action.NONE;
            rationale = "no penalty signal; weight held at %.1f".formatted(updated);
        }

        return new ScoredVerdict(updated, action, rationale);
    }

    private static double rateOf(long events, long windowMillis) {
        return events / (windowMillis / 1000.0);
    }

    private static float clamp(float w) {
        return Math.clamp(w, MIN_WEIGHT, MAX_WEIGHT);
    }
}
