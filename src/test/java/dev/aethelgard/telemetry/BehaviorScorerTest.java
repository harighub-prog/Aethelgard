package dev.aethelgard.telemetry;

import dev.aethelgard.telemetry.BehaviorScorer.ScoredVerdict;
import dev.aethelgard.telemetry.BehaviorScorer.ScoredVerdict.Action;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure-function verification of the Decide organ: synthetic PeerMetrics in,
 * exact verdicts out — no sockets, no event loops, no sensor state.
 * Determinism and hysteresis are the properties under test.
 */
class BehaviorScorerTest {

    private static final long WINDOW = 10_000L; // 10 s observation window
    private final DefaultBehaviorScorer scorer = new DefaultBehaviorScorer();

    // ── Metric factories ────────────────────────────────────────────────────

    private static PeerMetrics clean(long frames) {
        return new PeerMetrics("peer", WINDOW, 0, 0, 0.0, 0, 1, frames, frames, 5.0, 0, 1.0);
    }

    private static PeerMetrics malformedAttack(double framesPerSec) {
        return new PeerMetrics("peer", WINDOW,
                (long) (framesPerSec * WINDOW / 1000.0), 0, framesPerSec,
                0, 1, 10, 10, 5.0, 0, 0.1);
    }

    private static PeerMetrics abuse(long abuseEvents) {
        return new PeerMetrics("peer", WINDOW, 0, abuseEvents,
                (double) abuseEvents * 1000 / WINDOW, 0, 1, 10, 10, 5.0, 0, 0.5);
    }

    private static PeerMetrics handshakeFlooding(int failures) {
        return new PeerMetrics("peer", WINDOW, 0, 0, 0.0, failures, 0, 0, 0, 0.0, 0, 1.0);
    }

    private static PeerMetrics latencySpikes(long spikes) {
        return new PeerMetrics("peer", WINDOW, 0, 0, 0.0, 0, 10, 10, 10, 5.0, spikes, 1.0);
    }

    // ── Ladder thresholds ───────────────────────────────────────────────────

    @Test
    @DisplayName("Healthy traffic at neutral weight -> NONE, weight unchanged")
    void healthyPeerStaysNone() {
        ScoredVerdict v = scorer.evaluate(0.0f, clean(500));
        assertEquals(Action.NONE, v.action());
        assertEquals(2.0f, v.updatedWeight(), 0.001f, "clean window earns the reward");
    }

    @Test
    @DisplayName("Exactly-at-limit malformed rate (5/sec) is tolerated -> NONE")
    void atLimitIsTolerated() {
        ScoredVerdict v = scorer.evaluate(100.0f, malformedAttack(5.0));
        assertEquals(Action.NONE, v.action(), "penalty is max(0, rate - limit) = 0");
        assertEquals(100.0f, v.updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("Above-limit malformed rate starts demotion path")
    void overLimitDemotes() {
        // 10/sec over a 10s window = 100 events; penalty = (10-5)*3 = 15 → 100-15 = 85 → DEMOTE
        ScoredVerdict v = scorer.evaluate(100.0f, malformedAttack(10.0));
        assertEquals(Action.DEMOTE, v.action());
        assertEquals(85.0f, v.updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("Sustained malformed flood crosses the revoke band")
    void floodRevokes() {
        // 30/sec: penalty = (30-5)*3 = 75 → 100-75 = 25 → DEMOTE (not yet revoke)
        assertEquals(Action.DEMOTE, scorer.evaluate(100.0f, malformedAttack(30.0)).action());
        // 40/sec: penalty = 105 → 100-105 clamped... weight 0 → QUARANTINE
        ScoredVerdict v = scorer.evaluate(50.0f, malformedAttack(40.0));
        // penalty (40-5)*3=105 → 50-105 = -55 → QUARANTINE
        assertEquals(Action.QUARANTINE_NOMINATE, v.action());
        assertEquals(-55.0f, v.updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("Resource abuse is weighted 5x malformed — single event near-quarantines")
    void resourceAbuseIsSevere() {
        // 1 abuse event over 10s = 0.1/sec > 0.5 limit? No: 0.1 < 0.5 → no penalty.
        assertEquals(Action.NONE, scorer.evaluate(100.0f, abuse(1)).action());
        // 10 events over 10s = 1.0/sec: penalty = (1.0-0.5)*15 = 7.5 → 92.5 DEMOTE
        ScoredVerdict v = scorer.evaluate(100.0f, abuse(10));
        assertEquals(Action.DEMOTE, v.action());
        assertEquals(92.5f, v.updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("TLS handshake flooding drains weight into the revoke band")
    void handshakeFloodingRevokes() {
        // 10 failures / 10s = 1.0/sec: penalty = (1-2)... max(0,·)=0 → NONE
        assertEquals(Action.NONE, scorer.evaluate(100.0f, handshakeFlooding(10)).action());
        // 50 failures = 5.0/sec: penalty = (5-2)*5 = 15 → 85 DEMOTE
        assertEquals(Action.DEMOTE, scorer.evaluate(100.0f, handshakeFlooding(50)).action());
        // 200 failures = 20/sec: penalty = 90 → 100-90 = 10 → REVOKE (boundary inclusive)
        ScoredVerdict v = scorer.evaluate(100.0f, handshakeFlooding(200));
        assertEquals(Action.REVOKE, v.action());
        assertEquals(10.0f, v.updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("Latency spikes beyond tolerance penalize")
    void spikesPenalize() {
        // 10 spikes, tolerance 3: penalty = 7*2 = 14 → 100-14 = 86 → DEMOTE
        ScoredVerdict v = scorer.evaluate(100.0f, latencySpikes(10));
        assertEquals(Action.DEMOTE, v.action());
        assertEquals(86.0f, v.updatedWeight(), 0.001f);
    }

    // ── Hysteresis ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("Hysteresis: revoked peer with mildly improving traffic stays revoked (no flapping)")
    void revokedPeerDoesNotFlap() {
        // Weight 10 (just revoked). Clean window: +2 → 12 < 40 readmit ceiling
        // → NONE: the registry revocation persists until the ceiling is crossed.
        ScoredVerdict v = scorer.evaluate(10.0f, clean(100));
        assertEquals(Action.NONE, v.action());
        assertEquals(12.0f, v.updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("Hysteresis: recovery to 39 is NOT enough; only ≥40 with clean window re-admits")
    void readmitRequiresCleanWindowAndCeiling() {
        // previousWeight 37: +2 = 39 < 40 readmit ceiling → NONE, still revoked.
        assertEquals(Action.NONE, scorer.evaluate(37.0f, clean(100)).action());
        // previous 38: +2 = 40 ≥ 40 AND clean → READMIT
        ScoredVerdict v = scorer.evaluate(38.0f, clean(100));
        assertEquals(Action.READMIT, v.action());
        assertEquals(40.0f, v.updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("Hysteresis: high weight reached via dirty window does NOT re-admit")
    void dirtyWindowBlocksReadmission() {
        // previousWeight 38, malformed rate just at limit (no penalty): still 'clean' is false
        PeerMetrics borderline = new PeerMetrics("peer", WINDOW,
                50, 0, 5.0, 0, 1, 100, 100, 5.0, 0, 0.95);
        // clean flag = false (malformedFrames != 0) → no reward, no readmit even at high weight
        ScoredVerdict v = scorer.evaluate(80.0f, borderline);
        assertEquals(Action.NONE, v.action(), "at-limit malformed keeps weight high but forbids READMIT");
        assertEquals(80.0f, v.updatedWeight(), 0.001f);
    }

    // ── Quarantine nomination ───────────────────────────────────────────────

    @Test
    @DisplayName("Weight ≤ 0 under penalty nominates for quarantine; quarantine persists")
    void zeroWeightQuarantines() {
        assertEquals(Action.QUARANTINE_NOMINATE, scorer.evaluate(0.0f, malformedAttack(10.0)).action());
        // A quarantined peer behaving cleanly: weight creeps up (-100 + 2) but
        // stays far below the 40 readmit ceiling → NONE, registry revocation
        // persists. Only Layer 4 consensus can release an isolated peer early.
        ScoredVerdict v = scorer.evaluate(-100.0f, clean(100));
        assertEquals(Action.NONE, v.action());
        assertEquals(-98.0f, v.updatedWeight(), 0.001f);
    }

    // ── Determinism & clamping ──────────────────────────────────────────────

    @Test
    @DisplayName("Pure function: identical inputs produce identical verdicts")
    void deterministic() {
        PeerMetrics m = malformedAttack(10.0);
        ScoredVerdict a = scorer.evaluate(50.0f, m);
        ScoredVerdict b = scorer.evaluate(50.0f, m);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("Weights clamp to [-100, +100]")
    void clamped() {
        assertEquals(100.0f, scorer.evaluate(100.0f, clean(1000)).updatedWeight(), 0.001f);
        assertEquals(-100.0f, scorer.evaluate(-100.0f, malformedAttack(50.0)).updatedWeight(), 0.001f);
    }

    @Test
    @DisplayName("Idle peer: no reward, no penalty — weight untouched")
    void idlePeerHoldsWeight() {
        PeerMetrics idle = PeerMetrics.empty("peer", WINDOW);
        ScoredVerdict v = scorer.evaluate(42.0f, idle);
        assertEquals(Action.NONE, v.action());
        assertEquals(42.0f, v.updatedWeight(), 0.001f);
    }
}
