package dev.aethelgard.time;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Layer 7 Verification Matrix: Deterministic Time Triggering and Swarm Clock Convergence.
 *
 * All tests run under Netty's {@code PARANOID} resource leak detector
 * (declared in the Surefire argLine in pom.xml). Since Layer 7 deals only in
 * primitive {@code long} values and {@link AtomicLong} — no {@code ByteBuf} or
 * heap object graphs — there is zero risk of managed memory leaks; the paranoid
 * level serves here as an external sanity check that no upstream dependency
 * allocates un-released buffers as a side effect.
 *
 * <h3>Properties under test</h3>
 * <ol>
 *   <li>Clock convergence: synthetic peer samples from honest nodes pull the local
 *       offset toward the true swarm centroid monotonically.</li>
 *   <li>Byzantine isolation: adversarial samples (high skew or invalid trust) are
 *       unconditionally rejected, leaving the offset unchanged.</li>
 *   <li>Epoch gate semantics: {@link DeterministicTimeTrigger#isWindowBoundaryReached}
 *       correctly fires on epoch advance and suppresses on intra-epoch calls.</li>
 *   <li>Boundary acquisition mutual exclusion: {@link DeterministicTimeTrigger#tryAcquireBoundary()}
 *       permits exactly one winner per epoch boundary under racing threads.</li>
 *   <li>Trust weight scaling: high-trust peers produce faster convergence than
 *       low-trust peers over the same sample distance.</li>
 *   <li>Monotonicity: {@link SwarmEpochManager#swarmNanoTime()} is strictly
 *       non-decreasing for positive offsets.</li>
 * </ol>
 */
class DeterministicTimeTest {

    private SwarmEpochManager epochManager;

    @BeforeEach
    void setUp() {
        epochManager = new SwarmEpochManager();
        // Start from a known zero-offset baseline.
        epochManager.resetOffset();
    }

    // ── Clock Convergence ────────────────────────────────────────────────────

    @Test
    @DisplayName("Convergence: sequence of honest peer samples pulls offset toward target centroid")
    void honestPeerSamplesConvergeOffset() {
        // Simulate 50 honest peers each claiming the swarm is 500 ms ahead (500_000_000 ns).
        // After enough samples at full trust, the offset must converge close to 500_000_000.
        long targetOffsetNanos = 500_000_000L; // 500 ms
        double fullTrust = 1.0;

        for (int i = 0; i < 50; i++) {
            boolean accepted = epochManager.adjustOffset(targetOffsetNanos, fullTrust);
            assertTrue(accepted, "Honest peer sample must be accepted: iteration " + i);
        }

        long convergeddOffset = epochManager.currentOffsetNanos();

        // After 50 iterations with alpha=0.25 at full trust:
        // offset = targetOffset * (1 - (1-0.25)^50) ≈ targetOffset * (1 - ~0) ≈ targetOffset
        // Tolerance: within 1% of target (5_000_000 ns = 5 ms).
        long tolerance = targetOffsetNanos / 100; // 1%
        assertTrue(
                Math.abs(convergeddOffset - targetOffsetNanos) <= tolerance,
                "Converged offset %,d must be within 1%% of target %,d (tolerance ±%,d)"
                        .formatted(convergeddOffset, targetOffsetNanos, tolerance)
        );
        assertEquals(50, epochManager.acceptedSamples(), "All 50 honest samples must be counted as accepted");
        assertEquals(0, epochManager.rejectedSamples(), "No samples should be rejected from honest peers");
    }

    @Test
    @DisplayName("Convergence: high-trust peers converge faster than low-trust peers")
    void highTrustConvergesFasterThanLowTrust() {
        long targetOffsetNanos = 1_000_000_000L; // 1 second
        int iterations = 20;

        // Measure convergence with high-trust peers (trust = 1.0)
        SwarmEpochManager highTrustManager = new SwarmEpochManager();
        for (int i = 0; i < iterations; i++) {
            highTrustManager.adjustOffset(targetOffsetNanos, 1.0);
        }
        long highTrustOffset = highTrustManager.currentOffsetNanos();

        // Measure convergence with low-trust peers (trust = 0.1)
        SwarmEpochManager lowTrustManager = new SwarmEpochManager();
        for (int i = 0; i < iterations; i++) {
            lowTrustManager.adjustOffset(targetOffsetNanos, 0.1);
        }
        long lowTrustOffset = lowTrustManager.currentOffsetNanos();

        // High-trust must have converged significantly closer to the target
        long highTrustError = Math.abs(highTrustOffset - targetOffsetNanos);
        long lowTrustError = Math.abs(lowTrustOffset - targetOffsetNanos);
        assertTrue(
                highTrustError < lowTrustError,
                "High-trust offset error (%,d ns) must be smaller than low-trust error (%,d ns) after %d iterations"
                        .formatted(highTrustError, lowTrustError, iterations)
        );
    }

    @Test
    @DisplayName("Convergence: interleaved honest and adversarial samples — offset tracks honest centroid")
    void interleavedAdversarialSamplesDoNotPoison() {
        long honestTargetNanos = 200_000_000L; // 200 ms
        // First, seed the offset toward the honest centroid using 20 trusted peers
        for (int i = 0; i < 20; i++) {
            epochManager.adjustOffset(honestTargetNanos, 1.0);
        }
        long preAttackOffset = epochManager.currentOffsetNanos();

        // Now fire 10 adversarial samples 200 seconds off baseline (hard rejection)
        long adversarialSkewNanos = 200_000_000_000L; // 200 seconds — well past MAX_ACCEPTABLE_SKEW_NS
        for (int i = 0; i < 10; i++) {
            boolean accepted = epochManager.adjustOffset(adversarialSkewNanos, 1.0);
            assertFalse(accepted, "Adversarial skew must be rejected: iteration " + i);
        }

        long postAttackOffset = epochManager.currentOffsetNanos();

        // Offset must remain unchanged after all rejections
        assertEquals(
                preAttackOffset, postAttackOffset,
                "Offset must not shift after adversarial samples are rejected"
        );
        assertEquals(10, epochManager.rejectedSamples(), "All 10 adversarial samples must be counted as rejected");
    }

    // ── Byzantine Input Rejection ────────────────────────────────────────────

    @Test
    @DisplayName("Byzantine: samples beyond MAX_ACCEPTABLE_SKEW_NS are unconditionally rejected")
    void excessiveSkewIsRejected() {
        // A skew of exactly MAX_ACCEPTABLE_SKEW_NS should be accepted (boundary is inclusive to reject > max)
        // A skew of MAX_ACCEPTABLE_SKEW_NS + 1 should be rejected
        long boundary = SwarmEpochManager.MAX_ACCEPTABLE_SKEW_NS;
        long justOver = boundary + 1L;

        // From a zero baseline offset, skew = |sample - 0|
        boolean acceptedAtBoundary = epochManager.adjustOffset(boundary, 1.0);
        assertTrue(acceptedAtBoundary, "Sample at exactly MAX_ACCEPTABLE_SKEW_NS must be accepted");

        // Reset for clean test of rejection — re-seed manager from fresh state
        SwarmEpochManager freshManager = new SwarmEpochManager();
        boolean rejectedOverBoundary = freshManager.adjustOffset(justOver, 1.0);
        assertFalse(rejectedOverBoundary, "Sample 1 ns over MAX_ACCEPTABLE_SKEW_NS must be rejected");
        assertEquals(1, freshManager.rejectedSamples());
    }

    @Test
    @DisplayName("Byzantine: invalid trust weights (negative, >1.0, NaN) are rejected without altering offset")
    void invalidTrustWeightsAreRejected() {
        long sampleNanos = 1_000_000L; // a benign 1 ms sample

        // Seed a known offset first
        epochManager.adjustOffset(sampleNanos, 1.0);
        long knownOffset = epochManager.currentOffsetNanos();

        // Negative trust weight
        assertFalse(epochManager.adjustOffset(sampleNanos, -0.01),
                "Negative trust weight must be rejected");

        // Trust weight > 1.0
        assertFalse(epochManager.adjustOffset(sampleNanos, 1.001),
                "Trust weight > 1.0 must be rejected");

        // NaN trust weight
        assertFalse(epochManager.adjustOffset(sampleNanos, Double.NaN),
                "NaN trust weight must be rejected");

        // Offset must not have changed from the invalid submissions
        assertEquals(knownOffset, epochManager.currentOffsetNanos(),
                "Offset must be unaffected by invalid-weight rejections");

        assertEquals(3, epochManager.invalidWeightRejections(),
                "All 3 invalid weight submissions must be counted");
    }

    @Test
    @DisplayName("Byzantine: zero-trust (0.0) samples are accepted but contribute minimal influence")
    void zeroTrustSamplesHaveMinimalInfluence() {
        long largeTargetNanos = 1_000_000_000L; // 1 second

        // Submit many zero-trust samples toward a large target
        for (int i = 0; i < 100; i++) {
            boolean accepted = epochManager.adjustOffset(largeTargetNanos, 0.0);
            assertTrue(accepted, "Zero-trust sample must still be accepted (trust=0.0 is valid)");
        }

        long offset = epochManager.currentOffsetNanos();

        // With alpha = MIN_ALPHA = 0.01 and 100 iterations:
        // offset ≈ target * (1 - 0.99^100) ≈ target * 0.634 ≈ 634_000_000 ns
        // But we assert a weaker property: offset must not be zero (some influence) and
        // must not be ≥ target * 0.95 (i.e., NOT as fast as full trust)
        assertTrue(offset > 0,
                "Zero-trust samples must still move the offset slightly away from zero");
        assertTrue(offset < (long) (largeTargetNanos * 0.95),
                "Zero-trust convergence must be significantly slower than full-trust (offset=%,d)"
                        .formatted(offset));
    }

    // ── Epoch Gate Semantics ─────────────────────────────────────────────────

    @Test
    @DisplayName("Epoch gate: boundary reached after one full epoch length, NOT before")
    void boundaryReachedAfterEpochLength() {
        // Use a 500 ms epoch for wall-clock testability
        long epochLengthNanos = 500_000_000L;
        DeterministicTimeTrigger trigger = new DeterministicTimeTrigger(epochManager, epochLengthNanos);

        long now = trigger.swarmNanoTimeNow();

        // Record as if execution just happened
        assertFalse(trigger.isWindowBoundaryReached(now),
                "Boundary must NOT be reached immediately after recording execution time");

        // Simulate time passing by using a lastExecutionNanos that is one full epoch in the past
        long oneEpochAgo = now - epochLengthNanos;
        assertTrue(trigger.isWindowBoundaryReached(oneEpochAgo),
                "Boundary MUST be reached when last execution was one full epoch ago");

        // Simulate a partial epoch (half-way through)
        long halfEpochAgo = now - (epochLengthNanos / 2);
        assertFalse(trigger.isWindowBoundaryReached(halfEpochAgo),
                "Boundary must NOT be reached halfway through an epoch");
    }

    @Test
    @DisplayName("Epoch gate: isWindowBoundaryReached is idempotent (read-only, does not consume)")
    void isWindowBoundaryReachedIsIdempotent() {
        long epochLengthNanos = 500_000_000L;
        DeterministicTimeTrigger trigger = new DeterministicTimeTrigger(epochManager, epochLengthNanos);

        long oneEpochAgo = trigger.swarmNanoTimeNow() - epochLengthNanos;

        // Call multiple times — must return same result, not consume the boundary
        assertTrue(trigger.isWindowBoundaryReached(oneEpochAgo));
        assertTrue(trigger.isWindowBoundaryReached(oneEpochAgo),
                "isWindowBoundaryReached must be idempotent — it does not consume the tick");
        assertTrue(trigger.isWindowBoundaryReached(oneEpochAgo),
                "Third consecutive call must still return true");
    }

    @Test
    @DisplayName("Epoch gate: minimum epoch length guard rejects sub-100ms configuration")
    void minimumEpochLengthGuard() {
        long tooShort = DeterministicTimeTrigger.MIN_EPOCH_LENGTH_NANOS - 1;
        assertThrows(IllegalArgumentException.class,
                () -> new DeterministicTimeTrigger(epochManager, tooShort),
                "Epoch length below minimum must throw IllegalArgumentException");
    }

    @Test
    @DisplayName("Epoch gate: null epochManager is rejected at construction time")
    void nullEpochManagerRejected() {
        assertThrows(NullPointerException.class,
                () -> new DeterministicTimeTrigger(null),
                "Null SwarmEpochManager must throw NullPointerException");
    }

    // ── Boundary Acquisition (Multi-Thread Safety) ───────────────────────────

    @Test
    @DisplayName("tryAcquireBoundary: exactly one thread wins per epoch boundary under concurrent contention")
    void tryAcquireBoundaryIsExclusiveUnderContention() throws InterruptedException {
        // Use a 1-second epoch so the boundary is stable throughout the test
        long epochLengthNanos = 1_000_000_000L;
        DeterministicTimeTrigger trigger = new DeterministicTimeTrigger(epochManager, epochLengthNanos);

        // Force first acquisition to establish a baseline
        // Wait until we're solidly inside an epoch (not right at the edge)
        // by seeding lastAcquiredEpoch to the CURRENT epoch
        // This means the next boundary occurs in at most epochLengthNanos.
        // We'll directly test that concurrent tryAcquireBoundary on a fresh epoch
        // produces exactly one winner.

        int threadCount = 16;
        AtomicInteger winnerCount = new AtomicInteger(0);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch finishLine = new CountDownLatch(threadCount);

        // Manually seed lastAcquiredEpoch to one epoch before now so the
        // next call to tryAcquireBoundary will see a fresh boundary.
        long currentEpoch = trigger.currentEpochNumber();
        assertTrue(currentEpoch >= 0, "Current epoch must be non-negative");
        // We seed it to currentEpoch - 1 by first acquiring the "currentEpoch - 1" boundary
        // indirectly: tryAcquireBoundary compares against lastAcquiredEpoch; since it starts
        // at -1, the first call from any thread will succeed and set it to currentEpoch.
        // Then no more threads can acquire. This is the exact behavior we assert.

        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        for (int i = 0; i < threadCount; i++) {
            pool.submit(() -> {
                try {
                    startGate.await(); // synchronize start
                    if (trigger.tryAcquireBoundary()) {
                        winnerCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    finishLine.countDown();
                }
            });
        }

        startGate.countDown(); // release all threads simultaneously
        assertTrue(finishLine.await(5, TimeUnit.SECONDS), "All threads must finish within 5 seconds");
        pool.shutdown();

        assertEquals(1, winnerCount.get(),
                "Exactly ONE thread must win the boundary acquisition; got " + winnerCount.get());
        assertEquals(1, trigger.totalBoundariesFired(),
                "Exactly one boundary must be recorded as fired");
    }

    @Test
    @DisplayName("tryAcquireBoundary: second call in same epoch returns false")
    void tryAcquireBoundaryReturnsFalseInSameEpoch() {
        // 5-second epoch — we are definitely inside one epoch throughout this test
        long epochLengthNanos = 5_000_000_000L;
        DeterministicTimeTrigger trigger = new DeterministicTimeTrigger(epochManager, epochLengthNanos);

        // First call: acquires the current epoch (lastAcquiredEpoch starts at -1)
        boolean first = trigger.tryAcquireBoundary();
        assertTrue(first, "First tryAcquireBoundary must succeed (lastAcquiredEpoch was -1)");

        // Second call: same epoch, already acquired
        boolean second = trigger.tryAcquireBoundary();
        assertFalse(second, "Second tryAcquireBoundary in the same epoch must return false");

        assertEquals(1, trigger.totalBoundariesFired(),
                "Only one boundary should be recorded as fired");
    }

    // ── SwarmNanoTime Monotonicity ───────────────────────────────────────────

    @Test
    @DisplayName("swarmNanoTime: monotonically non-decreasing across rapid successive calls")
    void swarmNanoTimeIsMonotonic() {
        int samples = 10_000;
        long prev = epochManager.swarmNanoTime();

        for (int i = 0; i < samples; i++) {
            long current = epochManager.swarmNanoTime();
            assertTrue(current >= prev,
                    "swarmNanoTime must be non-decreasing: got %,d after %,d at iteration %d"
                            .formatted(current, prev, i));
            prev = current;
        }
    }

    @Test
    @DisplayName("swarmNanoTime: positive offset shifts result above raw System.nanoTime baseline")
    void positiveOffsetShiftsTimeForward() {
        long positiveOffsetNanos = 30_000_000_000L; // 30 seconds forward
        // Feed enough samples at full trust to converge close to the target
        for (int i = 0; i < 50; i++) {
            epochManager.adjustOffset(positiveOffsetNanos, 1.0);
        }
        // swarmNanoTime must be strictly ahead of raw nanoTime
        long rawNano = System.nanoTime();
        long swarmNano = epochManager.swarmNanoTime();
        assertTrue(swarmNano > rawNano,
                "Swarm time must be ahead of raw System.nanoTime() after positive offset convergence. " +
                "swarm=%,d, raw=%,d".formatted(swarmNano, rawNano));
    }

    // ── Statistic Counters ───────────────────────────────────────────────────

    @Test
    @DisplayName("Counters: accepted, rejected, and invalidWeight counts are mutually exclusive and sum correctly")
    void countersMutuallyExclusive() {
        // 5 honest samples
        for (int i = 0; i < 5; i++) {
            epochManager.adjustOffset(1_000_000L, 1.0); // 1 ms — always accepted
        }
        // 3 adversarial (skew rejection)
        for (int i = 0; i < 3; i++) {
            epochManager.adjustOffset(SwarmEpochManager.MAX_ACCEPTABLE_SKEW_NS + 1_000_000_000L, 1.0);
        }
        // 2 invalid weight
        epochManager.adjustOffset(1_000_000L, -1.0);
        epochManager.adjustOffset(1_000_000L, Double.NaN);

        assertEquals(5, epochManager.acceptedSamples(), "Accepted count must match honest submissions");
        assertEquals(3, epochManager.rejectedSamples(), "Rejected count must match skew rejections");
        assertEquals(2, epochManager.invalidWeightRejections(), "Invalid weight count must match");

        // Total submissions = 10; accepted + rejected + invalid = 5 + 3 + 2 = 10
        long total = epochManager.acceptedSamples()
                + epochManager.rejectedSamples()
                + epochManager.invalidWeightRejections();
        assertEquals(10, total, "Sum of all counter categories must equal total submissions");
    }

    @Test
    @DisplayName("resetOffset: restores offset to zero regardless of prior convergence state")
    void resetOffsetRestoresZero() {
        // Converge significantly away from zero
        for (int i = 0; i < 30; i++) {
            epochManager.adjustOffset(60_000_000_000L, 1.0); // 60 seconds
        }
        assertTrue(epochManager.currentOffsetNanos() > 0, "Offset must be positive before reset");

        epochManager.resetOffset();
        assertEquals(0, epochManager.currentOffsetNanos(),
                "Offset must be exactly 0 after resetOffset()");
    }

    @Test
    @DisplayName("nanosUntilNextBoundary: returns a value in [0, epochLengthNanos] at any point in time")
    void nanosUntilNextBoundaryInRange() {
        long epochLengthNanos = 500_000_000L; // 500 ms
        DeterministicTimeTrigger trigger = new DeterministicTimeTrigger(epochManager, epochLengthNanos);

        long remaining = trigger.nanosUntilNextBoundary();
        assertTrue(remaining >= 0,
                "Remaining nanoseconds must be non-negative, got: " + remaining);
        assertTrue(remaining <= epochLengthNanos,
                "Remaining nanoseconds must not exceed epoch length. remaining=%,d, epoch=%,d"
                        .formatted(remaining, epochLengthNanos));
    }
}
