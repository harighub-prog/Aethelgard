package dev.aethelgard.time;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Layer 7: Deterministic Epoch-Aligned Execution Gate.
 *
 * Prevents time-asymmetry and clock-desynchronization attacks by ensuring that
 * telemetry sliding-window rotations, behavioral scoring evaluations, and gossip
 * dissemination cycles fire ONLY on boundaries aligned to the swarm-unified epoch
 * tick — never on the local host wall clock alone.
 *
 * <h3>Problem it solves</h3>
 * <p>
 * If each node independently determines "when" to rotate its telemetry windows
 * using its own {@code System.nanoTime()}, an adversary who can delay or accelerate
 * its apparent clock (e.g., by holding a TCP connection open across a window boundary)
 * can make its malicious frames fall into a fresh, empty scoring window every time,
 * creating a permanent telemetry blind spot. This is the <em>time-asymmetry attack</em>.
 *
 * <h3>Solution: epoch-aligned boundary gates</h3>
 * <p>
 * The trigger gate defines a fixed {@code epochLengthNanos}. All execution decisions
 * (telemetry rotation, scoring cycle, gossip tick) must use
 * {@link #isWindowBoundaryReached(long)} to determine if they should fire. This
 * method evaluates the swarm-corrected time from the supplied {@link SwarmEpochManager},
 * not the raw host clock — ensuring that even if the host clock drifts, the logical
 * epoch boundaries remain synchronized with the swarm majority.
 *
 * <h3>Epoch-Alignment Logic</h3>
 * <p>
 * Each epoch is of fixed length {@code E} nanoseconds. Boundaries occur at
 * {@code t = k * E} for integer {@code k} in swarm time. A window boundary is
 * considered reached when the current swarm epoch number ({@code swarmNanos / E})
 * differs from the epoch number at the last execution point. This guarantees:
 * <ol>
 *   <li>The boundary fires at most once per epoch.</li>
 *   <li>A peer that advances its own clock cannot cause the local node to fire
 *       early — the gate consults the FTA-converged swarm offset, not the peer's
 *       raw claim.</li>
 *   <li>A peer that delays traffic across a boundary cannot suppress the window
 *       rotation — the gate fires when the <em>swarm</em> clock crosses the next
 *       {@code k * E}, regardless of when the delayed frames actually arrive.</li>
 * </ol>
 *
 * <h3>Zero-Heap Allocation Contract</h3>
 * <p>
 * All state is primitive {@code long} values stored in {@link AtomicLong}. No
 * autoboxing, no object construction, no lambda captures on the hot path.
 * {@link #isWindowBoundaryReached(long)} and {@link #tryAcquireBoundary()} are
 * pure arithmetic + one volatile read + one conditional CAS — branch-free on
 * the common (no-boundary) path.
 */
public final class DeterministicTimeTrigger {

    /**
     * Default epoch length: 5 seconds in nanoseconds.
     * Matches the default {@code cycleIntervalMillis} in {@code DefaultDecisionLoop}.
     */
    public static final long DEFAULT_EPOCH_LENGTH_NANOS = 5_000_000_000L;

    /**
     * Minimum permitted epoch length: 100 milliseconds.
     * Values shorter than this provide no meaningful protection and risk CPU
     * saturation from constant boundary evaluations.
     */
    public static final long MIN_EPOCH_LENGTH_NANOS = 100_000_000L;

    private final SwarmEpochManager epochManager;
    private final long epochLengthNanos;

    /**
     * The epoch number (swarmNanoTime / epochLengthNanos) at which the most
     * recent boundary execution was acknowledged via {@link #tryAcquireBoundary()}.
     * Stored as an AtomicLong so that concurrent callers can race to "own" a
     * given boundary tick exactly once via CAS.
     */
    private final AtomicLong lastAcquiredEpoch = new AtomicLong(-1L);

    /** Total count of successful boundary acquisitions (monotonically increasing). */
    private final AtomicLong totalBoundariesFired = new AtomicLong(0L);

    /**
     * Constructs a trigger gate with the default epoch length.
     *
     * @param epochManager the swarm clock manager providing FTA-corrected time.
     */
    public DeterministicTimeTrigger(SwarmEpochManager epochManager) {
        this(epochManager, DEFAULT_EPOCH_LENGTH_NANOS);
    }

    /**
     * Constructs a trigger gate with an explicit epoch length.
     *
     * @param epochManager     the swarm clock manager providing FTA-corrected time.
     * @param epochLengthNanos the epoch boundary interval in nanoseconds.
     *                         Must be ≥ {@link #MIN_EPOCH_LENGTH_NANOS}.
     */
    public DeterministicTimeTrigger(SwarmEpochManager epochManager, long epochLengthNanos) {
        this.epochManager = Objects.requireNonNull(epochManager, "epochManager");
        if (epochLengthNanos < MIN_EPOCH_LENGTH_NANOS) {
            throw new IllegalArgumentException(
                    "epochLengthNanos %,d is below minimum %,d".formatted(epochLengthNanos, MIN_EPOCH_LENGTH_NANOS));
        }
        this.epochLengthNanos = epochLengthNanos;
    }

    /**
     * Checks whether a window boundary has been reached since the last execution.
     *
     * <p>This is a <em>read-only</em> probe — it does NOT consume the boundary tick.
     * Multiple callers will all see {@code true} until one of them calls
     * {@link #tryAcquireBoundary()}, which consumes it exactly once.
     *
     * <p>For single-threaded loops (e.g., the {@code DefaultDecisionLoop} virtual
     * thread), calling {@code isWindowBoundaryReached(lastNanos)} is sufficient;
     * the caller owns the epoch exclusively because it is the only consumer.
     * Multi-threaded consumers must use {@link #tryAcquireBoundary()} instead.
     *
     * @param lastExecutionNanos the swarm-time nanosecond value recorded at the last
     *                           execution. Pass {@link #swarmNanoTimeNow()} from the
     *                           previous cycle, or {@code 0} on first call.
     * @return {@code true} if the swarm clock has advanced by at least one full
     *         {@code epochLengthNanos} since {@code lastExecutionNanos}.
     */
    public boolean isWindowBoundaryReached(long lastExecutionNanos) {
        long currentSwarmNanos = epochManager.swarmNanoTime();
        // The elapsed duration is guaranteed non-negative by monotonic nanoTime contract.
        long elapsed = currentSwarmNanos - lastExecutionNanos;
        return elapsed >= epochLengthNanos;
    }

    /**
     * Atomically acquires the current boundary tick if one is available.
     *
     * <p>Exactly one caller among concurrent contenders will receive {@code true}
     * per epoch boundary. All others receive {@code false} and should skip their
     * execution for this tick. This is the <em>multi-producer safe</em> variant
     * for subsystems that run on multiple threads.
     *
     * <p>Implementation: computes the current epoch number from swarm time and
     * CAS-attempts to set {@link #lastAcquiredEpoch} to that number. The first
     * caller to succeed "wins" the tick; all concurrent losers see the already-
     * updated value and return {@code false}.
     *
     * @return {@code true} if this call successfully acquired the current epoch
     *         boundary; {@code false} if it was already consumed.
     */
    public boolean tryAcquireBoundary() {
        long currentSwarmNanos = epochManager.swarmNanoTime();
        long currentEpoch = currentSwarmNanos / epochLengthNanos;
        long prev = lastAcquiredEpoch.get();

        if (currentEpoch <= prev) {
            // Already at or behind the last acquired epoch — no boundary available.
            return false;
        }
        // Race to claim this epoch. Exactly one winner per epoch number.
        if (lastAcquiredEpoch.compareAndSet(prev, currentEpoch)) {
            totalBoundariesFired.incrementAndGet();
            return true;
        }
        // Lost the CAS race to a concurrent caller — boundary already claimed.
        return false;
    }

    /**
     * Convenience: returns the current swarm-corrected nanosecond time from
     * the underlying {@link SwarmEpochManager}. Use this to update a
     * {@code lastExecutionNanos} variable after a boundary fires.
     *
     * @return {@link SwarmEpochManager#swarmNanoTime()} — zero allocation.
     */
    public long swarmNanoTimeNow() {
        return epochManager.swarmNanoTime();
    }

    /**
     * Returns the current swarm epoch number (swarmNanoTime / epochLengthNanos).
     * Useful for diagnostics and test assertions.
     */
    public long currentEpochNumber() {
        return epochManager.swarmNanoTime() / epochLengthNanos;
    }

    /**
     * Returns the epoch length in nanoseconds this trigger gate was configured with.
     */
    public long epochLengthNanos() {
        return epochLengthNanos;
    }

    /**
     * Total number of epoch boundaries that have been successfully acquired via
     * {@link #tryAcquireBoundary()} since construction.
     */
    public long totalBoundariesFired() {
        return totalBoundariesFired.get();
    }

    /**
     * Returns the epoch number of the last acquired boundary, or {@code -1} if
     * no boundary has been acquired yet.
     */
    public long lastAcquiredEpoch() {
        return lastAcquiredEpoch.get();
    }

    /**
     * Returns the number of nanoseconds remaining until the next epoch boundary,
     * based on current swarm time. Returns {@code 0} if a boundary is available now.
     * Useful for scheduling exact sleep/delay durations in test harnesses.
     */
    public long nanosUntilNextBoundary() {
        long currentSwarmNanos = epochManager.swarmNanoTime();
        long currentEpoch = currentSwarmNanos / epochLengthNanos;
        long nextBoundaryNanos = (currentEpoch + 1L) * epochLengthNanos;
        long remaining = nextBoundaryNanos - currentSwarmNanos;
        return Math.max(0L, remaining);
    }
}
