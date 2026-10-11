package dev.aethelgard.telemetry;

/**
 * The Act organ: the autonomous Perceive → Decide → Act lifecycle.
 *
 * Execution model (per the architectural contract):
 * - Driven by a Virtual Thread per cycle tick scheduled through a
 *   ScheduledExecutorService — the loop NEVER runs on a Netty EventLoop and
 *   never blocks the data path. Sensor ingestion stays lock-free on the I/O
 *   threads; judgment happens here, off-thread, at human-scale frequency
 *   (default: every 5 s).
 * - Communication with the data path is strictly via Netty's
 *   EventExecutor.execute() (MPSC task queue) for any socket-touching action,
 *   or via the thread-safe trust registry (trust/revoke) which requires no
 *   event-loop affinity at all.
 *
 * Act escalation ladder (each stage narrows the peer's attack surface):
 *   1. DEMOTE               — record, watch, optionally send a probe frame.
 *   2. REVOKE               — AethelgardTrustManager.revoke(key): future TLS
 *                             handshakes die instantly (verified in Layer 2).
 *   3. QUARANTINE_NOMINATE  — sign a quarantine statement and hand it to the
 *                             Layer 4 gossip engine; isolation itself only
 *                             happens after cryptographic majority consensus.
 *   4. (post-consensus)     — sever live sockets + IP blacklist (Layer 4).
 */
public interface DecisionLoop extends AutoCloseable {

    /** Starts the periodic perceive-decide-act cycle. Idempotent. */
    void start();

    /** One synchronous cycle over all active peers (exposed for tests). */
    void runSingleCycle();

    /** Graceful stop: no new cycles, in-flight cycle completes. */
    @Override
    void close();
}
