package dev.aethelgard.telemetry;

/**
 * Per-peer telemetry sensor — the Perceive organ of the autonomous loop.
 *
 * Implementation contract (binding for the concrete sensor):
 *
 * 1. EVENT-LOOP CONFINEMENT. Every record*() method is invoked from Netty
 *    handler callbacks (channelRead, exceptionCaught, userEventTriggered) on
 *    the channel's pinned EventLoop thread. Implementations MUST use
 *    lock-free primitives (AtomicLong / LongAdder / striped counters) and
 *    MUST NOT block, allocate proportionally to payload size, or take locks
 *    that could stall the I/O thread.
 *
 * 2. SLIDING WINDOWS. Rate metrics (malformedFrameRate, spike counts) are
 *    computed over a fixed observation window. Implementations should use
 *    bucketed counters (e.g. HdrHistogram-style or simple ring buckets) so
 *    window rollover is O(1) and old buckets decay without a sweep thread.
 *
 * 3. SNAPSHOTS, NOT REFERENCES. snapshot() copies current counter values into
 *    an immutable {@link PeerMetrics}. It is the ONLY method the decision
 *    loop (off the event loop) may call. This upholds the architecture's
 *    snapshot rule: no live structures cross the thread boundary.
 *
 * 4. NO TRUST DECISIONS. Sensors observe; they never score, revoke, or
 *    disconnect. Separation of perception from judgment is what makes the
 *    scorer unit-testable against synthetic metrics.
 */
public interface PeerTelemetrySensor {

    // ── Ingestion (event-loop thread only) ──────────────────────────────────

    /** Fatal MALFORMED codec violation observed in a handler. */
    void recordMalformedFrame(String peerKey);

    /** Fatal RESOURCE_ABUSE violation (oversized frame, memory-pressure attack). */
    void recordResourceAbuse(String peerKey);

    /** Completed TLS handshake (either role). */
    void recordHandshakeSuccess(String peerKey);

    /** TLS-level rejection: bad cert, untrusted key, protocol failure. */
    void recordHandshakeFailure(String peerKey);

    /** A well-formed frame was decoded — feeds the hygiene ratio. */
    void recordFrameReceived(String peerKey, long latencyNanos);

    /** An outbound frame was written to the wire. */
    void recordFrameSent(String peerKey);

    // ── Extraction (any thread) ─────────────────────────────────────────────

    /**
     * Immutable copy of this peer's metrics over the current observation
     * window. Returns {@link PeerMetrics#empty} for unknown peers — absence of
     * telemetry is itself a (weak) signal the scorer may weigh.
     */
    PeerMetrics snapshot(String peerKey);

    /** Keys of all peers with activity in the current window (for the loop's sweep). */
    Iterable<String> activePeers();

    /** Drops all state for a peer (called after isolation/eviction). */
    void evict(String peerKey);
}
