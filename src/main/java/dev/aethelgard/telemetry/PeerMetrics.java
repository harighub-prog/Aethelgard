package dev.aethelgard.telemetry;

/**
 * Immutable point-in-time metric snapshot for one peer identity.
 *
 * Threading contract: instances are plain value objects produced by
 * {@link PeerTelemetrySensor#snapshot()} on the calling thread. All mutation
 * lives inside the sensor (event-loop-confined counters); this record is what
 * crosses thread boundaries into the decision loop — never a live mutable
 * structure. Zero shared-state hazards by construction.
 *
 * Design note: every metric is a RATE or a DELTA over the observation window,
 * not a lifetime total. Lifetime totals grow without bound and make threshold
 * logic meaningless ("10 000 malformed frames over 30 days" is healthy);
 * "40 malformed frames in the last 10 s" is an attack signature.
 */
public record PeerMetrics(
        String peerKey,
        long observationWindowMillis,

        // ── Protocol hygiene ────────────────────────────────────────────────
        long malformedFrames,          // FrameCodecException.MALFORMED events
        long resourceAbuseEvents,      // FrameCodecException.RESOURCE_ABUSE events
        double malformedFrameRate,     // events per second over the window

        // ── Transport health ────────────────────────────────────────────────
        long handshakeFailures,        // TLS-level rejections this window
        long handshakeSuccesses,
        long framesReceived,
        long framesSent,
        double latencyEwmaMillis,      // exponentially-weighted RTT estimate
        long latencySpikeCount,        // RTT samples > SPIKE_THRESHOLD in window

        // ── Composite (computed by the sensor, not the scorer) ─────────────
        double hygieneRatio) {         // good frames / (good + malformed), 0 if none

    public PeerMetrics {
        if (observationWindowMillis <= 0) {
            throw new IllegalArgumentException("observationWindowMillis must be positive");
        }
    }

    /** Sentinel for a peer with no recorded activity in the window. */
    public static PeerMetrics empty(String peerKey, long windowMillis) {
        return new PeerMetrics(peerKey, windowMillis, 0, 0, 0.0, 0, 0, 0, 0, 0.0, 0, 1.0);
    }

    public boolean isIdle() {
        return framesReceived == 0 && framesSent == 0 && handshakeSuccesses == 0
                && handshakeFailures == 0 && malformedFrames == 0 && resourceAbuseEvents == 0;
    }
}
