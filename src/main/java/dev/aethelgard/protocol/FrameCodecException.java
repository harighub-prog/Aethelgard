package dev.aethelgard.protocol;

/**
 * Fatal framing violation. Thrown by the codec layer to force an immediate
 * disconnect of the offending peer; the event is also surfaced to Layer 3
 * telemetry (malformed-frame counters).
 */
public class FrameCodecException extends RuntimeException {

    public enum Severity {
        /** Protocol fuzzing / garbage input: disconnect and penalize trust. */
        MALFORMED,
        /** Memory-protection trip (oversized frame): disconnect and penalize trust. */
        RESOURCE_ABUSE
    }

    private final Severity severity;

    public FrameCodecException(Severity severity, String message) {
        super(message);
        this.severity = severity;
    }

    public Severity severity() {
        return severity;
    }
}
