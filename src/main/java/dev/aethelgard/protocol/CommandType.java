package dev.aethelgard.protocol;

import java.util.Arrays;

/**
 * Command codes carried in the 1-byte command field of every frame.
 * Sealed-style exhaustive enum: Layer 3's decision loop pattern-matches over these.
 */
public enum CommandType {

    HANDSHAKE(0x01),
    GOSSIP(0x02),
    TELEMETRY(0x03),
    CONTROL(0x04);

    private final byte code;

    CommandType(int code) {
        this.code = (byte) code;
    }

    public byte code() {
        return code;
    }

    /** Returns the command for a wire code, or null if unknown (caller treats it as malformed). */
    public static CommandType fromCode(byte code) {
        return Arrays.stream(values())
                .filter(c -> c.code == code)
                .findFirst()
                .orElse(null);
    }
}
