package dev.aethelgard.protocol;

/**
 * Wire-protocol constants for the Aethelgard mesh framing layer.
 *
 * Frame layout (big-endian):
 * <pre>
 * [ Magic: 2 bytes ][ Payload Length: 4 bytes ][ Command Type: 1 byte ][ Encrypted Payload: N bytes ]
 * </pre>
 *
 * Payload Length counts the ENCRYPTED frame body (ciphertext + 16-byte AEAD tag),
 * as locked down in the Layer 1 contract.
 */
public final class ProtocolConstants {

    public static final short MAGIC = (short) 0xAE7E;

    public static final int MAGIC_SIZE = 2;
    public static final int LENGTH_SIZE = 4;
    public static final int COMMAND_SIZE = 1;
    public static final int HEADER_SIZE = MAGIC_SIZE + LENGTH_SIZE + COMMAND_SIZE; // 7

    /**
     * Upper bound for frame payloads.
     * Expanded from legacy 64 KiB to 1 MiB to accommodate the wire footprint of
     * Post-Quantum Cryptography (PQC) public keys and ML-DSA / Dilithium signatures.
     * Any advertised length above this is treated as a memory-exhaustion attack
     * and the connection is severed immediately.
     */
    public static final int MAX_FRAME_SIZE = 1024 * 1024; // 1 MiB

    private ProtocolConstants() {
    }
}
