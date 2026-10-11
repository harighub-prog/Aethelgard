package dev.aethelgard.gossip;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Tamper-proof quarantine attestation — the Layer 4 unit of swarm judgment.
 *
 * A ballot asserts: "I, the nominator identified by my Ed25519 public key,
 * nominate the peer with this key-ID for swarm quarantine." Every field is
 * bound into the signature, so any in-flight mutation (target swap, sequence
 * replay, nominator forgery) fails verification.
 *
 * Signing uses the standard JCA Ed25519 provider (Java 15+, pure JDK — no
 * BouncyCastle on this path): sign/verify are fully in-memory, single-shot,
 * and constant-time per the RFC 8032 implementation contract.
 *
 * Wire format (GOSSIP frame payload, big-endian):
 *   [targetLen:4][targetKeyId UTF-8][seq:8][pubLen:4][ed25519Pub][sigLen:4][signature]
 *
 * Immutability: all array fields are defensively copied in and out; the record
 * is safe to share across threads without coordination.
 */
public record QuarantineBallot(String targetKeyId, byte[] nominatorPub, long sequence, byte[] signature) {

    private static final SecureRandom RNG = new SecureRandom();

    public QuarantineBallot {
        targetKeyId = java.util.Objects.requireNonNull(targetKeyId);
        nominatorPub = nominatorPub.clone();
        signature = signature.clone();
    }

    /** Generates a fresh Ed25519 signing identity for a node's gossip engine. */
    public static KeyPair generateSigningKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").genKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    /** Canonical signed bytes: every field except the signature itself. */
    private byte[] canonical() {
        byte[] target = targetKeyId.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[4 + target.length + 8 + 4 + nominatorPub.length];
        int p = 0;
        p = putInt(out, p, target.length);
        System.arraycopy(target, 0, out, p, target.length);
        p += target.length;
        out[p++] = (byte) (sequence >>> 56);
        out[p++] = (byte) (sequence >>> 48);
        out[p++] = (byte) (sequence >>> 40);
        out[p++] = (byte) (sequence >>> 32);
        out[p++] = (byte) (sequence >>> 24);
        out[p++] = (byte) (sequence >>> 16);
        out[p++] = (byte) (sequence >>> 8);
        out[p++] = (byte) sequence;
        p = putInt(out, p, nominatorPub.length);
        System.arraycopy(nominatorPub, 0, out, p, nominatorPub.length);
        return out;
    }

    private static int putInt(byte[] out, int p, int v) {
        out[p++] = (byte) (v >>> 24);
        out[p++] = (byte) (v >>> 16);
        out[p++] = (byte) (v >>> 8);
        out[p++] = (byte) v;
        return p;
    }

    /**
     * Creates a signed ballot. Sequence numbers come from the engine's atomic
     * counter, guaranteeing uniqueness per nominator (replay resistance is
     * enforced by the registry's dedupe on ballotId).
     */
    public static QuarantineBallot sign(String targetKeyId, KeyPair nominator, long sequence) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(nominator.getPrivate(), RNG);
            QuarantineBallot unsigned = new QuarantineBallot(
                    targetKeyId, nominator.getPublic().getEncoded(), sequence, new byte[0]);
            sig.update(unsigned.canonical());
            return new QuarantineBallot(targetKeyId, nominator.getPublic().getEncoded(),
                    sequence, sig.sign());
        } catch (Exception e) {
            throw new IllegalStateException("ballot signing failed", e);
        }
    }

    /** Pure-JCA Ed25519 verification: false on ANY tampering or bad key. */
    public boolean verify() {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Ed25519");
            PublicKey pub = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(nominatorPub));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(canonical());
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /** Dedupe identity: SHA-256 over nominator key + sequence + target. */
    public String ballotId() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(nominatorPub);
            md.update(Long.toString(sequence).getBytes(StandardCharsets.UTF_8));
            md.update(targetKeyId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Stable identifier of the NOMINATOR (independent of sequence). */
    public String nominatorId() {
        try {
            return Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(nominatorPub));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] encode() {
        byte[] target = targetKeyId.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[4 + target.length + 8 + 4 + nominatorPub.length + 4 + signature.length];
        int p = putInt(out, 0, target.length);
        System.arraycopy(target, 0, out, p, target.length);
        p += target.length;
        for (int i = 7; i >= 0; i--) {
            out[p++] = (byte) (sequence >>> (8 * i));
        }
        p = putInt(out, p, nominatorPub.length);
        System.arraycopy(nominatorPub, 0, out, p, nominatorPub.length);
        p += nominatorPub.length;
        p = putInt(out, p, signature.length);
        System.arraycopy(signature, 0, out, p, signature.length);
        return out;
    }

    /** Decodes a wire payload; returns null if the buffer is malformed. */
    public static QuarantineBallot decode(byte[] payload) {
        try {
            int p = 0;
            int targetLen = intAt(payload, p);
            p += 4;
            if (targetLen < 0 || p + targetLen > payload.length) {
                return null;
            }
            String target = new String(payload, p, targetLen, StandardCharsets.UTF_8);
            p += targetLen;
            long seq = 0;
            for (int i = 0; i < 8; i++) {
                seq = (seq << 8) | (payload[p + i] & 0xFF);
            }
            p += 8;
            int pubLen = intAt(payload, p);
            p += 4;
            if (pubLen < 0 || p + pubLen > payload.length) {
                return null;
            }
            byte[] pub = Arrays.copyOfRange(payload, p, p + pubLen);
            p += pubLen;
            int sigLen = intAt(payload, p);
            p += 4;
            if (sigLen < 0 || p + sigLen != payload.length) {
                return null;
            }
            byte[] sig = Arrays.copyOfRange(payload, p, p + sigLen);
            return new QuarantineBallot(target, pub, seq, sig);
        } catch (Exception e) {
            return null;
        }
    }

    private static int intAt(byte[] b, int p) {
        return ((b[p] & 0xFF) << 24) | ((b[p + 1] & 0xFF) << 16) | ((b[p + 2] & 0xFF) << 8) | (b[p + 3] & 0xFF);
    }
}
