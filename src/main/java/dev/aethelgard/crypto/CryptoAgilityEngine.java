package dev.aethelgard.crypto;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.ReferenceCounted;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Layer 5: Post-Quantum Cryptographic Agility Engine.
 *
 * Defines the contract for hybrid authentication combining classical elliptic curve
 * cryptography (NIST P-256 / secp256r1) with NIST-standardized Post-Quantum Cryptography
 * (PQC) digital signatures: ML-DSA (Module-Lattice-Based Digital Signature Algorithm /
 * FIPS 204) and Crystals-Dilithium algorithms.
 *
 * The hybrid validation model enforces dual-signature verification: a transaction or frame
 * is verified IF AND ONLY IF both classical and post-quantum cryptographic proofs succeed.
 * If either proof fails or is tampered with, the frame is rejected instantly.
 *
 * Zero-heap-allocation contract:
 * Data streams are ingested via {@link ByteBuf#nioBuffer()} or {@link ByteBuf#nioBuffers()}
 * direct buffers, updating JCA signature engines without creating temporary heap byte arrays.
 */
public interface CryptoAgilityEngine {

    /**
     * Supported post-quantum cryptographic agility suites.
     */
    enum AlgorithmSuite {
        HYBRID_P256_MLDSA44((byte) 0x01, "EC", "secp256r1", "SHA256withECDSA", "ML-DSA-44", "ML-DSA-44"),
        HYBRID_P256_MLDSA65((byte) 0x02, "EC", "secp256r1", "SHA256withECDSA", "ML-DSA-65", "ML-DSA-65"),
        HYBRID_P256_MLDSA87((byte) 0x03, "EC", "secp256r1", "SHA256withECDSA", "ML-DSA-87", "ML-DSA-87"),
        HYBRID_P256_DILITHIUM3((byte) 0x04, "EC", "secp256r1", "SHA256withECDSA", "Dilithium", "Dilithium3");

        private final byte code;
        private final String classicalKeyAlgorithm;
        private final String classicalCurve;
        private final String classicalSignatureAlgorithm;
        private final String pqcKeyAlgorithm;
        private final String pqcSignatureAlgorithm;

        AlgorithmSuite(byte code,
                       String classicalKeyAlgorithm,
                       String classicalCurve,
                       String classicalSignatureAlgorithm,
                       String pqcKeyAlgorithm,
                       String pqcSignatureAlgorithm) {
            this.code = code;
            this.classicalKeyAlgorithm = classicalKeyAlgorithm;
            this.classicalCurve = classicalCurve;
            this.classicalSignatureAlgorithm = classicalSignatureAlgorithm;
            this.pqcKeyAlgorithm = pqcKeyAlgorithm;
            this.pqcSignatureAlgorithm = pqcSignatureAlgorithm;
        }

        public byte code() {
            return code;
        }

        public String classicalKeyAlgorithm() {
            return classicalKeyAlgorithm;
        }

        public String classicalCurve() {
            return classicalCurve;
        }

        public String classicalSignatureAlgorithm() {
            return classicalSignatureAlgorithm;
        }

        public String pqcKeyAlgorithm() {
            return pqcKeyAlgorithm;
        }

        public String pqcSignatureAlgorithm() {
            return pqcSignatureAlgorithm;
        }

        public static AlgorithmSuite fromCode(byte code) {
            for (AlgorithmSuite suite : values()) {
                if (suite.code == code) {
                    return suite;
                }
            }
            throw new IllegalArgumentException("Unknown AlgorithmSuite wire code: 0x" + Integer.toHexString(code & 0xFF));
        }
    }

    /**
     * Hybrid key pair binding a classical key pair and a post-quantum key pair.
     */
    record HybridKeyPair(
            AlgorithmSuite suite,
            KeyPair classicalKeyPair,
            KeyPair pqcKeyPair
    ) {
        public HybridKeyPair {
            Objects.requireNonNull(suite, "suite");
            Objects.requireNonNull(classicalKeyPair, "classicalKeyPair");
            Objects.requireNonNull(pqcKeyPair, "pqcKeyPair");
        }

        public HybridPublicKey toPublicKey() {
            return new HybridPublicKey(suite, classicalKeyPair.getPublic(), pqcKeyPair.getPublic());
        }
    }

    /**
     * Public key counterpart for hybrid verification.
     */
    record HybridPublicKey(
            AlgorithmSuite suite,
            PublicKey classicalPublicKey,
            PublicKey pqcPublicKey
    ) {
        public HybridPublicKey {
            Objects.requireNonNull(suite, "suite");
            Objects.requireNonNull(classicalPublicKey, "classicalPublicKey");
            Objects.requireNonNull(pqcPublicKey, "pqcPublicKey");
        }
    }

    /**
     * Zero-copy reference-counted container for hybrid signatures.
     */
    final class HybridSignature implements ReferenceCounted {
        private final AlgorithmSuite suite;
        private final ByteBuf classicalSignature;
        private final ByteBuf pqcSignature;

        public HybridSignature(AlgorithmSuite suite, ByteBuf classicalSignature, ByteBuf pqcSignature) {
            this.suite = Objects.requireNonNull(suite, "suite");
            this.classicalSignature = Objects.requireNonNull(classicalSignature, "classicalSignature");
            this.pqcSignature = Objects.requireNonNull(pqcSignature, "pqcSignature");
        }

        public AlgorithmSuite suite() {
            return suite;
        }

        public ByteBuf classicalSignature() {
            return classicalSignature;
        }

        public ByteBuf pqcSignature() {
            return pqcSignature;
        }

        @Override
        public int refCnt() {
            return Math.min(classicalSignature.refCnt(), pqcSignature.refCnt());
        }

        @Override
        public ReferenceCounted retain() {
            classicalSignature.retain();
            pqcSignature.retain();
            return this;
        }

        @Override
        public ReferenceCounted retain(int increment) {
            classicalSignature.retain(increment);
            pqcSignature.retain(increment);
            return this;
        }

        @Override
        public ReferenceCounted touch() {
            classicalSignature.touch();
            pqcSignature.touch();
            return this;
        }

        @Override
        public ReferenceCounted touch(Object hint) {
            classicalSignature.touch(hint);
            pqcSignature.touch(hint);
            return this;
        }

        @Override
        public boolean release() {
            boolean r1 = classicalSignature.release();
            boolean r2 = pqcSignature.release();
            return r1 || r2;
        }

        @Override
        public boolean release(int decrement) {
            boolean r1 = classicalSignature.release(decrement);
            boolean r2 = pqcSignature.release(decrement);
            return r1 || r2;
        }
    }

    /**
     * Active algorithm suite configured on this engine instance.
     */
    AlgorithmSuite currentSuite();

    /**
     * Generates a hybrid keypair for the specified cryptographic suite.
     */
    HybridKeyPair generateHybridKeyPair(AlgorithmSuite suite);

    /**
     * Generates a hybrid keypair using the default algorithm suite.
     */
    default HybridKeyPair generateHybridKeyPair() {
        return generateHybridKeyPair(currentSuite());
    }

    /**
     * Computes dual classical and PQC signatures over the supplied data buffer without
     * creating heap allocations for payload data.
     */
    HybridSignature sign(ByteBuf data, HybridKeyPair keyPair, ByteBufAllocator allocator);

    /**
     * Verifies both classical and post-quantum signatures against the provided hybrid public key.
     * Enforces strict fail-closed policy: returns true only if BOTH signatures verify.
     */
    boolean verify(ByteBuf data, ByteBuf classicalSig, ByteBuf pqcSig, HybridPublicKey publicKey);

    /**
     * Verifies a {@link HybridSignature} against the provided hybrid public key.
     */
    default boolean verify(ByteBuf data, HybridSignature signature, HybridPublicKey publicKey) {
        return verify(data, signature.classicalSignature(), signature.pqcSignature(), publicKey);
    }

    /**
     * Static factory returning a new default production instance.
     */
    static CryptoAgilityEngine createDefault() {
        return new DefaultCryptoAgilityEngine();
    }
}
