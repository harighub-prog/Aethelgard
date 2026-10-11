package dev.aethelgard.crypto;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;

/**
 * Concrete implementation of {@link CryptoAgilityEngine}.
 *
 * Implements hybrid validation executing classical NIST P-256 (secp256r1) ECDSA
 * in tandem with NIST FIPS 204 ML-DSA (Dilithium) post-quantum signatures via BouncyCastle.
 *
 * Enforces the zero-heap memory policy: feeds direct {@link ByteBuffer} slices to the
 * underlying {@link Signature} engine using {@link ByteBuf#nioBuffers()}, bypassing
 * intermediate heap array allocations.
 */
public final class DefaultCryptoAgilityEngine implements CryptoAgilityEngine {

    private static final String BC_PROVIDER = "BC";
    private final AlgorithmSuite defaultSuite;
    private final SecureRandom secureRandom;

    static {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public DefaultCryptoAgilityEngine() {
        this(AlgorithmSuite.HYBRID_P256_MLDSA65);
    }

    public DefaultCryptoAgilityEngine(AlgorithmSuite defaultSuite) {
        this.defaultSuite = Objects.requireNonNull(defaultSuite, "defaultSuite");
        this.secureRandom = new SecureRandom();
    }

    @Override
    public AlgorithmSuite currentSuite() {
        return defaultSuite;
    }

    @Override
    public HybridKeyPair generateHybridKeyPair(AlgorithmSuite suite) {
        Objects.requireNonNull(suite, "suite");
        try {
            // 1. Classical EC P-256 KeyPair
            KeyPairGenerator classicalGen = KeyPairGenerator.getInstance(suite.classicalKeyAlgorithm());
            classicalGen.initialize(new ECGenParameterSpec(suite.classicalCurve()), secureRandom);
            KeyPair classicalKeyPair = classicalGen.generateKeyPair();

            // 2. Post-Quantum ML-DSA / Dilithium KeyPair
            KeyPairGenerator pqcGen = KeyPairGenerator.getInstance(suite.pqcKeyAlgorithm(), BC_PROVIDER);
            KeyPair pqcKeyPair = pqcGen.generateKeyPair();

            return new HybridKeyPair(suite, classicalKeyPair, pqcKeyPair);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to generate hybrid keypair for suite " + suite, e);
        }
    }

    @Override
    public HybridSignature sign(ByteBuf data, HybridKeyPair keyPair, ByteBufAllocator allocator) {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(keyPair, "keyPair");
        Objects.requireNonNull(allocator, "allocator");

        AlgorithmSuite suite = keyPair.suite();
        try {
            // Classical signature setup
            Signature classicalSigner = Signature.getInstance(suite.classicalSignatureAlgorithm());
            classicalSigner.initSign(keyPair.classicalKeyPair().getPrivate(), secureRandom);

            // Post-quantum signature setup
            Signature pqcSigner = Signature.getInstance(suite.pqcSignatureAlgorithm(), BC_PROVIDER);
            pqcSigner.initSign(keyPair.pqcKeyPair().getPrivate(), secureRandom);

            // Feed payload zero-heap copy to both signers
            feedDataZeroCopy(data, classicalSigner);
            feedDataZeroCopy(data, pqcSigner);

            byte[] classicalBytes = classicalSigner.sign();
            byte[] pqcBytes = pqcSigner.sign();

            ByteBuf classicalBuf = allocator.directBuffer(classicalBytes.length);
            classicalBuf.writeBytes(classicalBytes);

            ByteBuf pqcBuf = allocator.directBuffer(pqcBytes.length);
            pqcBuf.writeBytes(pqcBytes);

            return new HybridSignature(suite, classicalBuf, pqcBuf);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Hybrid signing failed for suite " + suite, e);
        }
    }

    @Override
    public boolean verify(ByteBuf data, ByteBuf classicalSig, ByteBuf pqcSig, HybridPublicKey publicKey) {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(classicalSig, "classicalSig");
        Objects.requireNonNull(pqcSig, "pqcSig");
        Objects.requireNonNull(publicKey, "publicKey");

        AlgorithmSuite suite = publicKey.suite();
        try {
            // 1. Verify Classical Signature
            Signature classicalVerifier = Signature.getInstance(suite.classicalSignatureAlgorithm());
            classicalVerifier.initVerify(publicKey.classicalPublicKey());
            feedDataZeroCopy(data, classicalVerifier);

            byte[] classicalSigBytes = new byte[classicalSig.readableBytes()];
            classicalSig.getBytes(classicalSig.readerIndex(), classicalSigBytes);
            if (!classicalVerifier.verify(classicalSigBytes)) {
                return false;
            }

            // 2. Verify Post-Quantum Signature
            Signature pqcVerifier = Signature.getInstance(suite.pqcSignatureAlgorithm(), BC_PROVIDER);
            pqcVerifier.initVerify(publicKey.pqcPublicKey());
            feedDataZeroCopy(data, pqcVerifier);

            byte[] pqcSigBytes = new byte[pqcSig.readableBytes()];
            pqcSig.getBytes(pqcSig.readerIndex(), pqcSigBytes);
            return pqcVerifier.verify(pqcSigBytes);
        } catch (GeneralSecurityException e) {
            // Fail closed on any cryptographic anomaly
            return false;
        }
    }

    /**
     * Feeds Netty ByteBuf memory to a JCA Signature engine using off-heap direct
     * ByteBuffer slices, completely bypassing intermediate heap array allocations.
     */
    private static void feedDataZeroCopy(ByteBuf data, Signature signature) throws SignatureException {
        int readerIndex = data.readerIndex();
        int readableBytes = data.readableBytes();
        if (readableBytes == 0) {
            return;
        }

        if (data.nioBufferCount() == 1) {
            ByteBuffer nio = data.internalNioBuffer(readerIndex, readableBytes);
            signature.update(nio.slice());
        } else {
            ByteBuffer[] nioBuffers = data.nioBuffers(readerIndex, readableBytes);
            for (ByteBuffer bb : nioBuffers) {
                signature.update(bb);
            }
        }
    }
}
