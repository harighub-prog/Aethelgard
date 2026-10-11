package dev.aethelgard.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;

/**
 * Programmatically generates a node's complete cryptographic identity entirely
 * in memory: EC P-256 keypair, self-signed X.509v3 certificate, and a PKCS12
 * {@link KeyStore} that never touches disk.
 *
 * Why EC P-256 over RSA-3072: 64-byte signatures vs 384 bytes, ~10x faster
 * handshakes, same 128-bit security level — better fit for a mesh where every
 * peer pairs with every peer. (RSA is available by flipping the algorithm.)
 *
 * Cert generation uses BouncyCastle only because the JDK exposes no public
 * X.509 *builder* API (sun.security.x509 is module-encapsulated). Trust
 * evaluation stays pure JCA — see {@link AethelgardTrustManager}.
 */
public final class CryptoMaterialGenerator {

    /** Identity lifetime: nodes re-issue material rather than live forever. */
    private static final long CERT_VALIDITY_DAYS = 365L;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /** A node's complete in-memory identity. The KeyStore holds the private key. */
    public record CryptoMaterial(
            KeyStore keyStore,
            X509Certificate certificate,
            java.security.PublicKey publicKey,
            char[] keyPassword) {
    }

    private CryptoMaterialGenerator() {
    }

    public static CryptoMaterial generate(String nodeId) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();

            X509Certificate cert = selfSign(nodeId, keyPair);

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null); // fresh in-memory keystore, no backing file
            char[] password = ("aethelgard-" + nodeId).toCharArray();
            ks.setKeyEntry("aethelgard", keyPair.getPrivate(), password,
                    new X509Certificate[]{cert});

            return new CryptoMaterial(ks, cert, keyPair.getPublic(), password);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate crypto material for " + nodeId, e);
        }
    }

    private static X509Certificate selfSign(String nodeId, KeyPair keyPair) throws Exception {
        Instant now = Instant.now();
        X500Name subject = new X500Name("CN=aethelgard-" + nodeId + ", O=AethelgardMesh");
        BigInteger serial = new BigInteger(63, new SecureRandom());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,               // issuer == subject: self-signed mesh identity
                serial,
                Date.from(now),
                Date.from(now.plusSeconds(CERT_VALIDITY_DAYS * 86_400)),
                subject,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
    }
}
