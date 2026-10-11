package dev.aethelgard.crypto;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.KeyStore;
import java.util.List;

/**
 * Builds the Netty {@link SslContext} pair for a node from its in-memory
 * {@link CryptoMaterialGenerator.CryptoMaterial} and dynamic
 * {@link AethelgardTrustManager}.
 *
 * Hard security posture, no configuration surface:
 *   - TLSv1.3 only
 *   - AEAD-only cipher suites (TLS_AES_128/256_GCM_SHA256/384, CHACHA20_POLY1305)
 *   - Server side mandates client certificates: ClientAuth.REQUIRE — a peer
 *     without an admitted key never completes the handshake.
 *
 * The client side also uses the dynamic AethelgardTrustManager (mutual,
 * symmetric zero-trust: the client authenticates the server's pinned key just
 * as the server authenticates the client's).
 */
public final class TlsContextFactory {

    private static final List<String> PROTOCOLS = List.of("TLSv1.3");

    private static final String[] AEAD_CIPHERS = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
    };

    private TlsContextFactory() {
    }

    public static SslContext serverContext(CryptoMaterialGenerator.CryptoMaterial id,
                                           AethelgardTrustManager trustManager) {
        try {
            return SslContextBuilder.forServer(keyManagers(id))
                    .protocols(PROTOCOLS)
                    .ciphers(List.of(AEAD_CIPHERS))
                    .clientAuth(ClientAuth.REQUIRE) // mTLS: no cert, no connection
                    .trustManager(factoryFor(trustManager))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build server SslContext", e);
        }
    }

    public static SslContext clientContext(CryptoMaterialGenerator.CryptoMaterial id,
                                           AethelgardTrustManager trustManager) {
        try {
            return SslContextBuilder.forClient()
                    .protocols(PROTOCOLS)
                    .ciphers(List.of(AEAD_CIPHERS))
                    .keyManager(keyManagers(id)) // present OUR cert to the server
                    .trustManager(factoryFor(trustManager))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build client SslContext", e);
        }
    }

    private static KeyManagerFactory keyManagers(CryptoMaterialGenerator.CryptoMaterial id) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(id.keyStore(), id.keyPassword());
        return kmf;
    }

    /**
     * Wraps the dynamic {@link AethelgardTrustManager} in a standard
     * {@link TrustManagerFactory} — the only trust-manager shape Netty's
     * SslContextBuilder accepts. No providers or files involved; the wrapped
     * manager remains fully mutable at runtime.
     */
    private static TrustManagerFactory factoryFor(AethelgardTrustManager trustManager) {
        TrustManagerFactorySpi spi = new TrustManagerFactorySpi() {
            @Override
            protected void engineInit(KeyStore ks) { /* dynamic registry, no store */ }

            @Override
            protected void engineInit(javax.net.ssl.ManagerFactoryParameters spec) { /* none */ }

            @Override
            protected TrustManager[] engineGetTrustManagers() {
                return new TrustManager[]{trustManager};
            }
        };
        return new TrustManagerFactory(spi, null, "AethelgardDynamic") {};
    }
}
