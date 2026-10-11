package dev.aethelgard.transport;

import dev.aethelgard.crypto.AethelgardTrustManager;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslHandler;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Unified peer identity extraction. The mesh-wide identity of a peer is the
 * SHA-256 key-ID of its X.509 public key — the exact same identifier the
 * {@link AethelgardTrustManager} registry, the telemetry sensor, and the
 * decision loop key on. One identity, every layer.
 *
 * Fallback: on a plaintext channel (diagnostics/codec tests only) there is no
 * certificate, so the socket remote-address string is used. Production mTLS
 * channels always resolve cryptographically.
 *
 * Cost profile: pipeline lookup + session lookup are O(1) map reads; the
 * SHA-256 digest runs once per invocation, never per byte. Callers should
 * cache the result per channel (handlers call it once per event, which is
 * negligible against frame parsing costs and keeps the code stateless).
 */
public final class PeerIdentity {

    private PeerIdentity() {
    }

    /**
     * Resolves the peer's cryptographic key-ID from the active SSL session,
     * falling back to the remote address when no TLS session exists.
     */
    public static String keyIdOf(ChannelHandlerContext ctx) {
        SslHandler ssl = ctx.pipeline().get(SslHandler.class);
        if (ssl != null) {
            try {
                Certificate[] certs = ssl.engine().getSession().getPeerCertificates();
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                    return AethelgardTrustManager.keyId(x509.getPublicKey());
                }
            } catch (SSLPeerUnverifiedException ignored) {
                // Handshake not yet complete: fall through to the address key.
            }
        }
        return String.valueOf(ctx.channel().remoteAddress());
    }
}
