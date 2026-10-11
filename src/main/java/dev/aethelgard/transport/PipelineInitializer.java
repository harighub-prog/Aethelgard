package dev.aethelgard.transport;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import dev.aethelgard.telemetry.PeerTelemetrySensor;
import dev.aethelgard.crypto.AethelgardTrustManager;

/**
 * Single source of truth for pipeline layout, for both inbound (accepted) and
 * outbound (dialed) channels. The Layer 2 SslHandler now occupies the reserved
 * addFirst slot: every subsequent handler sees decrypted plaintext, and all
 * outbound bytes are encrypted before hitting the socket.
 *
 * Passing a null sslContext yields a plaintext pipeline (kept for the Layer 1
 * codec tests and local diagnostics only — never in production).
 */
public class PipelineInitializer extends ChannelInitializer<SocketChannel> {

    private final SslContext sslContext;
    private final PeerTelemetrySensor sensor;
    private final AethelgardTrustManager trustManager;
    private final AgentNodeHandler agentHandler;

    public PipelineInitializer(AgentNodeHandler agentHandler) {
        this(null, null, null, agentHandler);
    }

    public PipelineInitializer(SslContext sslContext, AgentNodeHandler agentHandler) {
        this(sslContext, null, null, agentHandler);
    }

    public PipelineInitializer(SslContext sslContext, PeerTelemetrySensor sensor,
                               AgentNodeHandler agentHandler) {
        this(sslContext, sensor, null, agentHandler);
    }

    public PipelineInitializer(SslContext sslContext, PeerTelemetrySensor sensor,
                               AethelgardTrustManager trustManager, AgentNodeHandler agentHandler) {
        this.sslContext = sslContext;
        this.sensor = sensor;
        this.trustManager = trustManager;
        this.agentHandler = agentHandler;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        // ─────────────────────────────────────────────────────────────────────
        // LAYER 2: mTLS stream wrapper. FIRST in the pipeline — the framing
        // codec downstream therefore parses a trusted, decrypted byte stream.
        // ClientAuth.REQUIRE + dynamic AethelgardTrustManager were baked into
        // the SslContext by TlsContextFactory; a rejected peer dies HERE,
        // before any Aethelgard frame is ever decoded.
        // ─────────────────────────────────────────────────────────────────────
        if (sslContext != null) {
            SslHandler sslHandler = sslContext.newHandler(ch.alloc());
            // Begin the handshake immediately on channel activation so the
            // codec layers see no plaintext window at all.
            sslHandler.setHandshakeTimeoutMillis(5_000);
            ch.pipeline().addLast("ssl", sslHandler);
        }

        ch.pipeline().addLast("frameDecoder", new AethelFrameDecoder(sensor));
        ch.pipeline().addLast("frameEncoder", new AethelFrameEncoder(sensor));
        ch.pipeline().addLast("agentHandler", agentHandler);
    }

    /** Returns the trust manager associated with this pipeline initializer. */
    public AethelgardTrustManager trustManager() {
        return trustManager;
    }
}
