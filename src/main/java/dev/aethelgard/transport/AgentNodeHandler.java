package dev.aethelgard.transport;

import dev.aethelgard.crypto.AethelgardTrustManager;
import dev.aethelgard.gossip.GossipEngine;
import dev.aethelgard.gossip.QuarantineBallot;
import dev.aethelgard.protocol.CommandType;
import dev.aethelgard.telemetry.PeerTelemetrySensor;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Layer-1 terminal pipeline handler (stub). It terminates the inbound Frame
 * stream: consumes each frame, counts it per-peer-identity, optionally hands
 * the frame to a listener (used by tests and later by the autonomous decision
 * loop), and — critically — releases every Frame exactly once, because this
 * handler is the final owner of the decoded payload.
 *
 * Zero-trust hardening: on every SUCCESSFUL TLS handshake the peer identity is
 * RE-VERIFIED against the dynamic trust registry. This closes the TLS 1.3
 * session-resumption bypass: a resumed session authenticates via cached PSK
 * and carries no certificate message, so the JSSE trust manager is never
 * consulted — but the resumed session object still exposes the ORIGINAL peer
 * certificates, letting this handler enforce the admission gate regardless of
 * how the TLS layer authenticated the connection. A revoked peer that slips
 * past resumption is dropped here, before any frame is decoded.
 *
 * Stateless across channels, therefore safe to share as a single instance
 * ({@link Sharable}); all mutable counters are concurrent.
 */
@Sharable
public class AgentNodeHandler extends ChannelDuplexHandler {

    private final ConcurrentMap<String, AtomicLong> framesReceivedByPeer = new ConcurrentHashMap<>();
    private final BiConsumer<ChannelHandlerContext, Frame> frameListener;
    private final PeerTelemetrySensor sensor;              // nullable in codec-only contexts
    private final AethelgardTrustManager trustManager;     // nullable: disables re-verification
    private final GossipEngine gossipEngine;               // nullable: no Layer 4 wiring

    public AgentNodeHandler() {
        this(null, null, null, null);
    }

    public AgentNodeHandler(BiConsumer<ChannelHandlerContext, Frame> frameListener) {
        this(frameListener, null, null, null);
    }

    public AgentNodeHandler(BiConsumer<ChannelHandlerContext, Frame> frameListener,
                            PeerTelemetrySensor sensor) {
        this(frameListener, sensor, null, null);
    }

    public AgentNodeHandler(BiConsumer<ChannelHandlerContext, Frame> frameListener,
                            PeerTelemetrySensor sensor,
                            AethelgardTrustManager trustManager) {
        this(frameListener, sensor, trustManager, null);
    }

    public AgentNodeHandler(BiConsumer<ChannelHandlerContext, Frame> frameListener,
                            PeerTelemetrySensor sensor,
                            AethelgardTrustManager trustManager,
                            GossipEngine gossipEngine) {
        this.frameListener = frameListener;
        this.sensor = sensor;
        this.trustManager = trustManager;
        this.gossipEngine = gossipEngine;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        // Layer 4 network blacklist: refuse connections from IPs of peers the
        // swarm has condemned, before any handshake or byte exchange.
        if (gossipEngine != null && ctx.channel().remoteAddress() instanceof
                java.net.InetSocketAddress addr && addr.getAddress() != null
                && gossipEngine.isIpBlacklisted(addr.getAddress().getHostAddress())) {
            ctx.close();
            return;
        }
        super.channelActive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof Frame frame) {
            try {
                String key = PeerIdentity.keyIdOf(ctx);
                if (gossipEngine != null && frame.command() == CommandType.GOSSIP) {
                    // Snapshot on the event loop (snapshot rule): the bytes are
                    // copied into the ballot object before the finally-block
                    // releases the payload buffer.
                    byte[] wire = new byte[frame.payload().readableBytes()];
                    frame.payload().readBytes(wire);
                    QuarantineBallot ballot = QuarantineBallot.decode(wire);
                    gossipEngine.onBallotReceived(ballot, ctx.channel());
                }
                framesReceivedByPeer
                        .computeIfAbsent(key, k -> new AtomicLong())
                        .incrementAndGet();
                if (sensor != null) {
                    // latencyNanos=0 delegates RTT computation to the sensor's
                    // ack-matcher (time since our last outbound frame).
                    sensor.recordFrameReceived(key, 0L);
                }
                if (frameListener != null) {
                    frameListener.accept(ctx, frame);
                }
            } finally {
                // Terminal owner of the decoded payload: release exactly once,
                // on both the happy path and listener failure.
                frame.release();
            }
        } else {
            // Frames are the only legal inbound type at this pipeline position.
            ctx.fireChannelRead(msg);
        }
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SslHandshakeCompletionEvent e) {
            if (e.isSuccess()) {
                // Post-handshake identity re-verification — closes the TLS 1.3
                // resumption bypass (see class javadoc). Revoked peers are
                // severed before the framing codec ever sees their bytes.
                if (trustManager != null) {
                    String keyId = PeerIdentity.keyIdOf(ctx);
                    if (!trustManager.isTrustedKeyId(keyId)
                            && !keyId.equals(String.valueOf(ctx.channel().remoteAddress()))) {
                        // Cryptographic identity present but not admitted: drop.
                        ctx.close();
                        return;
                    }
                }
                if (sensor != null) {
                    sensor.recordHandshakeSuccess(PeerIdentity.keyIdOf(ctx));
                }
                // Layer 4: admission into the swarm routing topology — this
                // channel becomes a gossip relay target and a severance
                // candidate should its peer ever be condemned by consensus.
                if (gossipEngine != null) {
                    gossipEngine.registerChannel(PeerIdentity.keyIdOf(ctx), ctx.channel());
                }
            } else if (sensor != null) {
                // TLS-gate rejection (untrusted/revoked key): telemetry key falls
                // back to the remote address — the peer never proved an identity.
                sensor.recordHandshakeFailure(PeerIdentity.keyIdOf(ctx));
            }
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (gossipEngine != null) {
            gossipEngine.unregisterChannel(PeerIdentity.keyIdOf(ctx), ctx.channel());
        }
        super.channelInactive(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        // Layer 3 telemetry hook: every fatal codec event lands here before the
        // decoder closes the socket. Stub for now; the BehaviorScorer will
        // subscribe to this signal.
        ctx.fireExceptionCaught(cause);
    }

    public long framesReceivedFrom(String peerKey) {
        AtomicLong n = framesReceivedByPeer.get(peerKey);
        return n == null ? 0 : n.get();
    }

}
