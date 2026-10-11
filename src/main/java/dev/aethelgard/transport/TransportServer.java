package dev.aethelgard.transport;

import dev.aethelgard.core.AgentConfig;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.ssl.SslContext;
import dev.aethelgard.telemetry.PeerTelemetrySensor;
import dev.aethelgard.crypto.AethelgardTrustManager;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/**
 * Accept side of the mesh transport. Per the Layer 1 architectural contract a
 * single shared {@link NioEventLoopGroup} serves both the acceptor (boss) and
 * I/O (worker) roles: one selector loop pool, one thread budget, shared by the
 * {@link TransportClient} via {@link #eventLoopGroup()}.
 *
 * Lifecycle: construct → {@link #start()} (binds, blocking only until the
 * kernel confirms the bind) → {@link #shutdownGracefully()} (non-blocking;
 * the returned future completes when selector loops and worker threads exit).
 * Channels are closed before the loops shut down so no handler races a dead loop.
 */
public class TransportServer implements AutoCloseable {

    private final AgentConfig config;
    private final EventLoopGroup eventLoopGroup;
    private final boolean ownsGroup;
    private final SslContext sslContext;
    private final AgentNodeHandler agentHandler;
    private volatile Channel serverChannel;

    public TransportServer(AgentConfig config, EventLoopGroup sharedGroup, AgentNodeHandler agentHandler) {
        this(config, sharedGroup, null, agentHandler);
    }

    public TransportServer(AgentConfig config, EventLoopGroup sharedGroup, SslContext sslContext,
                           AgentNodeHandler agentHandler) {
        this(config, sharedGroup, sslContext, null, agentHandler);
    }

    public TransportServer(AgentConfig config, EventLoopGroup sharedGroup, SslContext sslContext,
                           PeerTelemetrySensor sensor, AgentNodeHandler agentHandler) {
        this(config, sharedGroup, sslContext, sensor, null, agentHandler);
    }

    public TransportServer(AgentConfig config, EventLoopGroup sharedGroup, SslContext sslContext,
                           PeerTelemetrySensor sensor, AethelgardTrustManager trustManager,
                           AgentNodeHandler agentHandler) {
        this.config = config;
        this.eventLoopGroup = sharedGroup;
        this.sslContext = sslContext;
        this.agentHandler = agentHandler;
        this.sensor = sensor;
        this.trustManager = trustManager;
        this.ownsGroup = false;
    }

    /** Convenience factory owning its own group (tests, standalone node). */
    public static TransportServer standalone(AgentConfig config, AgentNodeHandler agentHandler) {
        return standalone(config, null, agentHandler);
    }

    public static TransportServer standalone(AgentConfig config, SslContext sslContext, AgentNodeHandler agentHandler) {
        return standalone(config, sslContext, null, agentHandler);
    }

    public static TransportServer standalone(AgentConfig config, SslContext sslContext,
                                             PeerTelemetrySensor sensor, AgentNodeHandler agentHandler) {
        return new TransportServer(config, new NioEventLoopGroup(1), true, sslContext, sensor, null, agentHandler);
    }

    public static TransportServer standalone(AgentConfig config, SslContext sslContext,
                                             PeerTelemetrySensor sensor, AethelgardTrustManager trustManager,
                                             AgentNodeHandler agentHandler) {
        return new TransportServer(config, new NioEventLoopGroup(1), true, sslContext, sensor, trustManager, agentHandler);
    }

    private final PeerTelemetrySensor sensor;
    private final AethelgardTrustManager trustManager;

    private TransportServer(AgentConfig config, EventLoopGroup group, boolean ownsGroup,
                            SslContext sslContext, PeerTelemetrySensor sensor,
                            AethelgardTrustManager trustManager, AgentNodeHandler agentHandler) {
        this.config = config;
        this.eventLoopGroup = group;
        this.ownsGroup = ownsGroup;
        this.sslContext = sslContext;
        this.sensor = sensor;
        this.trustManager = trustManager;
        this.agentHandler = agentHandler;
    }

    public TransportServer start() {
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(eventLoopGroup) // single shared group: boss + worker roles
                .channel(NioServerSocketChannel.class)
                .childHandler(new PipelineInitializer(sslContext, sensor, trustManager, agentHandler))
                .childOption(ChannelOption.SO_KEEPALIVE, true)   // detect dead peers
                .childOption(ChannelOption.TCP_NODELAY, true)    // disable Nagle: small control frames go out immediately
                .childOption(ChannelOption.CONNECT_TIMEOUT_MILLIS, config.connectTimeoutMillis());

        ChannelFuture bindFuture = bootstrap.bind(new InetSocketAddress(config.bindHost(), config.bindPort()));
        bindFuture.syncUninterruptibly(); // bind only; all subsequent I/O stays async
        serverChannel = bindFuture.channel();
        return this;
    }

    /** Actual bound port — differs from config when config.bindPort == 0 (ephemeral). */
    public int boundPort() {
        return ((InetSocketAddress) serverChannel.localAddress()).getPort();
    }

    public EventLoopGroup eventLoopGroup() {
        return eventLoopGroup;
    }

    /** Non-blocking graceful teardown: close sockets first, then (if owned) the loops. */
    @Override
    public void close() {
        Channel ch = serverChannel;
        if (ch != null) {
            ch.close().syncUninterruptibly();
        }
        if (ownsGroup) {
            // shutdownGracefully() is non-blocking: it stops accepting new tasks,
            // waits out the quiet period, then releases selector threads.
            eventLoopGroup.shutdownGracefully(0, config.shutdownQuietPeriodMillis() * 10L, TimeUnit.MILLISECONDS)
                    .syncUninterruptibly();
        }
    }
}
