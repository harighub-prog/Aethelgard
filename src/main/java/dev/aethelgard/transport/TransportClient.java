package dev.aethelgard.transport;

import dev.aethelgard.core.AgentConfig;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.ssl.SslContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/**
 * Dial side of the mesh transport. Attaches to the SAME
 * {@link EventLoopGroup} as the server wherever available — one selector pool,
 * one thread budget for the whole agent node (architectural contract:
 * "never one loop per peer").
 */
public class TransportClient implements AutoCloseable {

    private final AgentConfig config;
    private final EventLoopGroup eventLoopGroup;
    private final boolean ownsGroup;
    private final SslContext sslContext;
    private final AgentNodeHandler agentHandler;
    private volatile Channel channel;

    public TransportClient(AgentConfig config, EventLoopGroup sharedGroup, AgentNodeHandler agentHandler) {
        this(config, sharedGroup, null, agentHandler);
    }

    public TransportClient(AgentConfig config, EventLoopGroup sharedGroup, SslContext sslContext,
                           AgentNodeHandler agentHandler) {
        this.config = config;
        this.eventLoopGroup = sharedGroup;
        this.ownsGroup = false;
        this.sslContext = sslContext;
        this.agentHandler = agentHandler;
    }

    public static TransportClient standalone(AgentConfig config, AgentNodeHandler agentHandler) {
        return standalone(config, null, agentHandler);
    }

    public static TransportClient standalone(AgentConfig config, SslContext sslContext, AgentNodeHandler agentHandler) {
        return new TransportClient(config, new NioEventLoopGroup(1), true, sslContext, agentHandler);
    }

    private TransportClient(AgentConfig config, EventLoopGroup group, boolean ownsGroup,
                            SslContext sslContext, AgentNodeHandler agentHandler) {
        this.config = config;
        this.eventLoopGroup = group;
        this.ownsGroup = ownsGroup;
        this.sslContext = sslContext;
        this.agentHandler = agentHandler;
    }

    /** Connects to a peer. Blocking only until TCP establishment; I/O is fully async. */
    public Channel connect(String host, int port) {
        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .handler(new PipelineInitializer(sslContext, agentHandler))
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, config.connectTimeoutMillis());

        ChannelFuture connectFuture = bootstrap.connect(new InetSocketAddress(host, port));
        connectFuture.syncUninterruptibly();
        channel = connectFuture.channel();
        return channel;
    }

    /** Non-blocking graceful teardown: socket first, then (if owned) the loops. */
    @Override
    public void close() {
        Channel ch = channel;
        if (ch != null) {
            ch.close().syncUninterruptibly();
        }
        if (ownsGroup) {
            eventLoopGroup.shutdownGracefully(0, config.shutdownQuietPeriodMillis() * 10L, TimeUnit.MILLISECONDS)
                    .syncUninterruptibly();
        }
    }
}
