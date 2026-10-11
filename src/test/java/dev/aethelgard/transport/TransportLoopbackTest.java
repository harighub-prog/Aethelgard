package dev.aethelgard.transport;

import dev.aethelgard.core.AgentConfig;
import dev.aethelgard.protocol.CommandType;
import dev.aethelgard.protocol.FrameCodecException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Live loopback smoke test: real TCP sockets over 127.0.0.1, no EmbeddedChannel.
 * Exercises the full bootstrap stack — ServerBootstrap/Bootstrap, shared event
 * loop group, pipeline initializer, socket options.
 *
 * Resource discipline: the server-side frame listener COPIES payload bytes into
 * plain arrays before the terminal handler releases the Frame — never retain a
 * reference to a released ByteBuf. Everything is closed in @AfterEach in strict
 * order (sockets → event loops) so worker threads and selectors cannot leak;
 * the paranoid leak detector (surefire argLine) fails the build on any missed
 * buffer release.
 */
class TransportLoopbackTest {

    private TransportServer server;
    private TransportClient client;
    private AgentNodeHandler serverHandler;

    // Payload snapshots taken ON THE EVENT LOOP before the terminal handler
    // releases the Frame — comparing a released ByteBuf would throw
    // IllegalReferenceCount, so the listener detaches a copy immediately.
    private final CopyOnWriteArrayList<ByteBuf> receivedPayloads = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<CommandType> receivedCommands = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<String> peerKeys = new CopyOnWriteArrayList<>();
    private final AtomicReference<Throwable> serverFatal = new AtomicReference<>();
    private volatile CountDownLatch frameLatch;
    private volatile CountDownLatch fatalLatch;

    @BeforeEach
    void setUp() {
        frameLatch = new CountDownLatch(1);
        fatalLatch = new CountDownLatch(1);

        serverHandler = new AgentNodeHandler((ctx, frame) -> {
            receivedCommands.add(frame.command());
            receivedPayloads.add(io.netty.buffer.Unpooled.copiedBuffer(frame.payload()));
            peerKeys.add(PeerIdentity.keyIdOf(ctx)); // package-private: same package in tests
            frameLatch.countDown();
        }) {
            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                serverFatal.set(cause);
                fatalLatch.countDown();
                super.exceptionCaught(ctx, cause);
            }
        };

        server = TransportServer.standalone(AgentConfig.defaults(), serverHandler).start();
        client = TransportClient.standalone(AgentConfig.defaults(), new AgentNodeHandler());
    }

    @AfterEach
    void tearDown() {
        // Strict order: client socket+loops, then server socket+loops. Each
        // close() blocks only until kernel-level teardown confirms, preventing
        // both thread and fd leaks across the suite.
        client.close();
        server.close();
    }

    private static ByteBuf payload(String text) {
        return Unpooled.wrappedBuffer(text.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    @Test
    @DisplayName("Live TCP: HANDSHAKE frame client→server arrives intact, no refcount leak")
    void handshakeOverRealSocket() throws Exception {
        Channel ch = client.connect("127.0.0.1", server.boundPort());
        assertTrue(ch.isActive());

        ByteBuf body = payload("AETHELGARD-HANDSHAKE-v1");
        ByteBuf expectedCopy = body.copy(); // survive the encoder's release of the source
        assertEquals(1, body.refCnt());

        ch.writeAndFlush(new Frame(CommandType.HANDSHAKE, body)).sync();
        assertEquals(0, body.refCnt(), "encoder must release the outbound payload exactly once");

        assertTrue(frameLatch.await(5, TimeUnit.SECONDS), "server must receive the frame");
        assertEquals(1, receivedPayloads.size());

        assertEquals(CommandType.HANDSHAKE, receivedCommands.get(0));
        assertEquals(expectedCopy, receivedPayloads.get(0));
        expectedCopy.release();

        // Per-peer counter (the Layer 3 telemetry seed) registered exactly one frame.
        assertEquals(1, serverHandler.framesReceivedFrom(peerKeys.get(0)));
    }

    @Test
    @DisplayName("Malformed garbage → classified MALFORMED fatal, socket severed by server")
    void garbageBytesDisconnectPeer() throws Exception {
        Channel ch = client.connect("127.0.0.1", server.boundPort());

        // Raw garbage written UNDER the framing layer (no encoder) — simulates a
        // fuzzer or non-Aethelgard client speaking straight to the socket.
        ch.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{(byte) 0xDE, (byte) 0xAD, 0, 0, 0, 8, 1, 1, 2, 3, 4, 5, 6, 7, 8}))
                .sync();

        assertTrue(fatalLatch.await(5, TimeUnit.SECONDS), "server exceptionCaught must fire");
        Throwable fatal = serverFatal.get();
        assertInstanceOf(DecoderException.class, fatal);
        FrameCodecException cause = assertInstanceOf(FrameCodecException.class, fatal.getCause());
        assertEquals(FrameCodecException.Severity.MALFORMED, cause.severity());

        // Server forces the disconnect: client channel must observe closure.
        ch.closeFuture().await(5, TimeUnit.SECONDS);
        assertFalse(ch.isActive(), "peer socket must be severed after malformed input");
    }
}
