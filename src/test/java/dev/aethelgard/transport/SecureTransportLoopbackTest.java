package dev.aethelgard.transport;

import dev.aethelgard.core.AgentConfig;
import dev.aethelgard.crypto.AethelgardTrustManager;
import dev.aethelgard.crypto.CryptoMaterialGenerator;
import dev.aethelgard.crypto.TlsContextFactory;
import dev.aethelgard.protocol.CommandType;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Layer 2 integration: full mTLS over real loopback TCP sockets between two
 * independently generated node identities.
 *
 * Scenario A: mutual key pinning → TLS 1.3 handshake succeeds → framed payload
 *             crosses the encrypted tunnel intact.
 * Scenario B: server never admits the client's key → handshake dies inside the
 *             SslHandler; the framing codec never fires; socket severed.
 *
 * As with the plaintext test, payload bytes are snapshotted on the event loop
 * before the terminal handler releases the Frame, and teardown order is
 * client-then-server to guarantee clean loop/thread disposal.
 */
class SecureTransportLoopbackTest {

    // Node identities — fully independent, generated in memory, never on disk.
    private CryptoMaterialGenerator.CryptoMaterial nodeA;
    private CryptoMaterialGenerator.CryptoMaterial nodeB;
    private AethelgardTrustManager trustA; // server side (Node A)
    private AethelgardTrustManager trustB; // client side (Node B)

    private TransportServer serverA;
    private TransportClient clientB;

    private final CopyOnWriteArrayList<CommandType> receivedCommands = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<ByteBuf> receivedPayloads = new CopyOnWriteArrayList<>();
    private final AtomicReference<Throwable> clientFailure = new AtomicReference<>();
    private volatile CountDownLatch frameLatch;
    private volatile CountDownLatch failureLatch;

    @BeforeEach
    void setUp() {
        nodeA = CryptoMaterialGenerator.generate("node-A");
        nodeB = CryptoMaterialGenerator.generate("node-B");
        trustA = new AethelgardTrustManager();
        trustB = new AethelgardTrustManager();
        frameLatch = new CountDownLatch(1);
        failureLatch = new CountDownLatch(1);
    }

    @AfterEach
    void tearDown() {
        if (clientB != null) clientB.close();
        if (serverA != null) serverA.close();
    }

    private TransportServer startServer() {
        AgentNodeHandler handler = new AgentNodeHandler((ctx, frame) -> {
            receivedCommands.add(frame.command());
            receivedPayloads.add(Unpooled.copiedBuffer(frame.payload()));
            frameLatch.countDown();
        });
        SslContext sslCtx = TlsContextFactory.serverContext(nodeA, trustA);
        serverA = TransportServer.standalone(AgentConfig.defaults(), sslCtx, handler).start();
        return serverA;
    }

    private Channel connectClient() {
        AgentNodeHandler handler = new AgentNodeHandler() {
            @Override
            public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
                if (evt instanceof SslHandshakeCompletionEvent e && !e.isSuccess()) {
                    clientFailure.set(e.cause());
                    failureLatch.countDown();
                }
            }

            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                clientFailure.compareAndSet(null, cause);
                failureLatch.countDown();
            }
        };
        SslContext sslCtx = TlsContextFactory.clientContext(nodeB, trustB);
        clientB = TransportClient.standalone(AgentConfig.defaults(), sslCtx, handler);
        return clientB.connect("127.0.0.1", serverA.boundPort());
    }

    @Test
    @DisplayName("Trusted mTLS: pinned keys on both sides, frame crosses TLS 1.3 tunnel intact")
    void trustedHandshakeExchangesFrame() throws Exception {
        // Mutual pinning: each side admits the other's public key.
        trustA.trust(nodeB.publicKey());
        trustB.trust(nodeA.publicKey());
        assertEquals(1, trustA.trustedPeerCount());

        startServer();
        Channel ch = connectClient();

        // TLS handshake must complete before any application byte flows.
        ch.pipeline().get(io.netty.handler.ssl.SslHandler.class)
                .handshakeFuture().await(5, TimeUnit.SECONDS);

        ByteBuf body = Unpooled.wrappedBuffer("SECURE-AETHELGARD".getBytes(StandardCharsets.US_ASCII));
        ByteBuf expected = body.copy();
        ch.writeAndFlush(new Frame(CommandType.HANDSHAKE, body)).sync();
        assertEquals(0, body.refCnt(), "encoder released the outbound payload");

        assertTrue(frameLatch.await(5, TimeUnit.SECONDS), "server must decrypt & decode the frame");
        assertEquals(CommandType.HANDSHAKE, receivedCommands.get(0));
        assertEquals(expected, receivedPayloads.get(0));
        expected.release();
    }

    @Test
    @DisplayName("Untrusted peer: handshake rejected at TLS layer, zero frames ever decoded")
    void untrustedPeerIsolatedBeforeFraming() throws Exception {
        // Node A (server) NEVER admits Node B's key. Node B trusts A, so the
        // failure will be asymmetric — exactly the zero-trust scenario.
        trustB.trust(nodeA.publicKey());

        startServer();
        Channel ch = connectClient();

        // Client observes the handshake death as an SSLHandshakeException
        // (surfaced via SslHandshakeCompletionEvent / pipeline exception).
        assertTrue(failureLatch.await(5, TimeUnit.SECONDS), "handshake failure must surface");
        Throwable cause = clientFailure.get();
        Throwable root = cause instanceof DecoderException de && de.getCause() != null ? de.getCause() : cause;
        assertInstanceOf(javax.net.ssl.SSLException.class, root,
                "expected SSL-level failure, got: " + root);

        // The socket is severed and the framing codec never produced a frame.
        ch.closeFuture().await(5, TimeUnit.SECONDS);
        assertFalse(ch.isActive());
        assertTrue(receivedPayloads.isEmpty(), "no application frame may ever be decoded");
        assertTrue(receivedCommands.isEmpty());
    }

    @Test
    @DisplayName("Runtime revocation: trusted key revoked mid-flight blocks the NEXT handshake")
    void runtimeRevocationBlocksNewHandshakes() throws Exception {
        trustA.trust(nodeB.publicKey());
        trustB.trust(nodeA.publicKey());
        startServer();

        // First connection succeeds.
        Channel first = connectClient();
        first.pipeline().get(io.netty.handler.ssl.SslHandler.class)
                .handshakeFuture().await(5, TimeUnit.SECONDS);
        assertTrue(first.isActive());
        first.close().sync();
        clientB.close();
        clientB = null;

        // Layer 3 preview: BehaviorScorer drops the peer's weight to zero.
        trustA.revoke(nodeB.publicKey());
        assertFalse(trustA.isTrusted(nodeB.publicKey()));

        // Second connection: same identity, now revoked — must die at TLS.
        connectClient();
        assertTrue(failureLatch.await(5, TimeUnit.SECONDS),
                "revoked peer's handshake must be rejected without restart");
        assertTrue(receivedPayloads.isEmpty());
    }
}
