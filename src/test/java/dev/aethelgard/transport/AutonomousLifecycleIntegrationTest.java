package dev.aethelgard.transport;

import dev.aethelgard.core.AgentConfig;
import dev.aethelgard.crypto.AethelgardTrustManager;
import dev.aethelgard.crypto.CryptoMaterialGenerator;
import dev.aethelgard.crypto.TlsContextFactory;
import dev.aethelgard.protocol.CommandType;
import dev.aethelgard.telemetry.DefaultBehaviorScorer;
import dev.aethelgard.telemetry.DefaultDecisionLoop;
import dev.aethelgard.telemetry.LockFreeTelemetrySensor;
import dev.aethelgard.telemetry.PeerMetrics;
import dev.aethelgard.telemetry.BehaviorScorer.ScoredVerdict;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end autonomous lifecycle: two live mTLS nodes, real TCP, the full
 * Perceive → Decide → Act pipeline executing against genuine telemetry.
 *
 * Phase A — normal flight: 5 echoed frames; metrics stay clean, weight climbs
 *           to the healthy maximum.
 * Phase B — mid-flight attack: a burst of malformed frames within one window.
 *           The decoder severs each violating connection (by design), so the
 *           burst is delivered as rapid reconnects — exactly how a real
 *           fuzzing attack presents.
 * Phase C — autonomous revocation: one decision cycle reads the windowed
 *           penalty, drives the weight below zero, nominates for quarantine
 *           and revokes the peer's key in the trust registry.
 * Phase D — handshake blockade: the revoked identity's new connection dies at
 *           the TLS gate; zero application frames can ever pass.
 *
 * Scorer thresholds are test-tuned (malformedRateLimit 2/s, weightMalformed
 * 30, cleanReward 100) so a 6+ events/s burst quarantines in a single cycle —
 * deterministic and fast, with the DEFAULTS' production semantics unchanged
 * (they are exercised in BehaviorScorerTest).
 */
class AutonomousLifecycleIntegrationTest {

    private static final long SENSOR_WINDOW_MILLIS = 1_000L;   // 1 s attack window
    private static final int ATTACK_CONNECTIONS = 8;           // > 6 events/s target

    private CryptoMaterialGenerator.CryptoMaterial nodeA;      // server identity
    private CryptoMaterialGenerator.CryptoMaterial nodeB;      // client identity
    private AethelgardTrustManager trustA;
    private AethelgardTrustManager trustB;
    private LockFreeTelemetrySensor sensor;
    private DefaultDecisionLoop loop;

    private TransportServer serverA;
    private TransportClient clientB;
    private final List<String> quarantineNominations = new CopyOnWriteArrayList<>();

    /** Server-side echo + telemetry. The echo gives the ack-matcher real RTTs. */
    private AgentNodeHandler serverHandler;

    @BeforeEach
    void setUp() {
        nodeA = CryptoMaterialGenerator.generate("node-A");
        nodeB = CryptoMaterialGenerator.generate("node-B");
        trustA = new AethelgardTrustManager();
        trustB = new AethelgardTrustManager();
        trustA.trust(nodeB.publicKey());
        trustB.trust(nodeA.publicKey());

        sensor = new LockFreeTelemetrySensor(SENSOR_WINDOW_MILLIS, 2_000L);
        serverHandler = new AgentNodeHandler(
                (ctx, frame) -> ctx.writeAndFlush(
                        // Echo: ownership-safe heap copy; the terminal handler
                        // releases the inbound payload in its finally block.
                        new Frame(frame.command(), Unpooled.copiedBuffer(frame.payload()))),
                sensor);

        SslContext serverTls = TlsContextFactory.serverContext(nodeA, trustA);
        serverA = TransportServer.standalone(AgentConfig.defaults(), serverTls, sensor, trustA, serverHandler).start();

        // Test-tuned scorer: see class javadoc.
        var thresholds = new DefaultBehaviorScorer.Thresholds(
                50.0f, 10.0f, 40.0f,
                2.0,   // malformedRateLimit: anything above 2/s is attack territory here
                0.5, 2.0, 3,
                30.0,  // weightMalformed: 6 events/s ⇒ (6−2)·30 = 120 ⇒ sub-zero in one cycle
                15.0, 5.0, 2.0,
                100.0f); // cleanReward: one clean window ⇒ healthy maximum (clamped at 100)
        loop = new DefaultDecisionLoop(sensor, new DefaultBehaviorScorer(thresholds), trustA,
                250, quarantineNominations::add);
    }

    @AfterEach
    void tearDown() {
        if (loop != null) loop.close();
        if (clientB != null) clientB.close();
        if (serverA != null) serverA.close();
    }

    private String clientKeyId() {
        return AethelgardTrustManager.keyId(nodeB.publicKey());
    }

    private Channel connect() {
        if (clientB == null) {
            clientB = TransportClient.standalone(AgentConfig.defaults(),
                    TlsContextFactory.clientContext(nodeB, trustB), new AgentNodeHandler());
        }
        Channel ch = clientB.connect("127.0.0.1", serverA.boundPort());
        ch.pipeline().get(SslHandler.class).handshakeFuture().awaitUninterruptibly(5_000);
        return ch;
    }

    private void sendFrame(Channel ch, String text) {
        ch.writeAndFlush(new Frame(CommandType.TELEMETRY,
                Unpooled.wrappedBuffer(text.getBytes(StandardCharsets.US_ASCII)))).syncUninterruptibly();
    }

    @Test
    @DisplayName("Full autonomous lifecycle: clean flight → attack → revocation → TLS blockade")
    void fullLifecycle() throws Exception {
        String peerKey = clientKeyId();
        assertTrue(trustA.isTrustedKeyId(peerKey), "precondition: client admitted");

        // ── Phase A: Normal Flight ──────────────────────────────────────────
        Channel ch = connect();
        for (int i = 0; i < 5; i++) {
            sendFrame(ch, "flight-frame-" + i);
        }
        // Echoes flow back through the same handler; give the pipeline a beat.
        Thread.sleep(150);

        PeerMetrics flight = sensor.snapshot(peerKey);
        assertEquals(0, flight.malformedFrames(), "no malformed frames in normal flight");
        assertEquals(0, flight.resourceAbuseEvents(), "no abuse events in normal flight");
        assertEquals(1.0, flight.hygieneRatio(), 0.0001, "hygiene perfect");
        assertEquals(5, flight.framesReceived(), "all 5 frames counted");
        assertTrue(flight.latencyEwmaMillis() > 0.0, "ack-matcher derived a real RTT sample");

        loop.runSingleCycle();
        assertTrue(loop.weightOf(peerKey) >= 100.0f,
                "clean window carries the weight to the healthy maximum, got " + loop.weightOf(peerKey));

        // ── Phase B: Mid-Flight Attack (burst of malformed frames) ─────────
        // Each malformed frame is fatal (by design), so the burst presents as
        // rapid reconnects — all landing inside the 1 s telemetry window.
        for (int i = 0; i < ATTACK_CONNECTIONS; i++) {
            Channel attack = connect();
            // Raw garbage straight on the socket: valid-looking header, wrong magic.
            attack.writeAndFlush(Unpooled.wrappedBuffer(
                    new byte[]{(byte) 0xDE, (byte) 0xAD, 0, 0, 0, 8, 1, 1, 2, 3, 4, 5, 6, 7, 8}))
                    .syncUninterruptibly();
            attack.closeFuture().await(2, TimeUnit.SECONDS); // server severs it
        }

        PeerMetrics attack = sensor.snapshot(peerKey);
        assertTrue(attack.malformedFrames() >= 6,
                "burst must register ≥6 malformed frames in the window, got " + attack.malformedFrames());
        assertTrue(attack.malformedFrameRate() > 2.0, "rate must exceed the test limit");

        // ── Phase C: Autonomous Revocation ──────────────────────────────────
        loop.runSingleCycle();
        ScoredVerdict expected = new DefaultBehaviorScorer(
                new DefaultBehaviorScorer.Thresholds(50.0f, 10.0f, 40.0f, 2.0, 0.5, 2.0, 3,
                        30.0, 15.0, 5.0, 2.0, 100.0f)).evaluate(100.0f, attack);
        assertTrue(loop.weightOf(peerKey) <= 0.0f,
                "penalty must drive the weight to/below zero, got " + loop.weightOf(peerKey));
        assertEquals(ScoredVerdict.Action.QUARANTINE_NOMINATE, expected.action());
        assertTrue(quarantineNominations.contains(peerKey),
                "quarantine nomination must reach the Layer 4 gossip seam");
        assertFalse(trustA.isTrustedKeyId(peerKey),
                "trust registry must have revoked the attacker's key");

        // ── Phase D: Handshake Blockade ─────────────────────────────────────
        // The revocation is enforced by BOTH gates: a full TLS handshake dies
        // inside the AethelgardTrustManager; a resumed TLS 1.3 session (cached
        // PSK, no certificate message) dies at AgentNodeHandler's post-
        // handshake identity re-verification. Either way the channel never
        // becomes usable for application frames.
        clientB.close();
        clientB = null;
        final CountDownLatch severed = new CountDownLatch(1);
        AgentNodeHandler observer = new AgentNodeHandler() {
            @Override
            public void channelInactive(ChannelHandlerContext ctx) {
                severed.countDown();
            }
        };
        clientB = TransportClient.standalone(AgentConfig.defaults(),
                TlsContextFactory.clientContext(nodeB, trustB), observer);
        Channel blocked = clientB.connect("127.0.0.1", serverA.boundPort());

        var hsFuture = blocked.pipeline().get(SslHandler.class).handshakeFuture();
        hsFuture.awaitUninterruptibly(5_000);
        assertTrue(severed.await(3, TimeUnit.SECONDS),
                "revoked identity's channel must be severed (TLS gate or re-verification gate)");
        assertFalse(blocked.isActive(), "channel must be dead after the blockade");
        assertEquals(5, sensor.snapshot(peerKey).framesReceived(),
                "no new application frames may pass after revocation");
    }
}
