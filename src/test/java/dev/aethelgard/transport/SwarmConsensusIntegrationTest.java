package dev.aethelgard.transport;

import dev.aethelgard.core.AgentConfig;
import dev.aethelgard.crypto.AethelgardTrustManager;
import dev.aethelgard.crypto.CryptoMaterialGenerator;
import dev.aethelgard.crypto.TlsContextFactory;
import dev.aethelgard.gossip.ConsensusRegistry;
import dev.aethelgard.gossip.GossipEngine;
import dev.aethelgard.gossip.QuarantineBallot;
import dev.aethelgard.telemetry.DefaultBehaviorScorer;
import dev.aethelgard.telemetry.DefaultDecisionLoop;
import dev.aethelgard.telemetry.LockFreeTelemetrySensor;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Layer 4 end-to-end: a live 3-node loopback swarm (A, B, C) running full
 * mTLS + telemetry + decision loops + gossip engines + consensus registries.
 *
 * Attack flow:
 *   1. Node A attacks Node B (malformed-frame burst).
 *   2. Node B's decision loop reaches QUARANTINE_NOMINATE → signs an Ed25519
 *      ballot → anti-entropy push to its live peers (C among them).
 *   3. Node C verifies the signature, COUNTERSIGNS its own ballot; with
 *      2 distinct nominators > 3/2 the ABSOLUTE MAJORITY is reached on C —
 *      and C's countersignature, relayed back over the B↔C link, closes the
 *      majority on B as well.
 *   4. Both B and C autonomously sever A's live channels, blacklist its IP,
 *      and revoke its key. A's reconnection attempts die swarm-wide.
 *
 * Loopback caveat (inherent to 127.0.0.1 testing): all peers share one IP, so
 * the IP-level blacklist necessarily blocks every loopback peer on the
 * condemning node. The test asserts identity-level isolation (key-ID revocation
 * + channel severance), which is what production multi-host deployments rely
 * on; the IP gate is additionally observable on C's fresh-connection refusal.
 */
class SwarmConsensusIntegrationTest {

    private static final long SENSOR_WINDOW_MILLIS = 1_000L;
    private static final int ATTACK_CONNECTIONS = 8;

    private CryptoMaterialGenerator.CryptoMaterial idA, idB, idC;
    private AethelgardTrustManager trustA, trustB, trustC;
    private LockFreeTelemetrySensor sensorB;
    private DefaultDecisionLoop loopB;
    private ConsensusRegistry registryB, registryC;
    private GossipEngine gossipB, gossipC;
    private AgentNodeHandler handlerC;

    private TransportServer serverB, serverC;

    private String attackerKeyId() {
        return AethelgardTrustManager.keyId(idA.publicKey());
    }

    @BeforeEach
    void setUp() {
        idA = CryptoMaterialGenerator.generate("node-A");
        idB = CryptoMaterialGenerator.generate("node-B");
        idC = CryptoMaterialGenerator.generate("node-C");
        trustA = new AethelgardTrustManager();
        trustB = new AethelgardTrustManager();
        trustC = new AethelgardTrustManager();

        // Mutual admission across the swarm (3 nodes × both directions).
        trustA.trust(idB.publicKey());
        trustA.trust(idC.publicKey());
        trustB.trust(idA.publicKey());
        trustB.trust(idC.publicKey());
        trustC.trust(idA.publicKey());
        trustC.trust(idB.publicKey());

        // ── Node B: the victim. Telemetry → decision loop → gossip. ─────────
        sensorB = new LockFreeTelemetrySensor(SENSOR_WINDOW_MILLIS, 2_000L);
        // Engine first, then registry bound to the engine (two-phase: breaks
        // the construction cycle between severance and judgment).
        gossipB = new GossipEngine(trustB, null);
        registryB = new ConsensusRegistry(trustB, () -> 3, gossipB);
        gossipB.bindRegistry(registryB);

        loopB = new DefaultDecisionLoop(sensorB,
                new DefaultBehaviorScorer(new DefaultBehaviorScorer.Thresholds(
                        50.0f, 10.0f, 40.0f, 2.0, 0.5, 2.0, 3, 30.0, 15.0, 5.0, 2.0, 100.0f)),
                trustB, 250, gossipB::nominate);

        AgentNodeHandler handlerB = new AgentNodeHandler(null, sensorB, trustB, gossipB);
        SslContext tlsB = TlsContextFactory.serverContext(idB, trustB);
        serverB = TransportServer.standalone(AgentConfig.defaults(), tlsB, sensorB, trustB, handlerB).start();

        // ── Node C: the witness. Gossip + registry, no telemetry needed. ────
        gossipC = new GossipEngine(trustC, null);
        registryC = new ConsensusRegistry(trustC, () -> 3, gossipC);
        gossipC.bindRegistry(registryC);

        handlerC = new AgentNodeHandler(null, null, trustC, gossipC);
        SslContext tlsC = TlsContextFactory.serverContext(idC, trustC);
        serverC = TransportServer.standalone(AgentConfig.defaults(), tlsC, null, trustC, handlerC).start();
    }

    @AfterEach
    void tearDown() {
        if (loopB != null) loopB.close();
        for (TransportServer s : new TransportServer[]{serverB, serverC}) {
            if (s != null) s.close();
        }
    }

    private Channel connectTo(TransportServer server, CryptoMaterialGenerator.CryptoMaterial asNode,
                              AethelgardTrustManager trust, AgentNodeHandler handler) {
        TransportClient client = TransportClient.standalone(AgentConfig.defaults(),
                TlsContextFactory.clientContext(asNode, trust), handler);
        Channel ch = client.connect("127.0.0.1", server.boundPort());
        ch.pipeline().get(SslHandler.class).handshakeFuture().awaitUninterruptibly(5_000);
        return ch;
    }

    private Channel connectTo(TransportServer server, CryptoMaterialGenerator.CryptoMaterial asNode,
                              AethelgardTrustManager trust) {
        return connectTo(server, asNode, trust, new AgentNodeHandler());
    }

    private static void awaitFalse(java.util.concurrent.atomic.AtomicBoolean cond, long timeoutMillis)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (cond.get() && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        cond.set(false);
    }

    @Test
    @DisplayName("Swarm consensus: A attacks B → ballot gossips → C countersigns → majority severs & blacklists A")
    void fullSwarmConsensusLifecycle() throws Exception {
        String attacker = attackerKeyId();

        // ── 0. Ballot tamper-evidence sanity (pure, no sockets) ─────────────
        QuarantineBallot genuine = QuarantineBallot.sign("some-target",
                QuarantineBallot.generateSigningKeyPair(), 1);
        assertTrue(genuine.verify());
        byte[] tampered = genuine.encode();
        tampered[tampered.length - 1] ^= 0x01; // flip one signature bit
        assertTrue(QuarantineBallot.decode(tampered).verify() == false,
                "any mutation must fail Ed25519 verification");

        // ── 1. Topology: A→B, A→C, and the B↔C gossip link ──────────────────
        assertTrue(trustB.isTrustedKeyId(attacker) && trustC.isTrustedKeyId(attacker),
                "precondition: A trusted swarm-wide");
        Channel chToB = connectTo(serverB, idA, trustA);
        Channel chToC = connectTo(serverC, idA, trustA);
        // C dials B carrying its REAL handler: gossip ballots arriving on a
        // node's CLIENT-side channel must reach the node's GossipEngine too —
        // swarm membership is per-node, not per-connection-direction.
        Channel chCB = connectTo(serverB, idC, trustC, handlerC);
        assertTrue(chToB.isActive() && chToC.isActive() && chCB.isActive());
        Thread.sleep(200); // handshake events register all channels in the engines

        // ── 2. Node A attacks Node B ────────────────────────────────────────
        for (int i = 0; i < ATTACK_CONNECTIONS; i++) {
            Channel attack = connectTo(serverB, idA, trustA);
            attack.writeAndFlush(Unpooled.wrappedBuffer(
                    new byte[]{(byte) 0xDE, (byte) 0xAD, 0, 0, 0, 8, 1, 1, 2, 3, 4, 5, 6, 7, 8}))
                    .syncUninterruptibly();
            attack.closeFuture().await(2, TimeUnit.SECONDS);
        }
        assertTrue(sensorB.snapshot(attacker).malformedFrames() >= 6,
                "B must observe the attack burst");

        // ── 3. Node B: nominate, sign, judge (1 vote), disseminate ──────────
        loopB.runSingleCycle();
        assertFalse(trustB.isTrustedKeyId(attacker), "B's Layer 3 gate revokes A at nomination");

        // ── 4. Swarm convergence: C verifies → countersigns → majority ──────
        long deadline = System.currentTimeMillis() + 5_000;
        while (!registryC.isCondemned(attacker) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertTrue(registryC.isCondemned(attacker),
                "C must reach absolute majority (2 distinct nominators > 3/2) and condemn A");
        assertTrue(registryC.nominatorCount(attacker) >= 2,
                "B's ballot + C's countersignature");
        assertFalse(trustC.isTrustedKeyId(attacker), "C revokes A at consensus");

        // C's consensus execution must sever A's live channel on C.
        long severDeadline = System.currentTimeMillis() + 3_000;
        while (chToC.isActive() && System.currentTimeMillis() < severDeadline) {
            Thread.sleep(50);
        }
        assertFalse(chToC.isActive(), "C severs A's active channel at consensus");

        // B closes the majority too, off C's relayed countersignature.
        long bDeadline = System.currentTimeMillis() + 5_000;
        while (!registryB.isCondemned(attacker) && System.currentTimeMillis() < bDeadline) {
            Thread.sleep(50);
        }
        assertTrue(registryB.isCondemned(attacker), "B must also reach majority via C's countersignature");

        // ── 5. Network-wide blockade: A's fresh connections die everywhere ──
        TransportClient probe = TransportClient.standalone(AgentConfig.defaults(),
                TlsContextFactory.clientContext(idA, trustA), new AgentNodeHandler());
        Channel retryB = probe.connect("127.0.0.1", serverB.boundPort());
        retryB.pipeline().get(SslHandler.class).handshakeFuture().awaitUninterruptibly(5_000);
        java.util.concurrent.atomic.AtomicBoolean bDead = new java.util.concurrent.atomic.AtomicBoolean(retryB.isActive());
        awaitFalse(bDead, 3_000);
        assertFalse(retryB.isActive(), "A must not re-enter via B (revoked key at the TLS gate)");

        Channel retryC = probe.connect("127.0.0.1", serverC.boundPort());
        java.util.concurrent.atomic.AtomicBoolean cDead = new java.util.concurrent.atomic.AtomicBoolean(retryC.isActive());
        awaitFalse(cDead, 3_000);
        assertFalse(retryC.isActive(), "A must not re-enter via C (revoked key / IP blacklist)");
        probe.close();
    }
}
