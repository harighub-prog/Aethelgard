package dev.aethelgard;

import dev.aethelgard.core.AgentConfig;
import dev.aethelgard.crypto.AethelgardTrustManager;
import dev.aethelgard.crypto.CryptoMaterialGenerator;
import dev.aethelgard.crypto.CryptoMaterialGenerator.CryptoMaterial;
import dev.aethelgard.crypto.TlsContextFactory;
import dev.aethelgard.gossip.ConsensusRegistry;
import dev.aethelgard.gossip.GossipEngine;
import dev.aethelgard.kernel.NativeKernelBridge;
import dev.aethelgard.telemetry.DefaultBehaviorScorer;
import dev.aethelgard.telemetry.DefaultDecisionLoop;
import dev.aethelgard.telemetry.LockFreeTelemetrySensor;
import dev.aethelgard.time.DeterministicTimeTrigger;
import dev.aethelgard.time.SwarmEpochManager;
import dev.aethelgard.transport.AgentNodeHandler;
import dev.aethelgard.transport.TransportClient;
import dev.aethelgard.transport.TransportServer;
import io.netty.handler.ssl.SslContext;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Production entry point for a Project Aethelgard agent node.
 *
 * <h3>Startup Sequence</h3>
 * <ol>
 *   <li><b>CLI parse</b>: extract {@code --port} and optional {@code --connect}.</li>
 *   <li><b>Identity generation</b>: {@link CryptoMaterialGenerator} produces a fresh EC
 *       P-256 keypair + self-signed X.509v3 certificate entirely in memory — no
 *       files written, no disk I/O.</li>
 *   <li><b>Trust registry</b>: the node admits its own public key, then bootstraps
 *       a dynamic {@link AethelgardTrustManager} that Layer 3 can mutate at runtime.</li>
 *   <li><b>TLS contexts</b>: {@link TlsContextFactory} builds mTLS-only server and client
 *       {@link SslContext} objects backed by the in-memory identity. TLSv1.3 + AEAD
 *       ciphers only; {@code ClientAuth.REQUIRE} on the server side.</li>
 *   <li><b>Telemetry stack</b>: {@link LockFreeTelemetrySensor} (ring-bucket EWMA sensor)
 *       + {@link DefaultBehaviorScorer} (pure-function scorer) + {@link DefaultDecisionLoop}
 *       (virtual-thread driven Perceive → Decide → Act cycle).</li>
 *   <li><b>Gossip + consensus</b>: {@link GossipEngine} + {@link ConsensusRegistry} wired
 *       with the Layer 6 {@link NativeKernelBridge} for line-rate XDP mitigation.</li>
 *   <li><b>Layer 7 clock</b>: {@link SwarmEpochManager} + {@link DeterministicTimeTrigger}
 *       bind all evaluation cycles to the unified swarm epoch, neutralizing
 *       time-asymmetry attacks.</li>
 *   <li><b>Transport bind</b>: {@link TransportServer} binds the requested port; an
 *       optional {@link TransportClient} dials the bootstrap peer immediately after.</li>
 *   <li><b>Decision loop start</b>: the Perceive → Decide → Act cycle starts its
 *       scheduled virtual-thread executor.</li>
 *   <li><b>Shutdown hook</b>: registered with {@link Runtime#addShutdownHook} to
 *       cleanly drain all Netty event loops, close the kernel bridge, and flush
 *       telemetry on SIGTERM / Ctrl-C.</li>
 * </ol>
 *
 * <h3>CLI Flags</h3>
 * <pre>
 *   --port=&lt;int&gt;           Required. Local TCP port the server binds to.
 *   --connect=&lt;host:port&gt;  Optional. Bootstrap peer to dial on startup.
 *   --node-id=&lt;string&gt;     Optional. Human-readable node identifier (default: random UUID prefix).
 * </pre>
 */
public final class AgentApp {

    /** Telemetry window: 60 s sliding window, 16 ring buckets → 3.75 s per bucket. */
    private static final long TELEMETRY_WINDOW_MILLIS = 60_000L;

    /** Latency spike threshold: frames taking longer than 200 ms round-trip are flagged. */
    private static final long SPIKE_THRESHOLD_MILLIS = 200L;

    /** Decision cycle interval: evaluate all peers every 5 seconds. */
    private static final long DECISION_CYCLE_MILLIS = 5_000L;

    /**
     * Bootstrap connection retry budget: wait up to 10 s for the peer to become
     * reachable (accounts for container startup ordering in docker-compose).
     */
    private static final int CONNECT_RETRY_ATTEMPTS = 10;
    private static final long CONNECT_RETRY_DELAY_MILLIS = 1_000L;

    private AgentApp() {
        // static entry point; no instances
    }

    public static void main(String[] args) throws InterruptedException {
        // ── 1. Parse CLI ──────────────────────────────────────────────────────
        int port = 0;
        String connectTarget = null;
        String nodeId = "node-" + UUID.randomUUID().toString().substring(0, 8);

        for (String arg : args) {
            if (arg.startsWith("--port=")) {
                port = Integer.parseInt(arg.substring("--port=".length()).trim());
            } else if (arg.startsWith("--connect=")) {
                connectTarget = arg.substring("--connect=".length()).trim();
            } else if (arg.startsWith("--node-id=")) {
                nodeId = arg.substring("--node-id=".length()).trim();
            }
        }

        if (port <= 0 || port > 65535) {
            System.err.println("[AgentApp] FATAL: --port=<1-65535> is required.");
            System.err.println("  Usage: aethelgard --port=8001 [--connect=127.0.0.1:8002] [--node-id=my-node]");
            System.exit(1);
        }

        System.out.printf("[AgentApp] Starting node '%s' on port %d%n", nodeId, port);

        // ── 2. Cryptographic identity (fully in-memory, no disk I/O) ─────────
        System.out.printf("[AgentApp] Generating EC P-256 identity for '%s'...%n", nodeId);
        CryptoMaterial identity = CryptoMaterialGenerator.generate(nodeId);
        System.out.printf("[AgentApp] Identity ready. Cert subject: %s%n",
                identity.certificate().getSubjectX500Principal().getName());

        // ── 3. Dynamic trust registry ─────────────────────────────────────────
        AethelgardTrustManager trustManager = new AethelgardTrustManager();
        // Admit our own key so peers can reach us after receiving our cert.
        trustManager.trust(identity.publicKey());

        // ── 4. TLS contexts (mTLS-only, TLSv1.3, AEAD ciphers) ───────────────
        SslContext serverSslCtx = TlsContextFactory.serverContext(identity, trustManager);
        SslContext clientSslCtx = TlsContextFactory.clientContext(identity, trustManager);

        // ── 5. Telemetry stack ────────────────────────────────────────────────
        LockFreeTelemetrySensor sensor = new LockFreeTelemetrySensor(
                TELEMETRY_WINDOW_MILLIS, SPIKE_THRESHOLD_MILLIS);
        DefaultBehaviorScorer scorer = new DefaultBehaviorScorer();

        // ── 6. Layer 6: Kernel bridge (eBPF/XDP, graceful non-Linux fallback) ─
        NativeKernelBridge kernelBridge = new NativeKernelBridge();
        System.out.printf("[AgentApp] NativeKernelBridge: native=%s, path=%s%n",
                kernelBridge.isNativeLinked(), kernelBridge.bpfMapPath());

        // ── 7. Layer 4: Gossip + consensus registry ───────────────────────────
        // Two-phase wiring: gossip ↔ registry have a mutual reference;
        // bind the severance callback after both are constructed.
        ConsensusRegistry consensusRegistry = new ConsensusRegistry(
                trustManager,
                () -> 1,          // cluster size starts at self only; grows as peers join
                null,             // severance bound below after gossipEngine is ready
                kernelBridge
        );
        GossipEngine gossipEngine = new GossipEngine(trustManager, consensusRegistry);
        consensusRegistry.bindSeverance(gossipEngine);

        // ── 8. Layer 7: Swarm clock + deterministic epoch trigger ─────────────
        SwarmEpochManager epochManager = new SwarmEpochManager();
        DeterministicTimeTrigger timeTrigger = new DeterministicTimeTrigger(
                epochManager, DECISION_CYCLE_MILLIS * 1_000_000L);
        System.out.printf("[AgentApp] Swarm epoch manager active. Current epoch: %,d (length: %,d ms)%n",
                timeTrigger.currentEpochNumber(), DECISION_CYCLE_MILLIS);

        // ── 9. Layer 3: Autonomous decision loop (virtual threads) ────────────
        DefaultDecisionLoop decisionLoop = new DefaultDecisionLoop(
                sensor,
                scorer,
                trustManager,
                DECISION_CYCLE_MILLIS,
                targetKeyId -> {
                    // Layer 4 quarantine callback: nominate via gossip engine.
                    System.out.printf("[AgentApp] QUARANTINE_NOMINATE: %s%n", targetKeyId);
                    gossipEngine.nominate(targetKeyId);
                }
        );

        // ── 10. AgentNodeHandler: terminal pipeline handler (all layers wired) ─
        AgentNodeHandler agentHandler = new AgentNodeHandler(
                null,           // no external frame listener in production
                sensor,
                trustManager,
                gossipEngine
        );

        // ── 11. AgentConfig + TransportServer ─────────────────────────────────
        AgentConfig serverConfig = new AgentConfig("0.0.0.0", port, 5_000, 500);
        TransportServer server = TransportServer.standalone(
                serverConfig, serverSslCtx, sensor, trustManager, agentHandler);
        server.start();
        System.out.printf("[AgentApp] Listening on 0.0.0.0:%d%n", server.boundPort());

        // ── 12. Optional bootstrap peer dial (with retry for container ordering) ─
        TransportClient client = null;
        if (connectTarget != null && !connectTarget.isBlank()) {
            client = dialWithRetry(connectTarget, serverConfig, clientSslCtx,
                    agentHandler, trustManager, nodeId);
        }
        final TransportClient finalClient = client;

        // ── 13. Start the Perceive → Decide → Act cycle ───────────────────────
        decisionLoop.start();
        System.out.printf("[AgentApp] Decision loop started (cycle=%,d ms).%n", DECISION_CYCLE_MILLIS);
        System.out.printf("[AgentApp] Node '%s' is fully operational.%n", nodeId);

        // ── 14. Shutdown hook ─────────────────────────────────────────────────
        // Capture mutable CLI variable into a final for lambda use.
        final String capturedNodeId = nodeId;
        CountDownLatch shutdownLatch = new CountDownLatch(1);

        Runtime.getRuntime().addShutdownHook(Thread.ofVirtual()
                .name("aethelgard-shutdown")
                .unstarted(() -> {
                    System.out.printf("[AgentApp] Shutdown signal received. Draining node '%s'...%n", capturedNodeId);

                    // Stop the decision loop first: no new scoring while sockets drain.
                    try {
                        decisionLoop.close();
                        System.out.println("[AgentApp] Decision loop stopped.");
                    } catch (Exception e) {
                        System.err.println("[AgentApp] Error stopping decision loop: " + e.getMessage());
                    }

                    // Close outbound connection
                    if (finalClient != null) {
                        try {
                            finalClient.close();
                            System.out.println("[AgentApp] Client transport closed.");
                        } catch (Exception e) {
                            System.err.println("[AgentApp] Error closing client: " + e.getMessage());
                        }
                    }

                    // Close server (binds socket → graceful NIO group drain)
                    try {
                        server.close();
                        System.out.println("[AgentApp] Server transport closed.");
                    } catch (Exception e) {
                        System.err.println("[AgentApp] Error closing server: " + e.getMessage());
                    }

                    // Release Layer 6 kernel resources (closes BPF map fd if native)
                    try {
                        kernelBridge.close();
                        System.out.println("[AgentApp] Kernel bridge closed.");
                    } catch (Exception e) {
                        System.err.println("[AgentApp] Error closing kernel bridge: " + e.getMessage());
                    }

                    System.out.printf("[AgentApp] Node '%s' cleanly shut down. Goodbye.%n", capturedNodeId);
                    shutdownLatch.countDown();
                }));

        // Block the main thread; the JVM exits when the shutdown hook calls countDown.
        shutdownLatch.await();
    }

    /**
     * Attempts to dial a bootstrap peer with exponential retry to handle
     * container startup ordering (node-b may start before node-a is ready).
     *
     * @param target     "{@code host:port}" string from {@code --connect=}.
     * @param baseConfig base AgentConfig for timeout parameters.
     * @param sslCtx     client-side TLS context (mTLS).
     * @param handler    shared AgentNodeHandler.
     * @param trust      trust manager — the peer's cert is admitted on first connection.
     * @param selfNodeId this node's ID for logging.
     * @return the connected TransportClient, or {@code null} if all retries exhausted.
     */
    private static TransportClient dialWithRetry(
            String target,
            AgentConfig baseConfig,
            SslContext sslCtx,
            AgentNodeHandler handler,
            AethelgardTrustManager trust,
            String selfNodeId) throws InterruptedException {

        String[] parts = target.split(":", 2);
        if (parts.length != 2) {
            System.err.printf("[AgentApp] WARNING: invalid --connect target '%s' (expected host:port). Skipping.%n", target);
            return null;
        }
        String host = parts[0];
        int peerPort;
        try {
            peerPort = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            System.err.printf("[AgentApp] WARNING: invalid port in --connect='%s'. Skipping.%n", target);
            return null;
        }

        // Client config: bind to any local address (port 0 = OS-assigned ephemeral).
        AgentConfig clientConfig = new AgentConfig("0.0.0.0", 0,
                baseConfig.connectTimeoutMillis(), baseConfig.shutdownQuietPeriodMillis());

        for (int attempt = 1; attempt <= CONNECT_RETRY_ATTEMPTS; attempt++) {
            try {
                System.out.printf("[AgentApp] Connecting to bootstrap peer %s:%d (attempt %d/%d)...%n",
                        host, peerPort, attempt, CONNECT_RETRY_ATTEMPTS);
                // Use the standalone factory for self-owned lifecycle.
                TransportClient standalone = TransportClient.standalone(clientConfig, sslCtx, handler);
                standalone.connect(host, peerPort);
                System.out.printf("[AgentApp] Connected to bootstrap peer %s:%d.%n", host, peerPort);
                return standalone;
            } catch (Exception e) {
                System.out.printf("[AgentApp] Connection attempt %d failed: %s. Retrying in %,d ms...%n",
                        attempt, e.getMessage(), CONNECT_RETRY_DELAY_MILLIS);
                if (attempt < CONNECT_RETRY_ATTEMPTS) {
                    TimeUnit.MILLISECONDS.sleep(CONNECT_RETRY_DELAY_MILLIS);
                }
            }
        }
        System.err.printf("[AgentApp] WARNING: Could not reach bootstrap peer %s:%d after %d attempts. "
                + "Node will operate in standalone mode until a peer connects inbound.%n",
                host, peerPort, CONNECT_RETRY_ATTEMPTS);
        return null;
    }
}
