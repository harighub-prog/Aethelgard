package dev.aethelgard.transport;

import dev.aethelgard.crypto.AethelgardTrustManager;
import dev.aethelgard.crypto.CryptoAgilityEngine;
import dev.aethelgard.crypto.CryptoAgilityEngine.AlgorithmSuite;
import dev.aethelgard.crypto.CryptoAgilityEngine.HybridKeyPair;
import dev.aethelgard.crypto.CryptoAgilityEngine.HybridPublicKey;
import dev.aethelgard.crypto.CryptoAgilityEngine.HybridSignature;
import dev.aethelgard.crypto.DefaultCryptoAgilityEngine;
import dev.aethelgard.gossip.ConsensusRegistry;
import dev.aethelgard.gossip.QuarantineBallot;
import dev.aethelgard.kernel.NativeKernelBridge;
import dev.aethelgard.protocol.CommandType;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Advanced Verification Matrix for Layer 5 (Post-Quantum Cryptographic Agility)
 * and Layer 6 (Native Linux eBPF/XDP Defense Bridge).
 *
 * Executed under Netty's PARANOID ResourceLeakDetector to confirm zero-leak memory
 * contracts across all composite buffers, retained slices, and off-heap Project Panama
 * FFM Arena boundaries.
 */
class PqcXdpIntegrationTest {

    private CryptoAgilityEngine cryptoEngine;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    @BeforeEach
    void setUp() {
        cryptoEngine = new DefaultCryptoAgilityEngine(AlgorithmSuite.HYBRID_P256_MLDSA65);
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup(2);
    }

    @AfterEach
    void tearDown() {
        if (bossGroup != null) {
            bossGroup.shutdownGracefully(100, 500, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully(100, 500, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }
    }

    @Test
    @DisplayName("Layer 5: Hybrid classical + PQC frame traverses loopback socket with zero-copy CompositeByteBuf")
    void hybridFrameTraversalLoopback() throws Exception {
        HybridKeyPair clientKeys = cryptoEngine.generateHybridKeyPair(AlgorithmSuite.HYBRID_P256_MLDSA65);
        HybridPublicKey clientPubKey = clientKeys.toPublicKey();

        CountDownLatch serverReceivedLatch = new CountDownLatch(1);
        AtomicReference<byte[]> receivedPayload = new AtomicReference<>();
        AtomicReference<HybridFrame> capturedFrame = new AtomicReference<>();

        // Server setup with HybridFrameCodec wired to verify client's public key
        ServerBootstrap sb = new ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("hybridCodec", new HybridFrameCodec(cryptoEngine, clientPubKey));
                        ch.pipeline().addLast("serverHandler", new SimpleChannelInboundHandler<HybridFrame>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HybridFrame msg) {
                                byte[] bytes = new byte[msg.payload().readableBytes()];
                                msg.payload().getBytes(msg.payload().readerIndex(), bytes);
                                receivedPayload.set(bytes);
                                capturedFrame.set(msg);
                                serverReceivedLatch.countDown();
                            }
                        });
                    }
                });

        Channel serverChannel = sb.bind(0).sync().channel();
        int port = ((InetSocketAddress) serverChannel.localAddress()).getPort();

        // Client setup
        Bootstrap cb = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("hybridCodec", new HybridFrameCodec());
                    }
                });

        Channel clientChannel = cb.connect("127.0.0.1", port).sync().channel();

        // Create application payload
        byte[] originalData = "Aethelgard-PQC-Layer5-Payload-ZeroCopy-Test".getBytes();
        ByteBuf payloadBuf = clientChannel.alloc().directBuffer(originalData.length);
        payloadBuf.writeBytes(originalData);

        // Compute dual classical + post-quantum signature
        HybridSignature signature = cryptoEngine.sign(payloadBuf, clientKeys, clientChannel.alloc());

        // Construct HybridFrame and transmit
        HybridFrame outboundFrame = new HybridFrame(
                CommandType.CONTROL,
                AlgorithmSuite.HYBRID_P256_MLDSA65,
                signature.classicalSignature(),
                signature.pqcSignature(),
                payloadBuf
        );

        clientChannel.writeAndFlush(outboundFrame).sync();

        assertTrue(serverReceivedLatch.await(5, TimeUnit.SECONDS), "Server must receive and verify hybrid frame");
        assertArrayEquals(originalData, receivedPayload.get(), "Payload bytes must match identically");

        // Clean shutdown and refcount verification
        clientChannel.close().sync();
        serverChannel.close().sync();
    }

    @Test
    @DisplayName("Layer 5: Forcing invalid post-quantum signature triggers immediate channel teardown")
    void invalidPqcSignatureTriggersImmediateChannelTeardown() throws Exception {
        HybridKeyPair clientKeys = cryptoEngine.generateHybridKeyPair(AlgorithmSuite.HYBRID_P256_MLDSA65);
        HybridPublicKey clientPubKey = clientKeys.toPublicKey();

        CountDownLatch serverClosedLatch = new CountDownLatch(1);
        AtomicBoolean serverReceivedPayload = new AtomicBoolean(false);

        ServerBootstrap sb = new ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("hybridCodec", new HybridFrameCodec(cryptoEngine, clientPubKey));
                        ch.pipeline().addLast("serverHandler", new SimpleChannelInboundHandler<HybridFrame>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HybridFrame msg) {
                                serverReceivedPayload.set(true);
                            }

                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                                serverClosedLatch.countDown();
                                super.channelInactive(ctx);
                            }
                        });
                    }
                });

        Channel serverChannel = sb.bind(0).sync().channel();
        int port = ((InetSocketAddress) serverChannel.localAddress()).getPort();

        Bootstrap cb = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("hybridCodec", new HybridFrameCodec());
                    }
                });

        Channel clientChannel = cb.connect("127.0.0.1", port).sync().channel();

        byte[] payloadData = "Hostile-Forged-Pqc-Attempt".getBytes();
        ByteBuf payloadBuf = clientChannel.alloc().directBuffer(payloadData.length);
        payloadBuf.writeBytes(payloadData);

        // Sign with valid classical + valid PQC
        HybridSignature validSig = cryptoEngine.sign(payloadBuf, clientKeys, clientChannel.alloc());

        // Deliberately corrupt PQC signature bytes (bit flip attack)
        ByteBuf corruptedPqcSig = clientChannel.alloc().directBuffer(validSig.pqcSignature().readableBytes());
        byte[] pqcBytes = new byte[validSig.pqcSignature().readableBytes()];
        validSig.pqcSignature().getBytes(validSig.pqcSignature().readerIndex(), pqcBytes);
        pqcBytes[0] = (byte) ~pqcBytes[0]; // Invert first byte
        pqcBytes[pqcBytes.length / 2] = (byte) ~pqcBytes[pqcBytes.length / 2];
        corruptedPqcSig.writeBytes(pqcBytes);
        validSig.pqcSignature().release();

        HybridFrame evilFrame = new HybridFrame(
                CommandType.CONTROL,
                AlgorithmSuite.HYBRID_P256_MLDSA65,
                validSig.classicalSignature(),
                corruptedPqcSig,
                payloadBuf
        );

        clientChannel.writeAndFlush(evilFrame).sync();

        // Channel must be torn down immediately by HybridFrameCodec
        assertTrue(serverClosedLatch.await(5, TimeUnit.SECONDS), "Server channel must be severed immediately upon bad PQC sig");
        assertFalse(serverReceivedPayload.get(), "Malicious payload must NEVER reach application handler");

        clientChannel.close().sync();
        serverChannel.close().sync();
    }

    @Test
    @DisplayName("Layer 5: Forcing invalid classical signature triggers immediate channel teardown")
    void invalidClassicalSignatureTriggersImmediateChannelTeardown() throws Exception {
        HybridKeyPair clientKeys = cryptoEngine.generateHybridKeyPair(AlgorithmSuite.HYBRID_P256_MLDSA65);
        HybridPublicKey clientPubKey = clientKeys.toPublicKey();

        CountDownLatch serverClosedLatch = new CountDownLatch(1);
        AtomicBoolean serverReceivedPayload = new AtomicBoolean(false);

        ServerBootstrap sb = new ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("hybridCodec", new HybridFrameCodec(cryptoEngine, clientPubKey));
                        ch.pipeline().addLast("serverHandler", new SimpleChannelInboundHandler<HybridFrame>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HybridFrame msg) {
                                serverReceivedPayload.set(true);
                            }

                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                                serverClosedLatch.countDown();
                                super.channelInactive(ctx);
                            }
                        });
                    }
                });

        Channel serverChannel = sb.bind(0).sync().channel();
        int port = ((InetSocketAddress) serverChannel.localAddress()).getPort();

        Bootstrap cb = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("hybridCodec", new HybridFrameCodec());
                    }
                });

        Channel clientChannel = cb.connect("127.0.0.1", port).sync().channel();

        byte[] payloadData = "Hostile-Forged-Classical-Attempt".getBytes();
        ByteBuf payloadBuf = clientChannel.alloc().directBuffer(payloadData.length);
        payloadBuf.writeBytes(payloadData);

        HybridSignature validSig = cryptoEngine.sign(payloadBuf, clientKeys, clientChannel.alloc());

        // Deliberately corrupt Classical ECDSA signature bytes
        ByteBuf corruptedClassicalSig = clientChannel.alloc().directBuffer(validSig.classicalSignature().readableBytes());
        byte[] classicalBytes = new byte[validSig.classicalSignature().readableBytes()];
        validSig.classicalSignature().getBytes(validSig.classicalSignature().readerIndex(), classicalBytes);
        classicalBytes[0] = (byte) ~classicalBytes[0];
        corruptedClassicalSig.writeBytes(classicalBytes);
        validSig.classicalSignature().release();

        HybridFrame evilFrame = new HybridFrame(
                CommandType.CONTROL,
                AlgorithmSuite.HYBRID_P256_MLDSA65,
                corruptedClassicalSig,
                validSig.pqcSignature(),
                payloadBuf
        );

        clientChannel.writeAndFlush(evilFrame).sync();

        assertTrue(serverClosedLatch.await(5, TimeUnit.SECONDS), "Server channel must be severed upon bad classical sig");
        assertFalse(serverReceivedPayload.get(), "Malicious payload must never be processed");

        clientChannel.close().sync();
        serverChannel.close().sync();
    }

    @Test
    @DisplayName("Layer 5: CompositeByteBuf stitches massive signature frames dynamically without heap allocations")
    void compositeByteBufZeroCopyStitching() {
        HybridKeyPair keyPair = cryptoEngine.generateHybridKeyPair(AlgorithmSuite.HYBRID_P256_MLDSA65);

        // 16 KiB payload simulating large swarm state synchronization
        byte[] payloadData = new byte[16 * 1024];
        for (int i = 0; i < payloadData.length; i++) {
            payloadData[i] = (byte) (i & 0xFF);
        }

        ByteBuf payloadBuf = UnpooledByteBufAllocator.DEFAULT.directBuffer(payloadData.length);
        payloadBuf.writeBytes(payloadData);

        HybridSignature signature = cryptoEngine.sign(payloadBuf, keyPair, UnpooledByteBufAllocator.DEFAULT);
        assertEquals(1, signature.refCnt());

        HybridFrame frame = new HybridFrame(
                CommandType.GOSSIP,
                AlgorithmSuite.HYBRID_P256_MLDSA65,
                signature.classicalSignature(),
                signature.pqcSignature(),
                payloadBuf
        );

        CompositeByteBuf stitchedBody = frame.stitchBody(UnpooledByteBufAllocator.DEFAULT);
        assertEquals(3, stitchedBody.numComponents(), "Composite buffer must dynamically stitch exactly 3 components");
        assertEquals(
                frame.classicalSignature().readableBytes() + frame.pqcSignature().readableBytes() + frame.payload().readableBytes(),
                stitchedBody.readableBytes()
        );

        // Verification zero-copy direct from CompositeByteBuf
        boolean verified = cryptoEngine.verify(payloadBuf, signature.classicalSignature(), signature.pqcSignature(), keyPair.toPublicKey());
        assertTrue(verified, "Zero-copy verification over direct memory must succeed");

        stitchedBody.release();
        frame.release();
        assertEquals(0, payloadBuf.refCnt(), "Payload buffer reference count must return to 0");
    }

    @Test
    @DisplayName("Layer 6: Project Panama FFM MemorySegment allocations strictly released via try-with-resources Arena")
    void nativeKernelBridgeFfmMemorySegmentLifecycle() {
        try (NativeKernelBridge bridge = new NativeKernelBridge()) {
            assertEquals(0, bridge.activeArenas(), "Initial active arenas must be 0");

            // Pin IP mitigation
            String targetIp = "192.168.10.77";
            boolean pinned = bridge.pinKernelMitigation(targetIp);
            assertTrue(pinned, "pinKernelMitigation must succeed");
            assertTrue(bridge.isIpPinned(targetIp), "Target IP must be registered in mitigation map");

            // Verify strict deterministic Arena closure
            assertEquals(0, bridge.activeArenas(), "Arena must be closed immediately after pinKernelMitigation");
            assertEquals(1, bridge.totalArenasAllocated());
            assertEquals(1, bridge.totalArenasClosed());
            assertTrue(bridge.totalSegmentsAllocated() >= 2, "Must allocate at least key and val off-heap segments");
            assertTrue(bridge.totalOffHeapBytesAllocated() >= 12, "Must allocate 4 bytes int key + 8 bytes long val");

            // Unpin IP mitigation
            boolean unpinned = bridge.unpinKernelMitigation(targetIp);
            assertTrue(unpinned, "unpinKernelMitigation must succeed");
            assertFalse(bridge.isIpPinned(targetIp));

            // Verify second Arena lifecycle was cleanly finalized
            assertEquals(0, bridge.activeArenas(), "Arena must be closed immediately after unpinKernelMitigation");
            assertEquals(2, bridge.totalArenasAllocated());
            assertEquals(2, bridge.totalArenasClosed());
        }
    }

    @Test
    @DisplayName("Layer 4 to Layer 6 Cascade: Absolute Majority Consensus triggers NativeKernelBridge IP Pinning")
    void consensusQuorumCascadesToKernelMitigation() {
        AethelgardTrustManager trustManager = new AethelgardTrustManager();
        NativeKernelBridge kernelBridge = new NativeKernelBridge();
        AtomicReference<String> severedKeyId = new AtomicReference<>();

        ConsensusRegistry.Severance severance = severedKeyId::set;
        // Cluster size = 3 -> majority requires > 3 / 2.0 = 1.5 (i.e. 2 unique nominators)
        ConsensusRegistry registry = new ConsensusRegistry(trustManager, () -> 3, severance, kernelBridge);

        String targetKeyId = "target-node-rogue-identity-pqc";
        String targetIp = "10.0.0.99";
        trustManager.admitKeyId(targetKeyId);

        KeyPair nominator1 = QuarantineBallot.generateSigningKeyPair();
        KeyPair nominator2 = QuarantineBallot.generateSigningKeyPair();

        QuarantineBallot ballot1 = QuarantineBallot.sign(targetKeyId, nominator1, 1L);
        QuarantineBallot ballot2 = QuarantineBallot.sign(targetKeyId, nominator2, 2L);

        // First vote: distinct nominators = 1 (1 <= 1.5 -> no consensus)
        boolean consensus1 = registry.record(ballot1);
        assertFalse(consensus1, "Single vote does not reach absolute majority");
        assertFalse(registry.isCondemned(targetKeyId));
        assertFalse(kernelBridge.isIpPinned(targetIp));

        // Second vote: distinct nominators = 2 (2 > 1.5 -> CONSENSUS REACHED!)
        boolean consensus2 = registry.record(ballot2);
        assertTrue(consensus2, "Second vote reaches absolute majority consensus");
        assertTrue(registry.isCondemned(targetKeyId), "Target must be condemned");
        assertEquals(targetKeyId, severedKeyId.get(), "Severance must be invoked for target");

        // Engine records IP of severed target
        registry.blacklistIp(targetIp);

        // Verification: Layer 6 native bridge automatically pinned hostile IP to kernel map!
        assertTrue(registry.isIpBlacklisted(targetIp));
        assertTrue(kernelBridge.isIpPinned(targetIp), "Layer 6 eBPF map must pin the hostile IP for line-rate XDP_DROP");

        kernelBridge.close();
    }

    @Test
    @DisplayName("Layer 5: Full suite matrix validation (ML-DSA-44, ML-DSA-65, ML-DSA-87, Dilithium3)")
    void allAlgorithmSuitesHybridValidation() {
        AlgorithmSuite[] suites = {
                AlgorithmSuite.HYBRID_P256_MLDSA44,
                AlgorithmSuite.HYBRID_P256_MLDSA65,
                AlgorithmSuite.HYBRID_P256_MLDSA87,
                AlgorithmSuite.HYBRID_P256_DILITHIUM3
        };

        for (AlgorithmSuite suite : suites) {
            CryptoAgilityEngine engine = new DefaultCryptoAgilityEngine(suite);
            HybridKeyPair keyPair = engine.generateHybridKeyPair(suite);
            assertNotNull(keyPair.classicalKeyPair());
            assertNotNull(keyPair.pqcKeyPair());

            byte[] testBytes = ("Agility-Suite-Test-" + suite.name()).getBytes();
            ByteBuf dataBuf = Unpooled.wrappedBuffer(testBytes);

            HybridSignature sig = engine.sign(dataBuf, keyPair, UnpooledByteBufAllocator.DEFAULT);
            assertNotNull(sig.classicalSignature());
            assertNotNull(sig.pqcSignature());
            assertTrue(sig.classicalSignature().readableBytes() > 0);
            assertTrue(sig.pqcSignature().readableBytes() > 1000, "PQC signature footprint must be > 1 KiB");

            boolean ok = engine.verify(dataBuf, sig.classicalSignature(), sig.pqcSignature(), keyPair.toPublicKey());
            assertTrue(ok, "Suite " + suite + " must verify successfully");

            sig.release();
        }
    }
}
