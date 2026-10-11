package dev.aethelgard.transport;

import dev.aethelgard.crypto.CryptoAgilityEngine;
import dev.aethelgard.crypto.CryptoAgilityEngine.AlgorithmSuite;
import dev.aethelgard.crypto.CryptoAgilityEngine.HybridPublicKey;
import dev.aethelgard.protocol.CommandType;
import dev.aethelgard.protocol.FrameCodecException;
import dev.aethelgard.protocol.ProtocolConstants;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.ByteToMessageCodec;

import java.util.List;

/**
 * Layer 5: Zero-Copy Netty Framing Codec for Hybrid Classical + PQC Frames.
 *
 * Designed to accommodate the expanded wire footprint of post-quantum cryptography:
 * - Public keys (up to ~2.6 KiB for ML-DSA-87)
 * - Signatures (up to ~4.6 KiB for ML-DSA-87 / Dilithium5)
 *
 * Enforces zero-heap memory policy:
 * 1. Outbound serialization stitches header, classical signature, PQC signature,
 *    and application payload dynamically using Netty's {@link CompositeByteBuf},
 *    bypassing all intermediate byte array allocations.
 * 2. Inbound parsing extracts direct retained slices and performs zero-copy verification
 *    against the {@link CryptoAgilityEngine}.
 * 3. Immediate channel teardown: if either the classical or post-quantum signature fails
 *    verification, the channel is closed immediately and a {@link FrameCodecException}
 *    is raised to prevent hostile frames from traversing further into the node stack.
 */
public class HybridFrameCodec extends ByteToMessageCodec<HybridFrame> {

    @FunctionalInterface
    public interface PublicKeyResolver {
        HybridPublicKey resolve(ChannelHandlerContext ctx, HybridFrame frame);
    }

    private final CryptoAgilityEngine cryptoEngine;
    private final PublicKeyResolver keyResolver;

    public HybridFrameCodec() {
        this(null, (PublicKeyResolver) null);
    }

    public HybridFrameCodec(CryptoAgilityEngine cryptoEngine, HybridPublicKey expectedPublicKey) {
        this(cryptoEngine, (ctx, frame) -> expectedPublicKey);
    }

    public HybridFrameCodec(CryptoAgilityEngine cryptoEngine, PublicKeyResolver keyResolver) {
        this.cryptoEngine = cryptoEngine;
        this.keyResolver = keyResolver;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof HybridFrame frame) {
            try {
                int classicalSigLen = frame.classicalSignature().readableBytes();
                int pqcSigLen = frame.pqcSignature().readableBytes();
                int payloadLen = frame.payload().readableBytes();

                int totalBodyLength = 1 + 2 + classicalSigLen + 4 + pqcSigLen + payloadLen;
                if (totalBodyLength > ProtocolConstants.MAX_FRAME_SIZE) {
                    throw new FrameCodecException(
                            FrameCodecException.Severity.RESOURCE_ABUSE,
                            "Hybrid frame length " + totalBodyLength + " exceeds MAX_FRAME_SIZE " + ProtocolConstants.MAX_FRAME_SIZE);
                }

                // 1. Fixed Header: [Magic: 2B][BodyLen: 4B][Command: 1B][Suite: 1B][ClassicalSigLen: 2B]
                ByteBuf headerBuf = ctx.alloc().directBuffer(ProtocolConstants.HEADER_SIZE + 1 + 2);
                headerBuf.writeShort(ProtocolConstants.MAGIC);
                headerBuf.writeInt(totalBodyLength);
                headerBuf.writeByte(frame.command().code());
                headerBuf.writeByte(frame.suite().code());
                headerBuf.writeShort(classicalSigLen);

                // 2. Length buffer for PQC signature: [PqcSigLen: 4B]
                ByteBuf pqcLenBuf = ctx.alloc().directBuffer(4);
                pqcLenBuf.writeInt(pqcSigLen);

                // 3. Zero-Copy Composite Stitching: dynamically binds slices without heap arrays
                CompositeByteBuf composite = ctx.alloc().compositeDirectBuffer(5);
                composite.addComponent(true, headerBuf);
                composite.addComponent(true, frame.classicalSignature().retainedSlice());
                composite.addComponent(true, pqcLenBuf);
                composite.addComponent(true, frame.pqcSignature().retainedSlice());
                composite.addComponent(true, frame.payload().retainedSlice());

                ctx.write(composite, promise);
            } finally {
                // Outbound MessageToByteEncoder contract: release input frame
                frame.release();
            }
        } else {
            super.write(ctx, msg, promise);
        }
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, HybridFrame msg, ByteBuf out) {
        // Fallback if encode is called directly: stitch via CompositeByteBuf
        int classicalSigLen = msg.classicalSignature().readableBytes();
        int pqcSigLen = msg.pqcSignature().readableBytes();
        int payloadLen = msg.payload().readableBytes();
        int totalBodyLength = 1 + 2 + classicalSigLen + 4 + pqcSigLen + payloadLen;

        ByteBuf headerBuf = ctx.alloc().directBuffer(ProtocolConstants.HEADER_SIZE + 1 + 2);
        headerBuf.writeShort(ProtocolConstants.MAGIC);
        headerBuf.writeInt(totalBodyLength);
        headerBuf.writeByte(msg.command().code());
        headerBuf.writeByte(msg.suite().code());
        headerBuf.writeShort(classicalSigLen);

        ByteBuf pqcLenBuf = ctx.alloc().directBuffer(4);
        pqcLenBuf.writeInt(pqcSigLen);

        CompositeByteBuf composite = ctx.alloc().compositeDirectBuffer(5);
        composite.addComponent(true, headerBuf);
        composite.addComponent(true, msg.classicalSignature().retainedSlice());
        composite.addComponent(true, pqcLenBuf);
        composite.addComponent(true, msg.pqcSignature().retainedSlice());
        composite.addComponent(true, msg.payload().retainedSlice());

        try {
            out.writeBytes(composite);
        } finally {
            composite.release();
        }
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (in.readableBytes() < ProtocolConstants.HEADER_SIZE) {
            return;
        }

        in.markReaderIndex();
        short magic = in.readShort();
        if (magic != ProtocolConstants.MAGIC) {
            throw new FrameCodecException(
                    FrameCodecException.Severity.MALFORMED,
                    "Bad magic 0x%04X from %s - not an Aethelgard peer"
                            .formatted(magic, ctx.channel().remoteAddress()));
        }

        int totalBodyLength = in.readInt();
        if (totalBodyLength > ProtocolConstants.MAX_FRAME_SIZE) {
            throw new FrameCodecException(
                    FrameCodecException.Severity.RESOURCE_ABUSE,
                    "Advertised hybrid frame length %,d exceeds MAX_FRAME_SIZE %,d from %s"
                            .formatted(totalBodyLength, ProtocolConstants.MAX_FRAME_SIZE, ctx.channel().remoteAddress()));
        }

        byte cmdCode = in.readByte();
        CommandType command = CommandType.fromCode(cmdCode);
        if (command == null) {
            throw new FrameCodecException(
                    FrameCodecException.Severity.MALFORMED,
                    "Unknown command code 0x%02X from %s".formatted(cmdCode, ctx.channel().remoteAddress()));
        }

        // Header verified; check if complete body has arrived
        in.resetReaderIndex();
        if (in.readableBytes() < ProtocolConstants.HEADER_SIZE + totalBodyLength) {
            return; // Wait for complete TCP frame cumulation
        }

        // Consume fixed header
        in.skipBytes(ProtocolConstants.HEADER_SIZE);

        byte suiteCode = in.readByte();
        AlgorithmSuite suite = AlgorithmSuite.fromCode(suiteCode);

        int classicalSigLen = in.readUnsignedShort();
        ByteBuf classicalSig = in.readRetainedSlice(classicalSigLen);

        int pqcSigLen = in.readInt();
        ByteBuf pqcSig = in.readRetainedSlice(pqcSigLen);

        int payloadLen = totalBodyLength - (1 + 2 + classicalSigLen + 4 + pqcSigLen);
        if (payloadLen < 0) {
            classicalSig.release();
            pqcSig.release();
            throw new FrameCodecException(
                    FrameCodecException.Severity.MALFORMED,
                    "Malformed hybrid frame: negative payload length from " + ctx.channel().remoteAddress());
        }

        ByteBuf payload = in.readRetainedSlice(payloadLen);

        // Verification phase (if CryptoAgilityEngine and keyResolver are wired)
        if (cryptoEngine != null && keyResolver != null) {
            HybridFrame tempFrame = new HybridFrame(command, suite, classicalSig, pqcSig, payload);
            HybridPublicKey pubKey = keyResolver.resolve(ctx, tempFrame);
            if (pubKey != null) {
                boolean verified = cryptoEngine.verify(payload, classicalSig, pqcSig, pubKey);
                if (!verified) {
                    // Critical Zero-Trust Reaction: Release buffers and tear down channel immediately!
                    classicalSig.release();
                    pqcSig.release();
                    payload.release();
                    ctx.close();
                    throw new FrameCodecException(
                            FrameCodecException.Severity.RESOURCE_ABUSE,
                            "Post-quantum hybrid signature verification failed for peer " + ctx.channel().remoteAddress());
                }
            }
        }

        out.add(new HybridFrame(command, suite, classicalSig, pqcSig, payload));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.fireExceptionCaught(cause);
        ctx.close();
    }
}
