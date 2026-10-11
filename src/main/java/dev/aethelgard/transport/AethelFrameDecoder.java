package dev.aethelgard.transport;

import dev.aethelgard.protocol.CommandType;
import dev.aethelgard.protocol.FrameCodecException;
import dev.aethelgard.telemetry.PeerTelemetrySensor;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.ByteToMessageDecoder;
import java.util.List;

import static dev.aethelgard.protocol.ProtocolConstants.*;

/**
 * Streaming frame parser for the Aethelgard wire protocol.
 *
 * Extends {@link ByteToMessageDecoder}, which maintains a per-channel cumulation
 * buffer: fragmented TCP segments are merged there until a full frame is
 * available, so partial frames require no manual reassembly logic.
 *
 * Memory contract: the payload is extracted with {@code readRetainedSlice()},
 * which (a) transfers a slice view of the cumulation buffer with its own
 * reference count and (b) advances the cumulation reader index. When the
 * cumulation is fully consumed, Netty discards it — the retained slice keeps
 * only the backing region alive until the Frame is released downstream. The
 * data path performs zero heap copies.
 *
 * Failure policy: bad magic or an oversized length is a fatal
 * {@link FrameCodecException}; Netty propagates it through the pipeline,
 * fires exceptionCaught downstream (Layer 3 telemetry hook) and closes the
 * channel, severing the TCP connection to the offending peer.
 */
public class AethelFrameDecoder extends ByteToMessageDecoder {

    private final PeerTelemetrySensor sensor; // nullable: null in codec-only tests

    public AethelFrameDecoder() {
        this(null);
    }

    public AethelFrameDecoder(PeerTelemetrySensor sensor) {
        this.sensor = sensor;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        // Not enough bytes for a full header yet — wait for more segments.
        if (in.readableBytes() < HEADER_SIZE) {
            return;
        }

        // Peek magic WITHOUT consuming: markReaderIndex/resetReaderIndex lets us
        // validate before committing to a parse.
        in.markReaderIndex();
        short magic = in.readShort();
        if (magic != MAGIC) {
            throw new FrameCodecException(
                    FrameCodecException.Severity.MALFORMED,
                    "Bad magic 0x%04X from %s — not an Aethelgard peer"
                            .formatted(magic, ctx.channel().remoteAddress()));
        }

        int length = in.readInt();
        if (length > MAX_FRAME_SIZE) {
            throw new FrameCodecException(
                    FrameCodecException.Severity.RESOURCE_ABUSE,
                    "Advertised frame length %,d exceeds MAX_FRAME_SIZE %,d from %s"
                            .formatted(length, MAX_FRAME_SIZE, ctx.channel().remoteAddress()));
        }

        byte code = in.readByte();
        CommandType command = CommandType.fromCode(code);
        if (command == null) {
            throw new FrameCodecException(
                    FrameCodecException.Severity.MALFORMED,
                    "Unknown command code 0x%02X from %s".formatted(code, ctx.channel().remoteAddress()));
        }

        // Header validated; restore reader index so the header bytes are consumed
        // only when the complete frame body has actually arrived.
        in.resetReaderIndex();

        if (in.readableBytes() < HEADER_SIZE + length) {
            // Frame body still fragmented across TCP segments — cumulation
            // buffer keeps the header until the rest arrives.
            return;
        }

        // Consume header, then hand off a retained slice as the payload:
        // zero-copy, ownership transferred to the Frame.
        in.skipBytes(HEADER_SIZE);
        ByteBuf payload = in.readRetainedSlice(length);
        out.add(new Frame(command, payload));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        // Layer 3 telemetry ingestion: classify the violation. Non-blocking by
        // contract (LongAdder/bucket increments) — safe on this event loop.
        if (sensor != null && cause instanceof DecoderException de
                && de.getCause() instanceof FrameCodecException fce) {
            String peerKey = PeerIdentity.keyIdOf(ctx);
            if (fce.severity() == FrameCodecException.Severity.RESOURCE_ABUSE) {
                sensor.recordResourceAbuse(peerKey);
            } else {
                sensor.recordMalformedFrame(peerKey);
            }
        }
        // Propagate so downstream handlers (AgentNodeHandler) observe the
        // violation, then drop the socket. ReferenceCounted messages already
        // released by ByteToMessageDecoder need no manual cleanup here.
        ctx.fireExceptionCaught(cause);
        ctx.close();
    }
}
