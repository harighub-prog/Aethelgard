package dev.aethelgard.transport;

import dev.aethelgard.protocol.ProtocolConstants;
import dev.aethelgard.telemetry.PeerTelemetrySensor;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

/**
 * Outbound encoder: Frame -> wire bytes.
 *
 * Allocates one pooled direct buffer sized header + payload up front (single
 * allocation, no resize-realloc churn) and writes the fixed header followed by
 * a zero-copy transfer of the payload buffer. The outbound ByteBuf assumes
 * ownership of the payload's bytes; the MessageToByteEncoder contract releases
 * the original Frame (and therefore its payload) after encoding completes,
 * keeping reference counts balanced on both the happy path and write failures.
 */
public class AethelFrameEncoder extends MessageToByteEncoder<Frame> {

    private final PeerTelemetrySensor sensor; // nullable in codec-only tests

    public AethelFrameEncoder() {
        this(null);
    }

    public AethelFrameEncoder(PeerTelemetrySensor sensor) {
        this.sensor = sensor;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Frame msg, ByteBuf out) {
        if (sensor != null) {
            // Outbound telemetry hook. The encoder is the single point EVERY
            // outbound frame traverses exactly once — including frames written
            // by handlers earlier in the pipeline (e.g. AgentNodeHandler's
            // echo, whose ctx.write() skips its own outbound methods).
            sensor.recordFrameSent(PeerIdentity.keyIdOf(ctx));
        }
        int payloadLen = msg.payload().readableBytes();
        out.writeShort(ProtocolConstants.MAGIC);
        out.writeInt(payloadLen);
        out.writeByte(msg.command().code());
        out.writeBytes(msg.payload(), msg.payload().readerIndex(), payloadLen);
    }

    @Override
    protected ByteBuf allocateBuffer(ChannelHandlerContext ctx, Frame msg, boolean preferDirect) throws Exception {
        int initialCapacity = ProtocolConstants.HEADER_SIZE + msg.payload().readableBytes();
        return super.allocateBuffer(ctx, msg, preferDirect).capacity(initialCapacity);
    }
}
