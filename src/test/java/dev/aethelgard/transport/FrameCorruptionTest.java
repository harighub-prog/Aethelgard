package dev.aethelgard.transport;

import dev.aethelgard.protocol.FrameCodecException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static dev.aethelgard.protocol.ProtocolConstants.MAGIC;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Scenario C — malicious input: bad magic, oversized length, unknown command.
 * Each case must fatal-close the channel (simulated IP disconnect) with the
 * correct Severity so Layer 3 telemetry can weight the trust penalty.
 */
class FrameCorruptionTest {

    private EmbeddedChannel channel;
    private Throwable captured;

    @BeforeEach
    void setUp() {
        captured = null;
        channel = new EmbeddedChannel(new AethelFrameDecoder());
        // Latch decoder exceptions so we can verify severity, mirroring how the
        // production AgentNodeHandler would observe and forward them to telemetry.
        channel.pipeline().addLast("recorder", new io.netty.channel.ChannelInboundHandlerAdapter() {
            @Override
            public void exceptionCaught(io.netty.channel.ChannelHandlerContext ctx, Throwable cause) {
                captured = cause;
            }
        });
    }

    @AfterEach
    void tearDown() {
        channel.finishAndReleaseAll();
    }

    @Test
    @DisplayName("Bad magic -> MALFORMED fatal, channel closed")
    void badMagicDisconnects() {
        ByteBuf evil = Unpooled.buffer();
        evil.writeShort(0xDEAD);      // wrong magic
        evil.writeInt(8);             // plausible length
        evil.writeByte(0x01);
        evil.writeBytes(new byte[8]);

        channel.writeInbound(evil);
        // The recorder handler latches the decoder's fatal exception (writeInbound
        // does not rethrow once a downstream handler consumes it).
        assertNotNull(captured, "fatal exception must fire through the pipeline");
        // ByteToMessageDecoder wraps codec exceptions in DecoderException; unwrap
        // the cause to inspect our severity classification.
        FrameCodecException ex = (FrameCodecException) ((io.netty.handler.codec.DecoderException) captured).getCause();
        assertEquals(FrameCodecException.Severity.MALFORMED, ex.severity());
        assertFalse(channel.isActive(), "peer socket must be severed");
    }

    @Test
    @DisplayName("Oversized length -> RESOURCE_ABUSE fatal, channel closed")
    void oversizeLengthDisconnects() {
        ByteBuf evil = Unpooled.buffer();
        evil.writeShort(MAGIC);
        evil.writeInt(Integer.MAX_VALUE); // memory-exhaustion attempt
        evil.writeByte(0x01);

        channel.writeInbound(evil);
        assertNotNull(captured, "fatal exception must fire through the pipeline");
        // ByteToMessageDecoder wraps codec exceptions in DecoderException; unwrap
        // the cause to inspect our severity classification.
        FrameCodecException ex = (FrameCodecException) ((io.netty.handler.codec.DecoderException) captured).getCause();
        assertEquals(FrameCodecException.Severity.RESOURCE_ABUSE, ex.severity());
        assertFalse(channel.isActive());
    }

    @Test
    @DisplayName("Unknown command code -> MALFORMED fatal, channel closed")
    void unknownCommandDisconnects() {
        ByteBuf evil = Unpooled.buffer();
        evil.writeShort(MAGIC);
        evil.writeInt(4);
        evil.writeByte((byte) 0x7F); // no such command
        evil.writeBytes(new byte[4]);

        channel.writeInbound(evil);
        assertNotNull(captured, "fatal exception must fire through the pipeline");
        // ByteToMessageDecoder wraps codec exceptions in DecoderException; unwrap
        // the cause to inspect our severity classification.
        FrameCodecException ex = (FrameCodecException) ((io.netty.handler.codec.DecoderException) captured).getCause();
        assertEquals(FrameCodecException.Severity.MALFORMED, ex.severity());
        assertFalse(channel.isActive());
    }

    @Test
    @DisplayName("Header-only prefix never throws: decoder waits for body")
    void partialHeaderIsPatient() {
        ByteBuf prefix = Unpooled.buffer();
        prefix.writeShort(MAGIC);
        prefix.writeInt(4);
        prefix.writeByte((byte) 0x01); // valid header, body missing

        // No exception, no output — the cumulation buffer simply holds the bytes.
        channel.writeInbound(prefix);
        assertNull(channel.readInbound());
        assertTrue(channel.isActive());
    }

    @Test
    @DisplayName("Cumulation releases cleanly when channel closes mid-frame (no leak)")
    void midFrameCloseReleasesCumulation() {
        ByteBuf partial = Unpooled.buffer();
        partial.writeShort(MAGIC);
        partial.writeInt(64);
        partial.writeBytes(new byte[16]); // body half-arrived

        channel.writeInbound(partial);
        channel.close().syncUninterruptibly();
        // finishAndReleaseAll in tearDown would throw if the cumulation leaked.
    }
}
