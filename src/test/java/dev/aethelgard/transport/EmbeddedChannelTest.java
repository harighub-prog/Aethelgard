package dev.aethelgard.transport;

import dev.aethelgard.protocol.CommandType;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Scenario A (Happy Path) and Scenario B (Fragmentation) for the frame codecs,
 * driven through Netty's EmbeddedChannel — full pipeline semantics with zero
 * real sockets.
 *
 * Leak prevention in tests: every ByteBuf handed into an EmbeddedChannel is
 * tracked and released in @AfterEach unless ownership demonstrably transferred
 * (retCnt assertions prove the transfer). EmbeddedChannel's finishAndReleaseAll()
 * drains and releases anything still stuck in the outbound pipeline, so a
 * forgotten buffer fails via the refCnt assertions rather than leaking silently.
 */
class EmbeddedChannelTest {

    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        // Full codec pair, mirroring the production pipeline order minus TLS.
        channel = new EmbeddedChannel(new AethelFrameEncoder(), new AethelFrameDecoder());
    }

    @AfterEach
    void tearDown() {
        assertFalse(channel.finishAndReleaseAll(), "pipeline should be drained of messages");
        // Netty's resource-leak detector flags any unreleased pooled buffer on GC;
        // tests use heap buffers but refCnt assertions below catch manual misuse.
    }

    private static ByteBuf payloadOf(byte seed, int len) {
        byte[] bytes = new byte[len];
        for (int i = 0; i < len; i++) {
            bytes[i] = (byte) (seed + i);
        }
        return Unpooled.wrappedBuffer(bytes);
    }

    @Test
    @DisplayName("Happy path: Frame -> encode -> decode round-trips exactly")
    void roundTrip() {
        ByteBuf payload = payloadOf((byte) 7, 256);
        ByteBuf expected = payload.copy(); // stable reference independent of refcount lifecycle
        Frame in = new Frame(CommandType.GOSSIP, payload);

        // refCnt 1 before write; the encoder releases the Frame after encoding.
        assertEquals(1, payload.refCnt(), "payload owned solely by the Frame pre-write");
        assertTrue(channel.writeOutbound(in));
        // MessageToByteEncoder released the Frame (and its payload) after encoding:
        // ownership of the bytes transferred to the outbound wire buffer.
        assertEquals(0, payload.refCnt(), "encoder must release the original payload");

        ByteBuf wire = channel.readOutbound();
        assertNotNull(wire);
        // Wire = 7-byte header + body, and the body bytes match the payload.
        assertEquals(7 + 256, wire.readableBytes());

        assertTrue(channel.writeInbound(wire)); // decoder path
        Frame out = channel.readInbound();
        assertNotNull(out);
        assertEquals(CommandType.GOSSIP, out.command());
        assertEquals(256, out.payload().readableBytes());
        assertEquals(expected, out.payload().slice());

        assertTrue(out.release(), "test consumer releases the decoded frame exactly once");
        expected.release();
    }

    @Test
    @DisplayName("Fragmentation: 1-byte-at-a-time delivery yields exactly one intact frame")
    void fragmentedDelivery() {
        ByteBuf payload = payloadOf((byte) 42, 100);
        Frame in = new Frame(CommandType.TELEMETRY, payload);
        assertTrue(channel.writeOutbound(in));
        ByteBuf wire = channel.readOutbound();
        assertNotNull(wire);

        // Feed the wire bytes one at a time, mimicking worst-case TCP segmentation.
        while (wire.isReadable()) {
            boolean lastByte = wire.readableBytes() == 1;
            channel.writeInbound(wire.readRetainedSlice(1));
            if (!lastByte) {
                assertNull(channel.readInbound(), "no frame must fire before the last fragment lands");
            }
        }
        wire.release();

        Frame out = channel.readInbound();
        assertNotNull(out, "complete frame must fire after final byte");
        assertEquals(CommandType.TELEMETRY, out.command());
        assertEquals(100, out.payload().readableBytes());
        assertEquals(payloadOf((byte) 42, 100), out.payload().slice());
        assertTrue(out.release());
    }

    @Test
    @DisplayName("Pipelining: two frames in one buffer decode in order, both intact")
    void multipleFramesOneSegment() {
        Frame first = new Frame(CommandType.HANDSHAKE, payloadOf((byte) 0, 16));
        Frame second = new Frame(CommandType.CONTROL, payloadOf((byte) 100, 32));
        assertTrue(channel.writeOutbound(first));
        assertTrue(channel.writeOutbound(second));
        ByteBuf wire = Unpooled.wrappedBuffer(new ByteBuf[]{channel.readOutbound(), channel.readOutbound()});

        assertTrue(channel.writeInbound(wire));
        Frame a = channel.readInbound();
        Frame b = channel.readInbound();
        assertNotNull(a);
        assertNotNull(b);
        assertEquals(CommandType.HANDSHAKE, a.command());
        assertEquals(CommandType.CONTROL, b.command());
        assertEquals(16, a.payload().readableBytes());
        assertEquals(32, b.payload().readableBytes());
        assertTrue(a.release());
        assertTrue(b.release());
    }
}
