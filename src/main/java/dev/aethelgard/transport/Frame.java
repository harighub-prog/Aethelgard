package dev.aethelgard.transport;

import dev.aethelgard.protocol.CommandType;
import io.netty.util.ReferenceCounted;
import java.util.Objects;

/**
 * Immutable frame carrier holding a command type and a REFERENCE-COUNTED payload
 * ({@link io.netty.buffer.ByteBuf}). The payload is never copied: the decoder
 * hands over ownership of a retained slice, and the encoder transfers that
 * ownership to the outbound buffer. Whoever releases the Frame releases the
 * payload exactly once.
 */
public final class Frame implements ReferenceCounted {

    private final CommandType command;
    private final io.netty.buffer.ByteBuf payload;

    public Frame(CommandType command, io.netty.buffer.ByteBuf payload) {
        this.command = Objects.requireNonNull(command);
        this.payload = Objects.requireNonNull(payload);
    }

    public CommandType command() {
        return command;
    }

    /** The payload buffer. Callers must NOT release it directly; use {@link #release()}. */
    public io.netty.buffer.ByteBuf payload() {
        return payload;
    }

    @Override
    public int refCnt() {
        return payload.refCnt();
    }

    @Override
    public ReferenceCounted retain() {
        payload.retain();
        return this;
    }

    @Override
    public ReferenceCounted retain(int increment) {
        payload.retain(increment);
        return this;
    }

    @Override
    public ReferenceCounted touch() {
        payload.touch();
        return this;
    }

    @Override
    public ReferenceCounted touch(Object hint) {
        payload.touch(hint);
        return this;
    }

    @Override
    public boolean release() {
        return payload.release();
    }

    @Override
    public boolean release(int decrement) {
        return payload.release(decrement);
    }

    @Override
    public String toString() {
        return "Frame{command=" + command + ", payloadReadableBytes=" + payload.readableBytes() + '}';
    }
}
