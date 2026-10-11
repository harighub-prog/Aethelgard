package dev.aethelgard.transport;

import dev.aethelgard.crypto.CryptoAgilityEngine.AlgorithmSuite;
import dev.aethelgard.protocol.CommandType;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.CompositeByteBuf;
import io.netty.util.ReferenceCounted;

import java.util.Objects;

/**
 * Layer 5 carrier for hybrid classical+PQC framed messages.
 *
 * Encapsulates the command type, agility suite metadata, dual cryptographic
 * signatures (classical ECDSA + post-quantum ML-DSA / Dilithium), and the zero-copy payload.
 *
 * Implements {@link ReferenceCounted} across all underlying direct buffers: releasing the
 * frame releases both signature buffers and the payload buffer atomically.
 */
public final class HybridFrame implements ReferenceCounted {

    private final CommandType command;
    private final AlgorithmSuite suite;
    private final ByteBuf classicalSignature;
    private final ByteBuf pqcSignature;
    private final ByteBuf payload;

    public HybridFrame(CommandType command,
                       AlgorithmSuite suite,
                       ByteBuf classicalSignature,
                       ByteBuf pqcSignature,
                       ByteBuf payload) {
        this.command = Objects.requireNonNull(command, "command");
        this.suite = Objects.requireNonNull(suite, "suite");
        this.classicalSignature = Objects.requireNonNull(classicalSignature, "classicalSignature");
        this.pqcSignature = Objects.requireNonNull(pqcSignature, "pqcSignature");
        this.payload = Objects.requireNonNull(payload, "payload");
    }

    public CommandType command() {
        return command;
    }

    public AlgorithmSuite suite() {
        return suite;
    }

    public ByteBuf classicalSignature() {
        return classicalSignature;
    }

    public ByteBuf pqcSignature() {
        return pqcSignature;
    }

    public ByteBuf payload() {
        return payload;
    }

    /**
     * Stitches signature components and payload dynamically into a single zero-copy
     * {@link CompositeByteBuf} without allocating temporary heap byte arrays.
     */
    public CompositeByteBuf stitchBody(ByteBufAllocator alloc) {
        CompositeByteBuf composite = alloc.compositeDirectBuffer(3);
        composite.addComponent(true, classicalSignature.retainedSlice());
        composite.addComponent(true, pqcSignature.retainedSlice());
        composite.addComponent(true, payload.retainedSlice());
        return composite;
    }

    @Override
    public int refCnt() {
        return payload.refCnt();
    }

    @Override
    public ReferenceCounted retain() {
        classicalSignature.retain();
        pqcSignature.retain();
        payload.retain();
        return this;
    }

    @Override
    public ReferenceCounted retain(int increment) {
        classicalSignature.retain(increment);
        pqcSignature.retain(increment);
        payload.retain(increment);
        return this;
    }

    @Override
    public ReferenceCounted touch() {
        classicalSignature.touch();
        pqcSignature.touch();
        payload.touch();
        return this;
    }

    @Override
    public ReferenceCounted touch(Object hint) {
        classicalSignature.touch(hint);
        pqcSignature.touch(hint);
        payload.touch(hint);
        return this;
    }

    @Override
    public boolean release() {
        boolean r1 = classicalSignature.release();
        boolean r2 = pqcSignature.release();
        boolean r3 = payload.release();
        return r1 && r2 && r3;
    }

    @Override
    public boolean release(int decrement) {
        boolean r1 = classicalSignature.release(decrement);
        boolean r2 = pqcSignature.release(decrement);
        boolean r3 = payload.release(decrement);
        return r1 && r2 && r3;
    }

    @Override
    public String toString() {
        return "HybridFrame{command=" + command +
                ", suite=" + suite +
                ", classicalSigLen=" + classicalSignature.readableBytes() +
                ", pqcSigLen=" + pqcSignature.readableBytes() +
                ", payloadLen=" + payload.readableBytes() +
                '}';
    }
}
