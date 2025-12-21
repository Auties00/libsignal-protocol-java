package com.github.auties00.libsignal.groups.ratchet;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Arrays;
import java.util.Objects;

@ProtobufMessage
public final class SignalSenderMessageKey {
    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int iteration;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final byte[] seed;

    SignalSenderMessageKey(int iteration, byte[] seed) {
        this.iteration = iteration;
        this.seed = seed;
    }

    public int iteration() {
        return iteration;
    }

    public byte[] seed() {
        return seed;
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || obj instanceof SignalSenderMessageKey that
                && this.iteration == that.iteration &&
                Arrays.equals(this.seed, that.seed);
    }

    @Override
    public int hashCode() {
        return Objects.hash(iteration, Arrays.hashCode(seed));
    }

    @Override
    public String toString() {
        return "SenderMessageKey[" +
                "iteration=" + iteration + ", " +
                "seed=" + Arrays.toString(seed) + ']';
    }
}