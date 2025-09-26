package com.github.auties00.libsignal.fingerprint;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Arrays;
import java.util.Objects;

@ProtobufMessage
public final class SignalLogicalFingerprint {
    private static final int LENGTH = 32;

    @ProtobufProperty(index = 1, type = ProtobufType.BYTES)
    final byte[] content;

    SignalLogicalFingerprint(byte[] content) {
        Objects.requireNonNull(content, "content cannot be null");
        this.content = Arrays.copyOf(content, LENGTH);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SignalLogicalFingerprint that
                && Arrays.equals(content, that.content);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(content);
    }

    public byte[] content() {
        return content;
    }

    @Override
    public String toString() {
        return "SignalLogicalFingerprint[" +
                "content=" + Arrays.toString(content) + ']';
    }
}
