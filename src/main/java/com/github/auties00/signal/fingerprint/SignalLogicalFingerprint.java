package com.github.auties00.signal.fingerprint;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Arrays;
import java.util.Objects;

@ProtobufMessage
public record SignalLogicalFingerprint(
        @ProtobufProperty(index = 1, type = ProtobufType.BYTES)
        byte[] content
) {
    private static final int LENGTH = 32;

    public SignalLogicalFingerprint(byte[] content) {
        Objects.requireNonNull(content, "content cannot be null");
        this.content = Arrays.copyOf(content, LENGTH);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SignalLogicalFingerprint(var otherContent)
                && Arrays.equals(content, otherContent);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(content);
    }
}
