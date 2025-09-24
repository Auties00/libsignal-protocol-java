package com.github.auties00.signal.key;

import it.auties.curve25519.Curve25519;
import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufSerializer;

import java.util.Objects;

// TODO: Refactor this class when next ModernProtobuf update is ready
public record SignalIdentityPrivateKey(byte[] encodedPoint) implements SignalIdentityKey {
    private static final int KEY_LENGTH = 32;

    public static int length() {
        return KEY_LENGTH;
    }

    public SignalIdentityPrivateKey {
        Objects.requireNonNull(encodedPoint, "key cannot be null");
    }

    public static SignalIdentityPrivateKey random() {
        return new SignalIdentityPrivateKey(Curve25519.randomPrivateKey());
    }

    @ProtobufDeserializer
    public static SignalIdentityPrivateKey of(byte[] serialized) {
        return new SignalIdentityPrivateKey(serialized);
    }

    @ProtobufSerializer
    @Override
    public byte[] encodedPoint() {
        return encodedPoint;
    }

    @Override
    public int writePoint(byte[] destination, int offset) {
        System.arraycopy(encodedPoint, 0, destination, offset, encodedPoint.length);
        return offset + length();
    }
}
