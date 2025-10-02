package com.github.auties00.libsignal.key;

import com.github.auties00.curve25519.Curve25519;
import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufSerializer;

import java.util.Arrays;
import java.util.Objects;

public final class SignalIdentityPrivateKey implements SignalIdentityKey {
    private static final int KEY_LENGTH = 32;

    public static int length() {
        return KEY_LENGTH;
    }

    private final byte[] encodedPoint;

    private SignalIdentityPrivateKey(byte[] encodedPoint) {
        this.encodedPoint = encodedPoint;
    }

    public static SignalIdentityPrivateKey random() {
        return new SignalIdentityPrivateKey(Curve25519.randomPrivateKey());
    }

    @ProtobufDeserializer
    public static SignalIdentityPrivateKey ofDirect(byte[] encodedPoint) {
        Objects.requireNonNull(encodedPoint, "encodedPoint cannot be null");
        if(encodedPoint.length != KEY_LENGTH) {
            throw new IndexOutOfBoundsException("encodedPoint length must be " + KEY_LENGTH + ", but was " + encodedPoint.length);
        }
        return new SignalIdentityPrivateKey(encodedPoint);
    }

    public static SignalIdentityPrivateKey ofCopy(byte[] serialized, int offset) {
        var encodedPoint = Arrays.copyOfRange(serialized, offset, offset + KEY_LENGTH);
        return new SignalIdentityPrivateKey(encodedPoint);
    }

    @ProtobufSerializer
    @Override
    public byte[] toEncodedPoint() {
        return encodedPoint;
    }

    @Override
    public int writeEncodedPoint(byte[] destination, int offset) {
        System.arraycopy(encodedPoint, 0, destination, offset, encodedPoint.length);
        return offset + length();
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this ||
                obj instanceof SignalIdentityPrivateKey that
                        && Arrays.equals(encodedPoint, that.encodedPoint);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encodedPoint);
    }

    @Override
    public String toString() {
        return "SignalIdentityPrivateKey[" +
                "encodedPoint=" + Arrays.toString(encodedPoint) + ']';
    }
}
