package com.github.auties00.libsignal.key;

import com.github.auties00.curve25519.Curve25519;
import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufSerializer;

import java.util.Arrays;
import java.util.Objects;

public final class SignalIdentityPublicKey implements SignalIdentityKey, Comparable<SignalIdentityPublicKey> {
    private static final byte KEY_TYPE = 5;
    private static final int KEY_LENGTH = 32;
    private static final int KEY_WITH_TYPE_LENGTH = 33;

    public static byte type() {
        return KEY_TYPE;
    }

    public static int length() {
        return KEY_LENGTH;
    }

    public static int lengthWithType() {
        return KEY_WITH_TYPE_LENGTH;
    }

    private final byte[] point;

    private SignalIdentityPublicKey(byte[] point) {
        this.point = point;
    }

    public static SignalIdentityPublicKey ofPrivate(SignalIdentityPrivateKey privateKey) {
        Objects.requireNonNull(privateKey, "privateKey cannot be null");
        var publicKey = Curve25519.getPublicKey(privateKey.toEncodedPoint());
        return new SignalIdentityPublicKey(publicKey);
    }

    // TODO: When the next version of ModernProtobuf is available,
    //       refactor me to take a ProtobufInputStream so we can save the copy
    //       if length == KEY_WITH_TYPE_LENGTH
    @ProtobufDeserializer
    public static SignalIdentityPublicKey ofDirect(byte[] encodedPoint) {
        Objects.requireNonNull(encodedPoint, "encodedPoint cannot be null");
        var encodedPointWithoutType = switch (encodedPoint.length) {
            case KEY_LENGTH -> encodedPoint;
            case KEY_WITH_TYPE_LENGTH -> {
                if (encodedPoint[0] != KEY_TYPE) {
                    throw new IllegalArgumentException("Invalid key type");
                }

                yield Arrays.copyOfRange(encodedPoint, 1, KEY_WITH_TYPE_LENGTH);
            }
            default -> throw new IllegalArgumentException("Invalid key length: " + encodedPoint.length);
        };
        return new SignalIdentityPublicKey(encodedPointWithoutType);
    }

    public static SignalIdentityPublicKey ofCopy(byte[] encodedPoint, int offset, int length) {
        Objects.requireNonNull(encodedPoint, "encodedPoint cannot be null");
        var encodedPointWithoutType = switch (length) {
            case KEY_LENGTH -> Arrays.copyOfRange(encodedPoint, offset, offset + KEY_LENGTH);
            case KEY_WITH_TYPE_LENGTH -> {
                if (encodedPoint[offset] != KEY_TYPE) {
                    throw new IllegalArgumentException("Invalid key type");
                }

                yield Arrays.copyOfRange(encodedPoint, offset + 1, offset + 1 + KEY_LENGTH);
            }
            default -> throw new IllegalArgumentException("Invalid key length: " + length);
        };
        return new SignalIdentityPublicKey(encodedPointWithoutType);
    }

    @Override
    public byte[] toEncodedPoint() {
        return point;
    }

    @ProtobufSerializer
    public byte[] toSerialized() {
        var result = new byte[KEY_WITH_TYPE_LENGTH];
        result[0] = KEY_TYPE;
        System.arraycopy(point, 0, result, 1, KEY_LENGTH);
        return result;
    }

    @Override
    public int writeEncodedPoint(byte[] destination, int offset) {
        System.arraycopy(point, 0, destination, offset, KEY_LENGTH);
        return offset + KEY_LENGTH;
    }

    public int writeEncodedPointWithType(byte[] destination, int offset) {
        destination[offset++] = KEY_TYPE;
        System.arraycopy(point, 0, destination, offset, KEY_LENGTH);
        return offset + KEY_LENGTH;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SignalIdentityPublicKey that
                && Arrays.equals(point, that.point);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(point);
    }

    @Override
    public String toString() {
        return "SignalPublicKey[" +
                "point=" + Arrays.toString(point) + ']';
    }

    // libsignal compares the two points through BigInteger
    // This approach is equivalent and doesn't require allocations
    @Override
    public int compareTo(SignalIdentityPublicKey o) {
        var aNeg = (point[0] & 0x80) != 0;
        var bNeg = (o.point[0] & 0x80) != 0;
        if (aNeg != bNeg) {
            return aNeg ? -1 : 1;
        }

        return Arrays.compareUnsigned(point, o.point);
    }
}
