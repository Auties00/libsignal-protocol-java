package com.github.auties00.signal.util;

public final class ByteUtils {
    private ByteUtils() {
        throw new UnsupportedOperationException("ByteUtils is a utility class and cannot be initialized");
    }

    public static long readInt40(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xffL) << 32) |
                ((bytes[offset + 1] & 0xffL) << 24) |
                ((bytes[offset + 2] & 0xffL) << 16) |
                ((bytes[offset + 3] & 0xffL) << 8) |
                ((bytes[offset + 4] & 0xffL));
    }
}
