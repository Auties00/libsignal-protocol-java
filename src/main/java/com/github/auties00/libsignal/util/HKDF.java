package com.github.auties00.libsignal.util;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.util.Objects;

public final class HKDF {
    private static final int V2_EXPAND_OFFSET = 0;
    private static final int V3_EXPAND_OFFSET = 1;

    private static final byte[] EMPTY_SALT = new byte[32];
    private static final String ALGORITHM = "HmacSHA256";

    private HKDF() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static byte[] deriveSecrets(int version, Mac mac, byte[] inputKeyMaterial, byte[] info, int outputLength) throws InvalidKeyException {
        return deriveSecrets(version, mac, inputKeyMaterial, EMPTY_SALT, info, outputLength);
    }

    public static byte[] deriveSecrets(int version, Mac mac, byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) throws InvalidKeyException {
        Objects.requireNonNull(mac, "mac cannot be null");
        Objects.requireNonNull(inputKeyMaterial, "inputKeyMaterial cannot be null");
        Objects.requireNonNull(salt, "salt cannot be null");
        Objects.requireNonNull(info, "info cannot be null");
        if(outputLength < 0) {
            throw new IllegalArgumentException("outputLength cannot be negative");
        }
        var prk = extract(mac, salt, inputKeyMaterial);
        return expand(version, mac, prk, info, outputLength);
    }

    private static byte[] extract(Mac mac, byte[] salt, byte[] inputKeyMaterial) throws InvalidKeyException {
        mac.init(new SecretKeySpec(salt, ALGORITHM));
        return mac.doFinal(inputKeyMaterial);
    }

    private static byte[] expand(int version, Mac mac, byte[] prk, byte[] info, int outputSize) throws InvalidKeyException {
        var offset = getExpandOffset(version);
        if(!ALGORITHM.equals(mac.getAlgorithm())) {
            throw new IllegalArgumentException("Invalid algorithm: " + mac.getAlgorithm());
        }

        var iterations = offset + ((outputSize + 31) / 32);
        if (iterations < 0 || iterations > 255) {
            throw new IllegalArgumentException("Too many iterations");
        }

        var result = new byte[outputSize];
        var remainingBytes = outputSize;
        var pos = 0;
        var key = new SecretKeySpec(prk, ALGORITHM);
        var stepResult = new byte[32];
        for (var i = offset; i < iterations; i++) {
            mac.init(key);
            if(i != offset) {
                mac.update(stepResult);
            }
            if (info != null) {
                mac.update(info);
            }
            mac.update((byte) i);
            try {
                mac.doFinal(stepResult, 0);
            }catch (ShortBufferException e) {
                throw new InternalError(e);
            }
            var stepSize = Math.min(remainingBytes, stepResult.length);
            System.arraycopy(stepResult, 0, result, pos, stepSize);
            pos += stepSize;
            remainingBytes -= stepSize;
        }
        return result;
    }

    private static int getExpandOffset(int messageVersion) {
        return switch (messageVersion) {
            case 2 -> V2_EXPAND_OFFSET;
            case 3 -> V3_EXPAND_OFFSET;
            default -> throw new IllegalArgumentException("Unknown version: " + messageVersion);
        };
    }
}