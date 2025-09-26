package com.github.auties00.libsignal.kdf;

import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public final class HKDF {
    private static final int HASH_OUTPUT_SIZE = 32;
    private static final byte[] EMPTY_SALT = new byte[HASH_OUTPUT_SIZE];

    private final int offset;

    private HKDF(int offset) {
        this.offset = offset;
    }

    public static HKDF of(int messageVersion) {
        return switch (messageVersion) {
            case 2 -> new  HKDF(0);
            case 3 -> new  HKDF(1);
            default -> throw new IllegalArgumentException("Unknown version: " + messageVersion);
        };
    }

    public static HKDF ofCurrent() {
        return of(SignalCiphertextMessage.CURRENT_VERSION);
    }

    public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength) throws NoSuchAlgorithmException, InvalidKeyException {
        return deriveSecrets(inputKeyMaterial, EMPTY_SALT, info, outputLength);
    }

    public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) throws NoSuchAlgorithmException, InvalidKeyException {
        var mac = Mac.getInstance("HmacSHA256");
        return deriveSecrets(mac, inputKeyMaterial, salt, info, outputLength);
    }

    public byte[] deriveSecrets(Mac mac, byte[] inputKeyMaterial, byte[] info, int outputLength) throws InvalidKeyException {
        return deriveSecrets(mac, inputKeyMaterial, EMPTY_SALT, info, outputLength);
    }

    public byte[] deriveSecrets(Mac mac, byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) throws InvalidKeyException {
        Objects.requireNonNull(mac, "mac cannot be null");
        Objects.requireNonNull(inputKeyMaterial, "inputKeyMaterial cannot be null");
        Objects.requireNonNull(salt, "salt cannot be null");
        Objects.requireNonNull(info, "info cannot be null");
        if(outputLength < 0) {
            throw new IllegalArgumentException("outputLength cannot be negative");
        }
        var prk = extract(mac, salt, inputKeyMaterial);
        return expand(mac, prk, info, outputLength);
    }

    private byte[] extract(Mac mac, byte[] salt, byte[] inputKeyMaterial) throws InvalidKeyException {
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(inputKeyMaterial);
    }

    private byte[] expand(Mac mac, byte[] prk, byte[] info, int outputSize) throws InvalidKeyException {
        var iterations = (int) Math.ceil((double) outputSize / (double) HASH_OUTPUT_SIZE);
        var mixin = new byte[0];
        var result = new byte[outputSize];
        var remainingBytes = outputSize;
        var pos = 0;
        for (var i = offset; i < iterations + offset; i++) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(mixin);
            if (info != null) {
                mac.update(info);
            }
            mac.update((byte) i);
            var stepResult = mac.doFinal();
            var stepSize = Math.min(remainingBytes, stepResult.length);
            System.arraycopy(stepResult, 0, result, pos, stepSize);
            pos += stepSize;
            remainingBytes -= stepSize;
            mixin = stepResult;
        }

        return result;
    }
}