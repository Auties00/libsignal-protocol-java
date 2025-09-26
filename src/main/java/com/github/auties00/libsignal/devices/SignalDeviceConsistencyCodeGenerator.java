package com.github.auties00.libsignal.devices;

import com.github.auties00.libsignal.util.ByteUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.SequencedCollection;

public final class SignalDeviceConsistencyCodeGenerator {
    private static final int CODE_VERSION = 0;

    private SignalDeviceConsistencyCodeGenerator() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static String generate(SignalDeviceConsistencyCommitment commitment, SequencedCollection<? extends SignalDeviceConsistencySignature> signatures) {
        try {
            var messageDigest = MessageDigest.getInstance("SHA-512");

            messageDigest.update((byte) (CODE_VERSION >> 8));
            messageDigest.update((byte) CODE_VERSION);

            messageDigest.update(commitment.toSerialized());

            var sortedSignatures = new ArrayList<>(signatures);
            Collections.sort(sortedSignatures);
            for (var signature : sortedSignatures) {
                messageDigest.update(signature.vrfOutput());
            }

            var hash = messageDigest.digest();

            var digits = getEncodedChunk(hash, 0) + getEncodedChunk(hash, 5);
            return digits.substring(0, 6);
        } catch (NoSuchAlgorithmException exception) {
            throw new InternalError(exception);
        }
    }

    private static String getEncodedChunk(byte[] hash, int offset) {
        var chunk = ByteUtils.readInt40(hash, offset) % 100000;
        return String.format("%05d", chunk);
    }
}