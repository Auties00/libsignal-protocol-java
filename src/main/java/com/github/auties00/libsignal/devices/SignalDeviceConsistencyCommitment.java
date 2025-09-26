package com.github.auties00.libsignal.devices;

import com.github.auties00.libsignal.key.SignalIdentityPublicKey;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.SequencedCollection;

public final class SignalDeviceConsistencyCommitment {
    private static final String VERSION = "DeviceConsistencyCommitment_V0";

    private final int generation;
    private final byte[] serialized;

    public SignalDeviceConsistencyCommitment(int generation, SequencedCollection<? extends SignalIdentityPublicKey> identityKeys) {
        try {
            var sortedIdentityKeys = new ArrayList<>(identityKeys);
            Collections.sort(sortedIdentityKeys);

            var messageDigest = MessageDigest.getInstance("SHA-512");

            messageDigest.update(VERSION.getBytes());

            messageDigest.update((byte) (generation >> 24));
            messageDigest.update((byte) (generation >> 16));
            messageDigest.update((byte) (generation >> 8));
            messageDigest.update((byte) generation);

            for (var commitment : sortedIdentityKeys) {
                messageDigest.update(commitment.toEncodedPoint());
            }

            this.generation = generation;
            this.serialized = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError(e);
        }
    }

    public int generation() {
        return generation;
    }

    public byte[] toSerialized() {
        return serialized;
    }
}