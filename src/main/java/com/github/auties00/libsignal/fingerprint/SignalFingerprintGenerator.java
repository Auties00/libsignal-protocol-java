package com.github.auties00.libsignal.fingerprint;

import com.github.auties00.libsignal.key.SignalIdentityPublicKey;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SequencedCollection;

public final class SignalFingerprintGenerator {
    private static final int FINGERPRINT_VERSION = 0;

    private final int iterations;

    public SignalFingerprintGenerator(int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("Expected at least 1 iteration, got " + iterations);
        }

        this.iterations = iterations;
    }

    public SignalCombinedFingerprint generate(int version, byte[] localStableIdentifier, SignalIdentityPublicKey localSignalIdentityKey, byte[] remoteStableIdentifier, SignalIdentityPublicKey remoteSignalIdentityKey) {
        return generate(version, localStableIdentifier, List.of(localSignalIdentityKey), remoteStableIdentifier, List.of(remoteSignalIdentityKey));
    }

    public SignalCombinedFingerprint generate(int version, byte[] localStableIdentifier, SequencedCollection<? extends SignalIdentityPublicKey> localSignalIdentityKeys, byte[] remoteStableIdentifier, SequencedCollection<? extends SignalIdentityPublicKey> remoteSignalIdentityKeys) {
        var localFingerprint = getFingerprint(localStableIdentifier, localSignalIdentityKeys);
        var remoteFingerprint = getFingerprint(remoteStableIdentifier, remoteSignalIdentityKeys);
        return new SignalCombinedFingerprint(version, localFingerprint, remoteFingerprint);
    }

    private SignalLogicalFingerprint getFingerprint(byte[] stableIdentifier, SequencedCollection<? extends SignalIdentityPublicKey> unsortedSignalIdentityKeys) {
        try {
            var digest = MessageDigest.getInstance("SHA-512");

            digest.update((byte) (FINGERPRINT_VERSION >> 8));
            digest.update((byte) FINGERPRINT_VERSION);

            var sortedSignalIdentityKeys = new ArrayList<>(unsortedSignalIdentityKeys);
            Collections.sort(sortedSignalIdentityKeys);
            for (var identityKey : sortedSignalIdentityKeys) {
                digest.update(SignalIdentityPublicKey.type());
                digest.update(identityKey.toEncodedPoint());
            }

            digest.update(stableIdentifier);

            byte[] hash = null;
            for (var i = 0; i < iterations; i++) {
                if(hash != null) {
                    digest.update(hash);
                }
                for (var identityKey : sortedSignalIdentityKeys) {
                    digest.update(SignalIdentityPublicKey.type());
                    digest.update(identityKey.toEncodedPoint());
                }
                hash = digest.digest();
            }

            if(hash == null) {
                throw new InternalError();
            }

            return new SignalLogicalFingerprintBuilder()
                    .content(hash)
                    .build();
        } catch (NoSuchAlgorithmException exception) {
            throw new InternalError(exception);
        }
    }

}