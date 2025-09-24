package com.github.auties00.signal.fingerprint;

import com.github.auties00.signal.key.SignalIdentityPublicKey;

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
            var publicKey = getLogicalKeyBytes(unsortedSignalIdentityKeys);
            digest.update(publicKey);
            digest.update(stableIdentifier);
            var hash = digest.digest(publicKey);
            for (var i = 0; i < iterations; i++) {
                digest.update(hash);
                hash = digest.digest(publicKey);
            }
            return new SignalLogicalFingerprintBuilder()
                    .content(digest.digest())
                    .build();
        } catch (NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }

    private byte[] getLogicalKeyBytes(SequencedCollection<? extends SignalIdentityPublicKey> identityKeys) {
        var sortedSignalIdentityKeys = new ArrayList<>(identityKeys);
        Collections.sort(sortedSignalIdentityKeys);
        var result = new byte[SignalIdentityPublicKey.lengthWithType() * sortedSignalIdentityKeys.size()];
        for (var i = 0; i < sortedSignalIdentityKeys.size(); i++) {
            var identityKey = sortedSignalIdentityKeys.get(i);
            identityKey.writeEncodedPointWithType(result, i * SignalIdentityPublicKey.lengthWithType());
        }
        return result;
    }
}