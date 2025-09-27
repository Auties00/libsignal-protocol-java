package com.github.auties00.libsignal.ratchet;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.kdf.HKDF;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPrivateKey;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.state.SignalSessionChainBuilder;
import com.github.auties00.libsignal.state.SignalSessionState;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class SignalRatchetingSession {
    private static final int DISCONTINUITY_BYTES_LENGTH = 32;
    private static final int KEY_AGREEMENT_LENGTH = 32;

    private static final byte[] TEXT_INFO = "WhisperText".getBytes(StandardCharsets.UTF_8);

    public static void initializeSession(SignalSessionState sessionState, SignalSymmetricParameters parameters) {
        if (isAlice(parameters.ourBaseKey().publicKey(), parameters.theirBaseKey())) {
            var aliceParameters = new SignalAliceParametersBuilder()
                    .ourBaseKey(parameters.ourBaseKey())
                    .ourIdentityKey(parameters.ourIdentityKey())
                    .theirRatchetKey(parameters.theirRatchetKey())
                    .theirIdentityKey(parameters.theirIdentityKey())
                    .theirSignedPreKey(parameters.theirBaseKey())
                    .build();
            initializeSession(sessionState, aliceParameters);
        } else {
            var bobParameters = new SignalBobParametersBuilder()
                    .ourIdentityKey(parameters.ourIdentityKey())
                    .ourRatchetKey(parameters.ourRatchetKey())
                    .ourSignedPreKey(parameters.ourBaseKey())
                    .theirBaseKey(parameters.theirBaseKey())
                    .theirIdentityKey(parameters.theirIdentityKey())
                    .build();
            initializeSession(sessionState, bobParameters);
        }
    }

    private static boolean isAlice(SignalIdentityPublicKey ourKey, SignalIdentityPublicKey theirKey) {
        return ourKey.compareTo(theirKey) < 0;
    }

    public static void initializeSession(SignalSessionState sessionState, SignalAliceParameters parameters) {
        try {
            sessionState.setSessionVersion(SignalCiphertextMessage.CURRENT_VERSION);
            sessionState.setRemoteIdentityPublic(parameters.theirIdentityKey());
            sessionState.setLocalIdentityPublic(parameters.ourIdentityKey().publicKey());

            var sendingRatchetKey = SignalIdentityKeyPair.random();
            var hasOneTimePreKey = parameters.theirOneTimePreKey() != null;
            var offset = 0;
            var secrets = new byte[DISCONTINUITY_BYTES_LENGTH + KEY_AGREEMENT_LENGTH + KEY_AGREEMENT_LENGTH + KEY_AGREEMENT_LENGTH + (hasOneTimePreKey ? KEY_AGREEMENT_LENGTH : 0)];
            offset = writeDiscontinuityBytes(secrets, offset);
            offset = writeKeyAgreement(parameters.ourIdentityKey().privateKey(), parameters.theirSignedPreKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.ourBaseKey().privateKey(), parameters.theirIdentityKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.ourBaseKey().privateKey(), parameters.theirSignedPreKey(), secrets, offset);
            if (hasOneTimePreKey) {
                offset = writeKeyAgreement(parameters.ourBaseKey().privateKey(), parameters.theirOneTimePreKey(), secrets, offset);
            }

            if (offset != secrets.length) {
                throw new InternalError("Offset is not equal to the length of the array");
            }

            var derivedKeys = HKDF.ofCurrent()
                    .deriveSecrets(secrets, TEXT_INFO, 64);

            var receiverRootKeyData = SignalIdentityPublicKey.ofCopy(derivedKeys, 0, 32);
            var receiverRootKey = SignalRootKey.of(receiverRootKeyData);
            var receiverChainKeyData = Arrays.copyOfRange(derivedKeys, 32, 64);
            var receiverChainKey = new SignalChainKeyBuilder()
                    .key(receiverChainKeyData)
                    .index(0)
                    .build();
            sessionState.addReceiverChain(new SignalSessionChainBuilder()
                    .senderRatchetKey(parameters.theirRatchetKey())
                    .chainKey(receiverChainKey)
                    .build());

            var hkdf = HKDF.of(sessionState.sessionVersion());
            var sendingChain = receiverRootKey.createChain(hkdf, sendingRatchetKey.privateKey(), parameters.theirRatchetKey());
            sessionState.setSenderChain(new SignalSessionChainBuilder()
                    .senderRatchetKey(sendingRatchetKey.publicKey())
                    .senderRatchetKeyPrivate(sendingRatchetKey.privateKey())
                    .chainKey(sendingChain.chainKey())
                    .build());

            sessionState.setRootKey(sendingChain.rootKey());
        } catch (GeneralSecurityException exception) {
            throw new InternalError(exception);
        }
    }

    public static void initializeSession(SignalSessionState sessionState, SignalBobParameters parameters) {
        try {
            sessionState.setSessionVersion(SignalCiphertextMessage.CURRENT_VERSION);
            sessionState.setRemoteIdentityPublic(parameters.theirIdentityKey());
            sessionState.setLocalIdentityPublic(parameters.ourIdentityKey().publicKey());

            var hasOneTimePreKey = parameters.ourOneTimePreKey() != null;
            var secrets = new byte[DISCONTINUITY_BYTES_LENGTH + KEY_AGREEMENT_LENGTH + KEY_AGREEMENT_LENGTH + KEY_AGREEMENT_LENGTH + (hasOneTimePreKey ? KEY_AGREEMENT_LENGTH : 0)];
            var offset = writeDiscontinuityBytes(secrets, 0);
            offset = writeKeyAgreement(parameters.ourSignedPreKey().privateKey(), parameters.theirIdentityKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.ourIdentityKey().privateKey(), parameters.theirBaseKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.ourSignedPreKey().privateKey(), parameters.theirBaseKey(), secrets, offset);

            if (parameters.ourOneTimePreKey() != null) {
                offset = writeKeyAgreement(parameters.ourOneTimePreKey().privateKey(), parameters.theirBaseKey(), secrets, offset);
            }

            if (offset != secrets.length) {
                throw new InternalError("Offset is not equal to the length of the array");
            }

            var senderDerivedSecrets = HKDF.ofCurrent()
                    .deriveSecrets(secrets, TEXT_INFO, 64);

            var senderRootKeyData = SignalIdentityPublicKey.ofCopy(senderDerivedSecrets, 0, 32);
            var senderRootKey = SignalRootKey.of(senderRootKeyData);
            var senderChainKeyData = Arrays.copyOfRange(senderDerivedSecrets, 32, 64);
            var senderChainKey = new SignalChainKeyBuilder()
                    .key(senderChainKeyData)
                    .index(0)
                    .build();
            var senderChain = new SignalSessionChainBuilder()
                    .senderRatchetKey(parameters.ourRatchetKey().publicKey())
                    .senderRatchetKeyPrivate(parameters.ourRatchetKey().privateKey())
                    .chainKey(senderChainKey)
                    .build();
            sessionState.setSenderChain(senderChain);

            sessionState.setRootKey(senderRootKey);
        } catch (GeneralSecurityException e) {
            throw new InternalError(e);
        }
    }

    private static int writeKeyAgreement(SignalIdentityPrivateKey privateKey, SignalIdentityPublicKey publicKey, byte[] output, int offset) {
        Curve25519.sharedKey(privateKey.toEncodedPoint(), publicKey.toEncodedPoint(), 0, output, offset);
        return offset + KEY_AGREEMENT_LENGTH;
    }

    private static int writeDiscontinuityBytes(byte[] output, int offset) {
        Arrays.fill(output, 0, DISCONTINUITY_BYTES_LENGTH, (byte) 0xFF);
        return offset + DISCONTINUITY_BYTES_LENGTH;
    }
}
