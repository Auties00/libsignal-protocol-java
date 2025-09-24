package com.github.auties00.signal.ratchet;

import com.github.auties00.signal.key.SignalIdentityKeyPair;
import com.github.auties00.signal.key.SignalIdentityPrivateKey;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import com.github.auties00.signal.protocol.SignalCiphertextMessage;
import com.github.auties00.signal.state.SignalSessionChainBuilder;
import com.github.auties00.signal.state.SignalSessionRootKey;
import com.github.auties00.signal.state.SignalSessionState;
import it.auties.curve25519.Curve25519;

import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class SignalRatchetingSession {
    private static final int DISCONTINUITY_BYTES_LENGTH = 32;
    private static final int KEY_AGREEMENT_LENGTH = 32;

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

    public static void initializeSession(SignalSessionState sessionState, SignalAliceParameters parameters) {
        try {
            var kdf = KDF.getInstance("HKDF-SHA256");

            sessionState.setSessionVersion(SignalCiphertextMessage.CURRENT_VERSION);
            sessionState.setRemoteIdentityPublic(parameters.theirIdentityKey());
            sessionState.setLocalIdentityPublic(parameters.ourIdentityKey().publicKey());

            var sendingRatchetKey = SignalIdentityKeyPair.random();
            var hasOneTimePreKey = parameters.theirOneTimePreKey() != null;
            var offset = 0;
            var secrets = new byte[DISCONTINUITY_BYTES_LENGTH + KEY_AGREEMENT_LENGTH + KEY_AGREEMENT_LENGTH + KEY_AGREEMENT_LENGTH + (hasOneTimePreKey ? KEY_AGREEMENT_LENGTH : 0)];
            offset = writeDiscontinuityBytes(secrets, offset);
            offset = writeKeyAgreement(parameters.theirSignedPreKey(), parameters.ourIdentityKey().privateKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.theirIdentityKey(), parameters.ourBaseKey().privateKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.theirSignedPreKey(), parameters.ourBaseKey().privateKey(), secrets, offset);
            if (hasOneTimePreKey) {
                offset = writeKeyAgreement(parameters.theirOneTimePreKey(), parameters.ourBaseKey().privateKey(), secrets, offset);
            }

            if (offset != secrets.length) {
                throw new InternalError("Offset is not equal to the length of the array");
            }

            var receiverParams = HKDFParameterSpec.ofExtract()
                    .addIKM(secrets)
                    .thenExpand("WhisperText".getBytes(StandardCharsets.UTF_8), 64);
            var receiverDerivedSecrets = kdf.deriveData(receiverParams);
            var receiverRootKeyData = Arrays.copyOfRange(receiverDerivedSecrets, 0, 32);
            var receiverChainKeyData = Arrays.copyOfRange(receiverDerivedSecrets, 32, 64);
            var receiverChainKey = new SignalChainKeyBuilder()
                    .key(receiverChainKeyData)
                    .index(0)
                    .build();
            var receiverChain = new SignalSessionChainBuilder()
                    .senderRatchetKey(parameters.theirRatchetKey())
                    .chainKey(receiverChainKey)
                    .build();
            sessionState.addReceiverChain(receiverChain);

            var chain = sessionState.rootKey()
                    .createChain(parameters.theirRatchetKey(), sendingRatchetKey.privateKey());
            var senderChain = new SignalSessionChainBuilder()
                    .senderRatchetKey(sendingRatchetKey.publicKey())
                    .chainKey(chain.chainKey())
                    .build();
            sessionState.setSenderChain(senderChain);
            sessionState.setRootKey(chain.rootKey());
        } catch (GeneralSecurityException exception) {
            throw new AssertionError(exception);
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
            offset = writeKeyAgreement(parameters.theirIdentityKey(), parameters.ourSignedPreKey().privateKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.theirBaseKey(), parameters.ourIdentityKey().privateKey(), secrets, offset);
            offset = writeKeyAgreement(parameters.theirBaseKey(), parameters.ourSignedPreKey().privateKey(), secrets, offset);

            if (parameters.ourOneTimePreKey() != null) {
                offset = writeKeyAgreement(parameters.theirBaseKey(), parameters.ourOneTimePreKey().privateKey(), secrets, offset);
            }

            if (offset != secrets.length) {
                throw new InternalError("Offset is not equal to the length of the array");
            }

            var kdf = KDF.getInstance("HKDF-SHA256");
            var senderParams = HKDFParameterSpec.ofExtract()
                    .addIKM(secrets)
                    .thenExpand("WhisperText".getBytes(StandardCharsets.UTF_8), 64);
            var senderDerivedSecrets = kdf.deriveData(senderParams);
            var senderRootKeyData = SignalSessionRootKey.of(senderDerivedSecrets, 0, 32);
            var senderChainKeyData = Arrays.copyOfRange(senderDerivedSecrets, 32, 64);
            var senderChainKey = new SignalChainKeyBuilder()
                    .key(senderChainKeyData)
                    .index(0)
                    .build();
            var senderChain = new SignalSessionChainBuilder()
                    .senderRatchetKey(parameters.ourRatchetKey().publicKey())
                    .chainKey(senderChainKey)
                    .build();
            sessionState.setSenderChain(senderChain);
            sessionState.setRootKey(senderRootKeyData);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    private static int writeKeyAgreement(SignalIdentityPublicKey publicKey, SignalIdentityPrivateKey privateKey, byte[] output, int offset) {
        Curve25519.sharedKey(publicKey.toEncodedPoint(), privateKey.toEncodedPoint(), output, offset);
        return offset + KEY_AGREEMENT_LENGTH;
    }

    private static int writeDiscontinuityBytes(byte[] output, int offset) {
        Arrays.fill(output, 0, DISCONTINUITY_BYTES_LENGTH, (byte) 0xFF);
        return offset + DISCONTINUITY_BYTES_LENGTH;
    }

    private static boolean isAlice(SignalIdentityPublicKey ourKey, SignalIdentityPublicKey theirKey) {
        return ourKey.compareTo(theirKey) < 0;
    }
}
