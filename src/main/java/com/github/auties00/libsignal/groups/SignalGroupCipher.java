package com.github.auties00.libsignal.groups;

import com.github.auties00.libsignal.SignalProtocolStore;
import com.github.auties00.libsignal.exception.SignalDecryptException;
import com.github.auties00.libsignal.exception.SignalEncryptException;
import com.github.auties00.libsignal.exception.SignalMissingSenderKeyException;
import com.github.auties00.libsignal.exception.SignalMissingSenderKeyStateException;
import com.github.auties00.libsignal.groups.ratchet.SignalSenderMessageKey;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyRecord;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyState;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.protocol.*;
import com.github.auties00.libsignal.util.HKDF;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SignalGroupCipher {
    private static final SecureRandom RANDOM;

    private static final int MAX_MESSAGE_KEYS = 2000;
    private static final byte[] GROUP_INFO = "WhisperGroup".getBytes(StandardCharsets.UTF_8);

    static {
        try {
            RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException error) {
            throw new InternalError("No strong secure random available", error);
        }
    }

    private final SignalProtocolStore store;

    public SignalGroupCipher(SignalProtocolStore store) {
        this.store = store;
    }

    public SignalCiphertextMessage encrypt(SignalSenderKeyName senderKeyId, byte[] paddedPlaintext) {
        try {
            var mac = Mac.getInstance("HmacSHA256");

            var senderKeyState = store.findSenderKeyByName(senderKeyId)
                    .orElseThrow(() -> new SignalMissingSenderKeyException(senderKeyId))
                    .findSenderKeyState()
                    .orElseThrow(() -> new SignalMissingSenderKeyStateException(senderKeyId));

            var senderKey = senderKeyState.senderChainKey();

            var messageKeys = senderKey.toSenderMessageKey(mac);

            var cipher = createCipher(mac, messageKeys, Cipher.ENCRYPT_MODE);
            var ciphertext = cipher.doFinal(paddedPlaintext);

            var senderKeyMessage = new SignalSenderKeyMessageBuilder()
                    .version(SignalCiphertextMessage.CURRENT_VERSION)
                    .id(senderKeyState.id())
                    .iteration(senderKey.iteration())
                    .cipherText(ciphertext)
                    .signaturePrivateKey(senderKeyState.signatureKey().privateKey())
                    .build();

            var nextSenderChainKey = senderKey.next(mac);
            senderKeyState.setSenderChainKey(nextSenderChainKey);

            return senderKeyMessage;
        } catch (GeneralSecurityException exception) {
            throw new SignalEncryptException(exception);
        }
    }

    public byte[] decrypt(SignalSenderKeyName senderKeyId, byte[] senderKeyMessageBytes) {
        try {
            var mac = Mac.getInstance("HmacSHA256");

            var record = store.findSenderKeyByName(senderKeyId)
                    .orElseThrow(() -> new SignalMissingSenderKeyException(senderKeyId));
            var senderKeyMessage = SignalSenderKeyMessage.ofSerialized(senderKeyMessageBytes);
            var senderKeyState = record.findSenderKeyStateById(senderKeyMessage.id())
                    .orElseThrow(() -> new SignalMissingSenderKeyStateException(senderKeyId, senderKeyMessage.id()));
            if (!senderKeyMessage.verifySignature(senderKeyState.signatureKey().publicKey())) {
                throw new SignalDecryptException("Invalid signature!");
            }

            var senderKey = getSenderKey(mac, senderKeyState, senderKeyMessage.iteration());

            var cipher = createCipher(mac, senderKey, Cipher.DECRYPT_MODE);
            return cipher.doFinal(senderKeyMessage.cipherText());
        } catch (GeneralSecurityException exception) {
            throw new SignalDecryptException(exception);
        }
    }

    private Cipher createCipher(Mac mac, SignalSenderMessageKey messageKeys, int mode) throws GeneralSecurityException {
        var chunks = HKDF.deriveSecrets(SignalCiphertextMessage.CURRENT_VERSION, mac, messageKeys.seed(), GROUP_INFO, 48);
        var iv = new IvParameterSpec(chunks, 0, 16);
        var cipherKey = new SecretKeySpec(chunks, 16, 32, "AES");
        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, cipherKey, iv);
        return cipher;
    }

    private SignalSenderMessageKey getSenderKey(Mac mac, SignalSenderKeyState senderKeyState, int iteration) throws NoSuchAlgorithmException {
        var senderChainKey = senderKeyState.senderChainKey();
        var currentSenderChainKey = senderChainKey.iteration();

        if (currentSenderChainKey > iteration) {
            return senderKeyState.removeMessageKey(iteration)
                    .orElseThrow(() -> new SignalDecryptException("Received message with old counter: " + currentSenderChainKey + " , " + iteration));
        }

        if (iteration - currentSenderChainKey > MAX_MESSAGE_KEYS) {
            throw new SignalDecryptException("Over " + MAX_MESSAGE_KEYS + " messages into the future!");
        }

        while (senderChainKey.iteration() < iteration) {
            senderKeyState.addMessageKey(senderChainKey.toSenderMessageKey(mac));
            senderChainKey = senderChainKey.next(mac);
        }

        senderKeyState.setSenderChainKey(senderChainKey.next(mac));
        return senderChainKey.toSenderMessageKey(mac);
    }

    public void process(SignalSenderKeyName senderKeyName, SignalSenderKeyDistributionMessage senderKeyDistributionMessage) {
        var senderKeyRecord = store.findSenderKeyByName(senderKeyName).orElseGet(() -> {
            var record = new SignalSenderKeyRecord();
            store.addSenderKey(senderKeyName, record);
            return record;
        });
        senderKeyRecord.addSenderKeyState(
                senderKeyDistributionMessage.id(),
                senderKeyDistributionMessage.iteration(),
                senderKeyDistributionMessage.chainKey(),
                senderKeyDistributionMessage.signatureKey()
        );
    }

    public SignalSenderKeyDistributionMessage create(SignalSenderKeyName senderKeyName) {
        var senderKeyRecord = store.findSenderKeyByName(senderKeyName).orElseGet(() -> {
            var record = new SignalSenderKeyRecord();
            store.addSenderKey(senderKeyName, record);
            return record;
        });

        if (senderKeyRecord.isEmpty()) {
            var senderKeyId = RANDOM.nextInt(Integer.MAX_VALUE);
            var senderKeyBytes = new byte[32];
            RANDOM.nextBytes(senderKeyBytes);
            var secretKey = new SecretKeySpec(senderKeyBytes, "AES");
            senderKeyRecord.setSenderKeyState(
                    senderKeyId,
                    0,
                    secretKey,
                    SignalIdentityKeyPair.random()
            );
        }

        var state = senderKeyRecord.findSenderKeyState()
                .orElseThrow(() -> new SignalMissingSenderKeyStateException(senderKeyName));

        return new SignalSenderKeyDistributionMessageBuilder()
                .version(SignalCiphertextMessage.CURRENT_VERSION)
                .id(state.id())
                .iteration(state.senderChainKey().iteration())
                .chainKey(state.senderChainKey().seed())
                .signatureKey(state.signatureKey().publicKey())
                .build();
    }
}
