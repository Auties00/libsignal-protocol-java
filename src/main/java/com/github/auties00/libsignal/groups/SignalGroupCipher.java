package com.github.auties00.libsignal.groups;

import com.github.auties00.libsignal.SignalProtocolStore;
import com.github.auties00.libsignal.groups.ratchet.SignalSenderMessageKey;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyRecord;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyState;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.protocol.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Random;

public final class SignalGroupCipher {
    private static final int MAX_MESSAGE_KEYS = 2000;

    private final SignalProtocolStore store;
    private final Random random;
    private final Cipher cipher;
    private final Mac mac;

    public SignalGroupCipher(SignalProtocolStore store) {
        this.store = store;
        try {
            this.random = SecureRandom.getInstanceStrong();
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            this.mac = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new InternalError(e);
        }
    }

    public SignalCiphertextMessage encrypt(SignalSenderKeyName senderKeyId, byte[] paddedPlaintext) {
        try {
            var senderKeyState = store.findSenderKeyByName(senderKeyId)
                    .orElseThrow(() -> new IllegalArgumentException("Sender key not found: " + senderKeyId))
                    .findSenderKeyState()
                    .orElseThrow(() -> new IllegalArgumentException("Sender key state not found: " + senderKeyId));

            var senderKey = senderKeyState.senderChainKey();

            var messageKeys = senderKey.toSenderMessageKey(mac);
            cipher.init(Cipher.ENCRYPT_MODE, messageKeys.cipherKey(), messageKeys.iv());
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
            throw new RuntimeException("Cannot encrypt message", exception);
        }
    }

    public byte[] decrypt(SignalSenderKeyName senderKeyId, byte[] senderKeyMessageBytes) {
        try {
            var record = store.findSenderKeyByName(senderKeyId)
                    .orElseThrow(() -> new SecurityException("No sender key for: " + senderKeyId));
            var senderKeyMessage = SignalSenderKeyMessage.ofSerialized(senderKeyMessageBytes);
            var senderKeyState = record.findSenderKeyStateById(senderKeyMessage.id())
                    .orElseThrow(() -> new SecurityException("Cannot find sender key state with id " + senderKeyMessage.id()));
            if (!senderKeyMessage.verifySignature(senderKeyState.signatureKey().publicKey())) {
                throw new SignatureException("Invalid signature!");
            }
            var senderKey = getSenderKey(senderKeyState, senderKeyMessage.iteration());
            cipher.init(Cipher.DECRYPT_MODE, senderKey.cipherKey(), senderKey.iv());
            return cipher.doFinal(senderKeyMessage.cipherText());
        } catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot decrypt message", exception);
        }
    }

    private SignalSenderMessageKey getSenderKey(SignalSenderKeyState senderKeyState, int iteration) throws NoSuchAlgorithmException {
        var senderChainKey = senderKeyState.senderChainKey();
        var currentSenderChainKey = senderChainKey.iteration();

        if (currentSenderChainKey > iteration) {
            return senderKeyState.removeMessageKey(iteration)
                    .orElseThrow(() -> new SecurityException("Received message with old counter: " + currentSenderChainKey + " , " + iteration));
        }

        if (iteration - currentSenderChainKey > MAX_MESSAGE_KEYS) {
            throw new SecurityException("Over " + MAX_MESSAGE_KEYS + " messages into the future!");
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
            var senderKeyId = random.nextInt(Integer.MAX_VALUE);
            var senderKeyBytes = new byte[32];
            random.nextBytes(senderKeyBytes);
            var secretKey = new SecretKeySpec(senderKeyBytes, "AES");
            senderKeyRecord.setSenderKeyState(
                    senderKeyId,
                    0,
                    secretKey,
                    SignalIdentityKeyPair.random()
            );
        }

        var state = senderKeyRecord.findSenderKeyState()
                .orElseThrow(() -> new IllegalStateException("No sender key state found"));

        return new SignalSenderKeyDistributionMessageBuilder()
                .version(SignalCiphertextMessage.CURRENT_VERSION)
                .id(state.id())
                .iteration(state.senderChainKey().iteration())
                .chainKey(state.senderChainKey().seed())
                .signatureKey(state.signatureKey().publicKey())
                .build();
    }
}
