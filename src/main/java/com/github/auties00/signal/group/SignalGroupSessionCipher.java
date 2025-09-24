package com.github.auties00.signal.group;

import com.github.auties00.signal.SignalStore;
import com.github.auties00.signal.group.ratchet.SignalSenderMessageKey;
import com.github.auties00.signal.group.state.SignalSenderKeyRecord;
import com.github.auties00.signal.group.state.SignalSenderKeyState;
import com.github.auties00.signal.protocol.SignalCiphertextMessage;
import com.github.auties00.signal.protocol.SignalSenderKeyMessage;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public final class SignalGroupSessionCipher {
    private static final int MAX_MESSAGE_KEYS = 2000;

    private final SignalStore store;
    private final SignalSenderKeyName senderKeyId;
    private final Cipher cipher;

    public SignalGroupSessionCipher(SignalStore store, SignalSenderKeyName senderKeyId) {
        this.store = store;
        this.senderKeyId = senderKeyId;
        try {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }catch(NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new RuntimeException("Cannot initialize cipher", exception);
        }
    }

    public byte[] encrypt(byte[] paddedPlaintext) {
        try {
            var record = store.findSenderKeyByName(senderKeyId).orElseGet(() -> {
                var newRecord = new SignalSenderKeyRecord();
                store.addSenderKey(senderKeyId, newRecord);
                return newRecord;
            });
            var senderKeyState = record.findSenderKeyState()
                    .orElseThrow(() -> new IllegalStateException("No sender key state found"));
            var senderKey = senderKeyState.chainKey().toSenderMessageKey();
            cipher.init(Cipher.ENCRYPT_MODE, senderKey.cipherKey(), senderKey.iv());
            var ciphertext = cipher.doFinal(paddedPlaintext);

            var senderKeyMessage = new SignalSenderKeyMessage(
                    SignalCiphertextMessage.CURRENT_VERSION,
                    senderKeyState.id(),
                    senderKey.iteration(),
                    ciphertext,
                    senderKeyState.signatureKey().privateKey()
            );

            senderKeyState.setChainKey(senderKeyState.chainKey().next());

            return senderKeyMessage.toSerialized();
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot encrypt message", exception);
        }
    }

    public byte[] decrypt(byte[] senderKeyMessageBytes) {
        try {
            var record = store.findSenderKeyByName(senderKeyId).orElseGet(() -> {
                var newRecord = new SignalSenderKeyRecord();
                store.addSenderKey(senderKeyId, newRecord);
                return newRecord;
            });

            if (record.isEmpty()) {
                throw new SecurityException("No sender key for: " + senderKeyId);
            }

            var senderKeyMessage = SignalSenderKeyMessage.ofSerialized(senderKeyMessageBytes);
            var senderKeyState = record.findSenderKeyStateById(senderKeyMessage.id())
                    .orElseThrow(() -> new SecurityException("Cannot find sender key state with id " + senderKeyMessage.id()));
            if (!senderKeyMessage.verifySignature(senderKeyState.signatureKey().publicKey())) {
                throw new GeneralSecurityException("Invalid signature!");
            }

            var senderKey = getSenderKey(senderKeyState, senderKeyMessage.iteration());
            cipher.init(Cipher.DECRYPT_MODE, senderKey.cipherKey(), senderKey.iv());
            return cipher.doFinal(senderKeyMessage.cipherText());
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot decrypt message", exception);
        }
    }

    private SignalSenderMessageKey getSenderKey(SignalSenderKeyState senderKeyState, int iteration) {
        var senderChainKey = senderKeyState.chainKey();
        var currentSenderChainKey = senderChainKey.iteration();

        if (currentSenderChainKey > iteration) {
            return senderKeyState.removeMessageKey(iteration)
                    .orElseThrow(() -> new SecurityException("Received message with old counter: " + currentSenderChainKey + " , " + iteration));
        }

        if (iteration - currentSenderChainKey > MAX_MESSAGE_KEYS) {
            throw new SecurityException("Over " + MAX_MESSAGE_KEYS + " messages into the future!");
        }

        while (senderChainKey.iteration() < iteration) {
            senderKeyState.addMessageKey(senderChainKey.toSenderMessageKey());
            senderChainKey = senderChainKey.next();
        }

        senderKeyState.setChainKey(senderChainKey.next());
        return senderChainKey.toSenderMessageKey();
    }
}
