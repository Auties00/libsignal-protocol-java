package com.github.auties00.libsignal.groups;

import com.github.auties00.libsignal.SignalProtocolStore;
import com.github.auties00.libsignal.groups.ratchet.SignalSenderMessageKey;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyState;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalSenderKeyMessage;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public final class SignalGroupCipher {
    private static final int MAX_MESSAGE_KEYS = 2000;

    private final SignalProtocolStore store;
    private final Cipher cipher;

    public SignalGroupCipher(SignalProtocolStore store) {
        this.store = store;
        try {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new RuntimeException("Cannot initialize cipher", exception);
        }
    }

    public SignalCiphertextMessage encrypt(SignalSenderKeyName senderKeyId, byte[] paddedPlaintext) {
        try {
            var senderKeyState = store.findSenderKeyByName(senderKeyId)
                    .orElseThrow(() -> new IllegalArgumentException("Sender key not found: " + senderKeyId))
                    .findSenderKeyState()
                    .orElseThrow(() -> new IllegalArgumentException("Sender key state not found: " + senderKeyId));

            var senderKey = senderKeyState.senderChainKey()
                    .toSenderMessageKey();
            cipher.init(Cipher.ENCRYPT_MODE, senderKey.cipherKey(), senderKey.iv());
            var ciphertext = cipher.doFinal(paddedPlaintext);

            var senderKeyMessage = new SignalSenderKeyMessage(
                    SignalCiphertextMessage.CURRENT_VERSION,
                    senderKeyState.id(),
                    senderKey.iteration(),
                    ciphertext,
                    senderKeyState.signatureKey().privateKey()
            );

            senderKeyState.setSenderChainKey(senderKeyState.senderChainKey().next());

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

    private SignalSenderMessageKey getSenderKey(SignalSenderKeyState senderKeyState, int iteration) {
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
            senderKeyState.addMessageKey(senderChainKey.toSenderMessageKey());
            senderChainKey = senderChainKey.next();
        }

        senderKeyState.setSenderChainKey(senderChainKey.next());
        return senderChainKey.toSenderMessageKey();
    }
}
