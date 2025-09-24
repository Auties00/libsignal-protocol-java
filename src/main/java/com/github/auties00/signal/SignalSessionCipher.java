package com.github.auties00.signal;

import com.github.auties00.signal.key.SignalIdentityKeyPair;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import com.github.auties00.signal.key.SignalKeyDirection;
import com.github.auties00.signal.protocol.SignalCiphertextMessage;
import com.github.auties00.signal.protocol.SignalMessage;
import com.github.auties00.signal.protocol.SignalPreKeyMessage;
import com.github.auties00.signal.ratchet.SignalChainKey;
import com.github.auties00.signal.ratchet.SignalMessageKey;
import com.github.auties00.signal.state.SignalSessionChain;
import com.github.auties00.signal.state.SignalSessionChainBuilder;
import com.github.auties00.signal.state.SignalSessionRecord;
import com.github.auties00.signal.state.SignalSessionState;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Objects;

public final class SignalSessionCipher {
    private static final int MAX_MESSAGE_KEYS = 2000;

    private final SignalDataStore keys;
    private final SignalSessionBuilder sessionBuilder;
    private final SignalAddress remoteAddress;

    public SignalSessionCipher(SignalDataStore store, SignalSessionBuilder sessionBuilder, SignalAddress remoteAddress) {
        this.keys = store;
        this.sessionBuilder = sessionBuilder;
        this.remoteAddress = remoteAddress;
    }

    public byte[] encrypt(byte[] paddedMessage) {
        var sessionRecord = keys.findSessionByAddress(remoteAddress).orElseGet(() -> {
            var record = new SignalSessionRecord();
            keys.addSession(remoteAddress, record);
            return record;
        });
        var sessionState = sessionRecord.sessionState();
        var sessionChain = sessionState.senderChain()
                .orElseThrow(() -> new IllegalStateException("Uninitialized session!"));
        var chainKey = sessionChain.chainKey();
        var messageKeys = chainKey.toMessageKeys();
        var senderEphemeral = sessionChain.senderRatchetKey();
        int previousCounter = sessionState.previousCounter();
        var sessionVersion = sessionState.sessionVersion();

        var ciphertextBody = getCiphertext(messageKeys, paddedMessage);
        SignalCiphertextMessage ciphertextMessage = new SignalMessage(
                sessionVersion,
                senderEphemeral,
                chainKey.index(),
                previousCounter,
                ciphertextBody,
                sessionState.localIdentityPublic(),
                sessionState.remoteIdentityPublic(),
                messageKeys.macKey()
        );
        var pendingPreKey = sessionState.pendingPreKey();
        if (pendingPreKey.isPresent()) {
            int localRegistrationId = sessionState.localRegistrationId();
            ciphertextMessage = new SignalPreKeyMessage(
                    sessionVersion,
                    localRegistrationId,
                    pendingPreKey.get().baseKey(),
                    sessionState.localIdentityPublic(),
                    ciphertextMessage.toSerialized(),
                    pendingPreKey.get().preKeyId(),
                    pendingPreKey.get().signedKeyId()
            );
        }

        sessionChain
                .setChainKey(chainKey.next());

        if (!keys.hasTrust(remoteAddress, sessionState.remoteIdentityPublic(), SignalKeyDirection.OUTGOING)) {
            throw new SecurityException("Untrusted identity: " + remoteAddress.name());
        }

        return ciphertextMessage.toSerialized();
    }

    public byte[] decrypt(SignalPreKeyMessage ciphertext) {
        var sessionRecord = keys.findSessionByAddress(remoteAddress).orElseGet(() -> {
            var record = new SignalSessionRecord();
            keys.addSession(remoteAddress, record);
            return record;
        });
        var unsignedPreKeyId = sessionBuilder.process(sessionRecord, ciphertext);
        var plaintext = decrypt(sessionRecord, ciphertext.signalMessage());

        if (unsignedPreKeyId.isPresent()) {
            if (!keys.removePreKey(unsignedPreKeyId.getAsInt())) {
                throw new InternalError("Key was not removed");
            }
        }

        return plaintext;
    }

    public byte[] decrypt(SignalMessage ciphertext) {
        var sessionRecord = keys.findSessionByAddress(remoteAddress)
                .orElseThrow(() -> new SecurityException("No session for: " + remoteAddress));
        var plaintext = decrypt(sessionRecord, ciphertext);
        if (!keys.hasTrust(remoteAddress, sessionRecord.sessionState().remoteIdentityPublic(), SignalKeyDirection.INCOMING)) {
            throw new SecurityException("Untrusted identity: " + remoteAddress.name());
        }
        return plaintext;
    }

    private byte[] decrypt(SignalSessionRecord sessionRecord, SignalMessage ciphertext) {
        var previousStates = sessionRecord.previousSessionStates().iterator();
        var exceptions = new ArrayList<Exception>();

        try {
            var sessionState = sessionRecord.sessionState();
            var plaintext = decrypt(sessionState, ciphertext);

            sessionRecord.setState(sessionState);
            return plaintext;
        } catch (RuntimeException e) {
            exceptions.add(e);
        }

        while (previousStates.hasNext()) {
            try {
                var promotedState = previousStates.next();
                var plaintext = decrypt(promotedState, ciphertext);

                previousStates.remove();
                sessionRecord.promoteState(promotedState);

                return plaintext;
            } catch (RuntimeException e) {
                exceptions.add(e);
            }
        }

        throw new SecurityException("No valid sessions. Errors: " + exceptions.size());
    }

    private byte[] decrypt(SignalSessionState sessionState, SignalMessage ciphertextMessage) {
        if (sessionState.senderChain().isEmpty()) {
            throw new IllegalStateException("Uninitialized session!");
        }

        if (!Objects.equals(ciphertextMessage.version(), sessionState.sessionVersion())) {
            throw new SecurityException(String.format("Message version %d, but session version %d",
                    ciphertextMessage.version(),
                    sessionState.sessionVersion()));
        }

        var theirEphemeral = ciphertextMessage.senderRatchetKey();
        int counter = ciphertextMessage.counter();
        var chainKey = getOrCreateChainKey(sessionState, theirEphemeral);
        var messageKeys = getOrCreateMessageKeys(sessionState, theirEphemeral, chainKey, counter);

        ciphertextMessage.verifyMac(sessionState.remoteIdentityPublic(),
                sessionState.localIdentityPublic(),
                messageKeys.macKey());

        var plaintext = getPlaintext(messageKeys, ciphertextMessage.ciphertext());

        sessionState.setPendingPreKey(null);

        return plaintext;
    }

    private SignalChainKey getOrCreateChainKey(SignalSessionState sessionState, SignalIdentityPublicKey theirEphemeral) {
        return sessionState.findReceiverChain(theirEphemeral)
                .map(SignalSessionChain::chainKey)
                .orElseGet(() -> {
                    var rootKey = sessionState.rootKey();
                    var ourEphemeral = sessionState.senderChain()
                            .orElseThrow(() -> new IllegalStateException("Uninitialized session!"))
                            .senderRatchetKeyPrivate();
                    var receiverChain = rootKey.createChain(theirEphemeral, ourEphemeral);
                    var ourNewEphemeral = SignalIdentityKeyPair.random();
                    var senderChain = receiverChain.rootKey()
                            .createChain(theirEphemeral, ourNewEphemeral.privateKey());
                    sessionState.setRootKey(senderChain.rootKey());
                    var sessionReceiverChain = new SignalSessionChainBuilder()
                            .senderRatchetKey(theirEphemeral)
                            .chainKey(receiverChain.chainKey())
                            .build();
                    sessionState.addReceiverChain(sessionReceiverChain);
                    var previousCounter = sessionState.senderChain()
                            .map(SignalSessionChain::chainKey)
                            .map(entry -> entry.index() <= 0 ? 0 : entry.index() - 1)
                            .orElse(0);
                    sessionState.setPreviousCounter(previousCounter);
                    var sessionSenderChain = new SignalSessionChainBuilder()
                            .senderRatchetKey(ourNewEphemeral.publicKey())
                            .senderRatchetKeyPrivate(ourNewEphemeral.privateKey())
                            .chainKey(senderChain.chainKey())
                            .build();
                    sessionState.setSenderChain(sessionSenderChain);
                    return senderChain.chainKey();
                });
    }

    private SignalMessageKey getOrCreateMessageKeys(SignalSessionState sessionState,
                                                    SignalIdentityPublicKey theirEphemeral,
                                                    SignalChainKey chainKey, int counter) {
        var receiverChain = sessionState.findReceiverChain(theirEphemeral)
                .orElseThrow(() -> new IllegalStateException("No receiver chain found"));
        if (chainKey.index() > counter) {
            if (receiverChain.removeMessageKey(counter).isEmpty()) {
                throw new SecurityException("Received message with old counter: " + chainKey.index() + " , " + counter);
            }
        }

        if (counter - chainKey.index() > MAX_MESSAGE_KEYS) {
            throw new SecurityException("Over " + MAX_MESSAGE_KEYS + " messages into the future!");
        }

        while (chainKey.index() < counter) {
            var messageKeys = chainKey.toMessageKeys();
            receiverChain.addMessageKey(messageKeys);
            chainKey = chainKey.next();
        }

        receiverChain.setChainKey(chainKey.next());
        return chainKey.toMessageKeys();
    }

    private byte[] getCiphertext(SignalMessageKey messageKeys, byte[] plaintext) {
        try {
            var cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.cipherKey(), messageKeys.iv());
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    private byte[] getPlaintext(SignalMessageKey messageKeys, byte[] cipherText) {
        try {
            var cipher = getCipher(Cipher.DECRYPT_MODE, messageKeys.cipherKey(), messageKeys.iv());
            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Decryption failed", e);
        }
    }

    private Cipher getCipher(int mode, byte[] key, byte[] iv) {
        try {
            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(
                    mode,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv)
            );
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Cannot initialize cipher", e);
        }
    }
}