package com.github.auties00.libsignal;

import com.github.auties00.libsignal.kdf.HKDF;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.key.SignalKeyDirection;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalMessage;
import com.github.auties00.libsignal.protocol.SignalPreKeyMessage;
import com.github.auties00.libsignal.ratchet.SignalChainKey;
import com.github.auties00.libsignal.ratchet.SignalMessageKey;
import com.github.auties00.libsignal.state.SignalSessionChain;
import com.github.auties00.libsignal.state.SignalSessionChainBuilder;
import com.github.auties00.libsignal.state.SignalSessionRecord;
import com.github.auties00.libsignal.state.SignalSessionState;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Objects;

public final class SignalSessionCipher {
    private static final int MAX_MESSAGE_KEYS = 2000;

    private final SignalProtocolStore store;
    private final SignalSessionBuilder sessionBuilder;
    private final SignalProtocolAddress remoteAddress;

    public SignalSessionCipher(SignalProtocolStore store, SignalSessionBuilder sessionBuilder, SignalProtocolAddress remoteAddress) {
        this.store = store;
        this.sessionBuilder = sessionBuilder;
        this.remoteAddress = remoteAddress;
    }

    public SignalCiphertextMessage encrypt(byte[] paddedMessage) {
        var sessionRecord = store.findSessionByAddress(remoteAddress)
                .orElseGet(SignalSessionRecord::new);
        var sessionState = sessionRecord.sessionState();
        var sessionChain = sessionState.senderChain()
                .orElseThrow(() -> new IllegalStateException("Uninitialized session!"));
        var chainKey = sessionChain.chainKey();
        var hkdf = HKDF.of(sessionState.sessionVersion());
        var messageKeys = chainKey.toMessageKeys(hkdf);
        var senderEphemeral = sessionChain.senderRatchetKey();
        var previousCounter = sessionState.previousCounter();
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
            var localRegistrationId = sessionState.localRegistrationId();
            ciphertextMessage = new SignalPreKeyMessage(
                    sessionVersion,
                    pendingPreKey.get().preKeyId(),
                    pendingPreKey.get().baseKey(),
                    sessionState.localIdentityPublic(),
                    ciphertextMessage.toSerialized(),
                    localRegistrationId,
                    pendingPreKey.get().signedKeyId()
            );
        }

        sessionChain.setChainKey(chainKey.next());

        if (!store.isTrustedIdentity(remoteAddress, sessionState.remoteIdentityPublic(), SignalKeyDirection.OUTGOING)) {
            throw new SecurityException("Untrusted identity: " + remoteAddress.name());
        }

        store.addTrustedIdentity(remoteAddress, sessionState.remoteIdentityPublic());

        sessionRecord.setFresh(false);
        store.addSession(remoteAddress, sessionRecord);

        return ciphertextMessage;
    }

    public byte[] decrypt(SignalPreKeyMessage ciphertext) {
        var sessionRecord = store.findSessionByAddress(remoteAddress)
                .orElseGet(SignalSessionRecord::new);
        var unsignedPreKeyId = sessionBuilder.process(sessionRecord, ciphertext);
        var plaintext = decrypt(sessionRecord, ciphertext.signalMessage());

        sessionRecord.setFresh(false);
        store.addSession(remoteAddress, sessionRecord);

        if (unsignedPreKeyId.isPresent()) {
            if (!store.removePreKey(unsignedPreKeyId.getAsInt())) {
                throw new InternalError("Key was not removed");
            }
        }

        return plaintext;
    }

    public byte[] decrypt(SignalMessage ciphertext) {
        var sessionRecord = store.findSessionByAddress(remoteAddress)
                .orElseThrow(() -> new SecurityException("No session for: " + remoteAddress));
        var plaintext = decrypt(sessionRecord, ciphertext);
        var theirIdentityKey = sessionRecord.sessionState().remoteIdentityPublic();
        if (!store.isTrustedIdentity(remoteAddress, theirIdentityKey, SignalKeyDirection.INCOMING)) {
            throw new SecurityException("Untrusted identity: " + remoteAddress.name());
        }

        store.addTrustedIdentity(remoteAddress, theirIdentityKey);

        sessionRecord.setFresh(false);
        store.addSession(remoteAddress, sessionRecord);

        return plaintext;
    }

    private byte[] decrypt(SignalSessionRecord sessionRecord, SignalMessage ciphertext) {
        var errors = 0;
        var currentSessionState = sessionRecord.sessionState();
        var currentSessionResult = tryDecrypt(currentSessionState, ciphertext);
        if(currentSessionResult != null) {
            sessionRecord.setState(currentSessionState);
            return currentSessionResult;
        }

        errors++;

        for (var promotedState : sessionRecord.previousSessionStates()) {
            var promotedStateResult = tryDecrypt(promotedState, ciphertext);
            if(promotedStateResult != null) {
                sessionRecord.promoteState(promotedState);
                return promotedStateResult;
            }
        }

        throw new SecurityException("No valid sessions. Errors: " + errors);
    }

    private byte[] tryDecrypt(SignalSessionState state, SignalMessage ciphertext) {
        // Store all the data that could change
        var savedSessionVersion = state.sessionVersion();
        var savedLocalIdentityPublic = state.localIdentityPublic();
        var savedRemoteIdentityPublic = state.remoteIdentityPublic();
        var savedRootKey = state.rootKey();
        var savedPreviousCounter = state.previousCounter();
        var savedRemoteRegistrationId = state.remoteRegistrationId();
        var savedLocalRegistrationId = state.localRegistrationId();
        var savedNeedsRefresh = state.needsRefresh();
        var savedPendingKeyExchange = state.pendingKeyExchange();
        var savedPendingPreKey = state.pendingPreKey().orElse(null);
        var savedBaseKey = state.baseKey() != null ? state.baseKey().clone() : null;
        var savedSenderChain = state.senderChain().orElse(null);
        var savedSenderChainKey = state.senderChain().map(SignalSessionChain::chainKey).orElse(null);
        var savedReceiverChains = new ArrayList<SignalSessionChain>();
        var savedReceiverChainKeys = new ArrayList<SignalChainKey>();
        var savedReceiverChainsMessageKeys = new ArrayList<ArrayList<SignalMessageKey>>();
        for (var chain : state.receiverChains()) {
            savedReceiverChains.add(chain);
            savedReceiverChainKeys.add(chain.chainKey());
            savedReceiverChainsMessageKeys.add(new ArrayList<>(chain.messageKeys()));
        }

        try {
            return decrypt(state, ciphertext);
        } catch (Throwable e) {
            state.setSessionVersion(savedSessionVersion);
            state.setLocalIdentityPublic(savedLocalIdentityPublic);
            state.setRemoteIdentityPublic(savedRemoteIdentityPublic);
            state.setRootKey(savedRootKey);
            state.setPreviousCounter(savedPreviousCounter);
            state.setRemoteRegistrationId(savedRemoteRegistrationId);
            state.setLocalRegistrationId(savedLocalRegistrationId);
            state.setNeedsRefresh(savedNeedsRefresh);
            state.setPendingKeyExchange(savedPendingKeyExchange);
            state.setPendingPreKey(savedPendingPreKey);
            state.setBaseKey(savedBaseKey);
            if (savedSenderChain != null) {
                savedSenderChain.setChainKey(savedSenderChainKey);
            }
            state.setSenderChain(savedSenderChain);
            for (var i = 0; i < savedReceiverChains.size(); i++) {
                var chain = savedReceiverChains.get(i);

                var originalChainKey = savedReceiverChainKeys.get(i);
                chain.setChainKey(originalChainKey);

                var originalMessageKeysMap = savedReceiverChainsMessageKeys.get(i);
                chain.setMessageKeys(originalMessageKeysMap);
            }
            state.setReceiverChains(savedReceiverChains);
            return null;
        }
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
        var counter = ciphertextMessage.counter();
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
                    var hkdf = HKDF.of(sessionState.sessionVersion());
                    var rootKey = sessionState.rootKey();
                    var ourEphemeral = sessionState.senderChain()
                            .orElseThrow(() -> new IllegalStateException("Uninitialized session!"))
                            .senderRatchetKeyPrivate();
                    var receiverChain = rootKey.createChain(hkdf, ourEphemeral, theirEphemeral);
                    var ourNewEphemeral = SignalIdentityKeyPair.random();
                    var senderChain = receiverChain.rootKey()
                            .createChain(hkdf, ourNewEphemeral.privateKey(), theirEphemeral);
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
                    return receiverChain.chainKey();
                });
    }

    private SignalMessageKey getOrCreateMessageKeys(SignalSessionState sessionState,
                                                    SignalIdentityPublicKey theirEphemeral,
                                                    SignalChainKey chainKey, int counter) {
        var receiverChain = sessionState.findReceiverChain(theirEphemeral)
                .orElseThrow(() -> new IllegalStateException("No receiver chain found"));
        if (chainKey.index() > counter) {
            return receiverChain.removeMessageKey(counter)
                    .orElseThrow(() -> new SecurityException("Received message with old counter: " + chainKey.index() + " , " + counter));
        }

        if (counter - chainKey.index() > MAX_MESSAGE_KEYS) {
            throw new SecurityException("Over " + MAX_MESSAGE_KEYS + " messages into the future!");
        }

        var hkdf = HKDF.of(sessionState.sessionVersion());
        var currentChainKey = chainKey;
        while (currentChainKey.index() < counter) {
            var messageKeys = currentChainKey.toMessageKeys(hkdf);
            receiverChain.addMessageKey(messageKeys);
            currentChainKey = currentChainKey.next();
        }

        receiverChain.setChainKey(currentChainKey.next());
        return currentChainKey.toMessageKeys(hkdf);
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