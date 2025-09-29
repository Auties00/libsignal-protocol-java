package com.github.auties00.libsignal;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.kdf.HKDF;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.key.SignalKeyDirection;
import com.github.auties00.libsignal.protocol.*;
import com.github.auties00.libsignal.ratchet.*;
import com.github.auties00.libsignal.state.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Objects;
import java.util.OptionalInt;

public final class SignalSessionCipher {
    private static final int MAX_MESSAGE_KEYS = 2000;

    private final SignalProtocolStore store;
    private final Cipher cipher;
    private final Mac mac;

    public SignalSessionCipher(SignalProtocolStore store) {
        this.store = store;
        try {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            this.mac = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new InternalError(e);
        }
    }

    public SignalCiphertextMessage encrypt(SignalProtocolAddress remoteAddress, byte[] paddedMessage) {
        var sessionRecord = store.findSessionByAddress(remoteAddress)
                .orElseThrow(() -> new SecurityException("No session for: " + remoteAddress));
        var sessionState = sessionRecord.sessionState();
        var sessionChain = sessionState.senderChain()
                .orElseThrow(() -> new IllegalStateException("Uninitialized session for " + remoteAddress));
        var chainKey = sessionChain.chainKey();
        var hkdf = HKDF.of(sessionState.sessionVersion());
        var messageKeys = chainKey.toMessageKeys(hkdf, mac);
        var senderEphemeral = sessionChain.senderRatchetKey();
        var previousCounter = sessionState.previousCounter();
        var sessionVersion = sessionState.sessionVersion();

        var ciphertextBody = getCiphertext(messageKeys, paddedMessage);
        SignalCiphertextMessage ciphertextMessage = new SignalMessageBuilder()
                .version(sessionVersion)
                .senderRatchetKey(senderEphemeral)
                .counter(chainKey.index())
                .previousCounter(previousCounter)
                .ciphertext(ciphertextBody)
                .localIdentityKey(sessionState.localIdentityPublic())
                .remoteIdentityKey(sessionState.remoteIdentityPublic())
                .macKey(messageKeys.macKey())
                .build();
        var pendingPreKey = sessionState.pendingPreKey();
        if (pendingPreKey.isPresent()) {
            var localRegistrationId = sessionState.localRegistrationId();
            ciphertextMessage = new SignalPreKeyMessageBuilder()
                    .version(sessionVersion)
                    .preKeyId(pendingPreKey.get().preKeyId())
                    .baseKey(pendingPreKey.get().baseKey())
                    .identityKey(sessionState.localIdentityPublic())
                    .serializedSignalMessage(ciphertextMessage.toSerialized())
                    .registrationId(localRegistrationId)
                    .signedPreKeyId(pendingPreKey.get().signedKeyId())
                    .build();
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

    public byte[] decrypt(SignalProtocolAddress remoteAddress, SignalPreKeyMessage ciphertext) {
        var sessionRecord = store.findSessionByAddress(remoteAddress)
                .orElseGet(SignalSessionRecord::new);
        var unsignedPreKeyId = process(remoteAddress, sessionRecord, ciphertext);
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

    public byte[] decrypt(SignalProtocolAddress remoteAddress, SignalMessage ciphertext) {
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
                    var receiverChain = rootKey.createChain(hkdf, mac, ourEphemeral, theirEphemeral);
                    var ourNewEphemeral = SignalIdentityKeyPair.random();
                    var senderChain = receiverChain.rootKey()
                            .createChain(hkdf, mac, ourNewEphemeral.privateKey(), theirEphemeral);
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
            var messageKeys = currentChainKey.toMessageKeys(hkdf, mac);
            receiverChain.addMessageKey(messageKeys);
            currentChainKey = currentChainKey.next(mac);
        }

        receiverChain.setChainKey(currentChainKey.next(mac));
        return currentChainKey.toMessageKeys(hkdf, mac);
    }

    private byte[] getCiphertext(SignalMessageKey messageKeys, byte[] plaintext) {
        try {
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    messageKeys.cipherKey(),
                    messageKeys.iv()
            );
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    private byte[] getPlaintext(SignalMessageKey messageKeys, byte[] cipherText) {
        try {
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    messageKeys.cipherKey(),
                    messageKeys.iv()
            );
            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Decryption failed", e);
        }
    }

    private OptionalInt process(SignalProtocolAddress remoteAddress, SignalSessionRecord sessionRecord, SignalPreKeyMessage message) {
        var theirIdentityKey = message.identityKey();
        if (!store.isTrustedIdentity(remoteAddress, theirIdentityKey, SignalKeyDirection.INCOMING)) {
            throw new SecurityException("The identity key of the incoming message is not trusted");
        }

        var unsignedPreKeyId = processV3(remoteAddress, sessionRecord, message);
        store.addTrustedIdentity(remoteAddress, theirIdentityKey);
        return unsignedPreKeyId;
    }

    private OptionalInt processV3(SignalProtocolAddress remoteAddress, SignalSessionRecord sessionRecord, SignalPreKeyMessage message) {
        if (sessionRecord.hasSessionState(message.version(), message.baseKey().toSerialized())) {
            return OptionalInt.empty();
        }

        var ourSignedPreKey = store.findSignedPreKeyById(message.signedPreKeyId())
                .orElseThrow(() -> new IllegalStateException("No signed prekey found with id " + message.signedPreKeyId()));
        var parameters = new SignalBobParametersBuilder()
                .theirBaseKey(message.baseKey())
                .theirIdentityKey(message.identityKey())
                .ourIdentityKey(store.identityKeyPair())
                .ourSignedPreKey(ourSignedPreKey.keyPair())
                .ourRatchetKey(ourSignedPreKey.keyPair());

        message.preKeyId().ifPresent(preKeyId -> {
            var preKey = store.findPreKeyById(preKeyId)
                    .orElseThrow(() -> new IllegalStateException("No prekey found with id " + preKeyId));
            parameters.ourOneTimePreKey(preKey.keyPair());
        });

        if (!sessionRecord.isFresh()) {
            sessionRecord.archiveCurrentState();
        }

        SignalRatchetingSession.initializeSession(mac, sessionRecord.sessionState(), parameters.build());

        sessionRecord.sessionState()
                .setLocalRegistrationId(store.registrationId());
        sessionRecord.sessionState()
                .setRemoteRegistrationId(message.registrationId());
        sessionRecord.sessionState()
                .setBaseKey(message.baseKey().toSerialized());

        return message.preKeyId();
    }

    public void process(SignalProtocolAddress remoteAddress, SignalPreKeyBundle preKey) {
        if (!store.isTrustedIdentity(remoteAddress, preKey.identityKey(), SignalKeyDirection.OUTGOING)) {
            throw new SecurityException("The identity key of the incoming message is not trusted");
        }

        var theirSignedPreKey = preKey.signedPreKeyPublic();
        if (preKey.signedPreKeyPublic() == null) {
            throw new SecurityException("No signed prekey!");
        }

        if (!Curve25519.verifySignature(preKey.identityKey().toEncodedPoint(),
                theirSignedPreKey.toSerialized(),
                preKey.signedPreKeySignature())) {
            throw new SecurityException("Invalid signature on device key!");
        }

        var sessionRecord = store.findSessionByAddress(remoteAddress)
                .orElseGet(SignalSessionRecord::new);

        var ourBaseKey = SignalIdentityKeyPair.random();

        var theirOneTimePreKey = preKey.preKeyPublic();
        var theirOneTimePreKeyId = theirOneTimePreKey != null ? preKey.preKeyId() : null;

        var parameters = new SignalAliceParametersBuilder()
                .ourBaseKey(ourBaseKey)
                .ourIdentityKey(store.identityKeyPair())
                .theirIdentityKey(preKey.identityKey())
                .theirSignedPreKey(theirSignedPreKey)
                .theirRatchetKey(theirSignedPreKey)
                .theirOneTimePreKey(theirOneTimePreKey);

        if (!sessionRecord.isFresh()) {
            sessionRecord.archiveCurrentState();
        }

        SignalRatchetingSession.initializeSession(mac, sessionRecord.sessionState(), parameters.build());

        var pendingPreKey = new SignalPendingPreKeyBuilder()
                .preKeyId(theirOneTimePreKeyId)
                .signedKeyId(preKey.signedPreKeyId())
                .baseKey(ourBaseKey.publicKey())
                .build();

        sessionRecord.sessionState()
                .setPendingPreKey(pendingPreKey);
        sessionRecord.sessionState()
                .setLocalRegistrationId(store.registrationId());
        sessionRecord.sessionState()
                .setRemoteRegistrationId(preKey.registrationId());
        sessionRecord.sessionState()
                .setBaseKey(ourBaseKey.publicKey().toSerialized());

        store.addTrustedIdentity(remoteAddress, preKey.identityKey());

        sessionRecord.setFresh(false);
        store.addSession(remoteAddress, sessionRecord);
    }
}