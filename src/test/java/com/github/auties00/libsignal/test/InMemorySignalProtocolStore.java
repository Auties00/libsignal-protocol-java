package com.github.auties00.libsignal.test;

import com.github.auties00.libsignal.SignalProtocolAddress;
import com.github.auties00.libsignal.SignalProtocolStore;
import com.github.auties00.libsignal.groups.SignalSenderKeyName;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyRecord;
import com.github.auties00.libsignal.key.*;
import com.github.auties00.libsignal.state.SignalSessionRecord;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ThreadLocalRandom;

public class InMemorySignalProtocolStore implements SignalProtocolStore {
    private final int registrationId;
    private final SignalIdentityKeyPair identityKeyPair;
    private final ConcurrentMap<SignalProtocolAddress, SignalSessionRecord> sessions;
    private final ConcurrentMap<SignalSenderKeyName, SignalSenderKeyRecord> senderKeys;
    private final ConcurrentMap<Integer, SignalSignedKeyPair> signedPreKeys;
    private final ConcurrentMap<Integer, SignalPreKeyPair> preKeys;
    private final ConcurrentMap<SignalProtocolAddress, SignalIdentityPublicKey> trustedIdentities;

    public InMemorySignalProtocolStore() {
        this.registrationId = ThreadLocalRandom.current().nextInt(16380) + 1;
        this.identityKeyPair = SignalIdentityKeyPair.random();
        this.sessions = new ConcurrentHashMap<>();
        this.senderKeys = new ConcurrentHashMap<>();
        this.signedPreKeys = new ConcurrentHashMap<>();
        this.preKeys = new ConcurrentHashMap<>();
        this.trustedIdentities = new ConcurrentHashMap<>();
    }

    @Override
    public int registrationId() {
        return registrationId;
    }

    @Override
    public SignalIdentityKeyPair identityKeyPair() {
        return identityKeyPair;
    }

    @Override
    public Optional<SignalSessionRecord> findSessionByAddress(SignalProtocolAddress remoteAddress) {
        return Optional.ofNullable(sessions.get(remoteAddress));
    }

    @Override
    public void addSession(SignalProtocolAddress remoteAddress, SignalSessionRecord record) {
        sessions.put(remoteAddress, record);
    }

    @Override
    public Optional<SignalSenderKeyRecord> findSenderKeyByName(SignalSenderKeyName senderKeyName) {
        return Optional.ofNullable(senderKeys.get(senderKeyName));
    }

    @Override
    public void addSenderKey(SignalSenderKeyName senderKeyName, SignalSenderKeyRecord record) {
        senderKeys.put(senderKeyName, record);
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress remoteAddress, SignalIdentityPublicKey theirIdentityKey, SignalKeyDirection direction) {
        var publicKey = trustedIdentities.get(remoteAddress);
        return publicKey == null || publicKey.equals(theirIdentityKey);
    }

    @Override
    public boolean addTrustedIdentity(SignalProtocolAddress remoteAddress, SignalIdentityPublicKey identityKey) {
        var existing = trustedIdentities.get(remoteAddress);
        if (!identityKey.equals(existing)) {
            trustedIdentities.put(remoteAddress, identityKey);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public Optional<SignalSignedKeyPair> findSignedPreKeyById(Integer id) {
        return Optional.ofNullable(signedPreKeys.get(id));
    }

    @Override
    public void addSignedPreKey(SignalSignedKeyPair signedKeyPair) {
        signedPreKeys.put(signedKeyPair.id(), signedKeyPair);
    }

    @Override
    public Optional<SignalPreKeyPair> findPreKeyById(Integer preKeyId) {
        return Optional.ofNullable(preKeys.get(preKeyId));
    }

    @Override
    public void addPreKey(SignalPreKeyPair preKeyPair) {
        preKeys.put(preKeyPair.id(), preKeyPair);
    }

    @Override
    public boolean removePreKey(int preKeyId) {
        return preKeys.remove(preKeyId) != null;
    }
}