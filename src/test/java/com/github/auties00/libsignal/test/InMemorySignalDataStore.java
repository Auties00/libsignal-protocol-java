package com.github.auties00.libsignal.test;

import com.github.auties00.libsignal.SignalAddress;
import com.github.auties00.libsignal.SignalDataStore;
import com.github.auties00.libsignal.groups.SignalSenderKeyName;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyRecord;
import com.github.auties00.libsignal.key.*;
import com.github.auties00.libsignal.state.SignalSessionRecord;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ThreadLocalRandom;

public class InMemorySignalDataStore implements SignalDataStore {
    private final int localRegistrationId;
    private final SignalIdentityKeyPair localIdentityKeyPair;
    private final ConcurrentMap<SignalAddress, SignalSessionRecord> sessions;
    private final ConcurrentMap<SignalSenderKeyName, SignalSenderKeyRecord> senderKeys;
    private final ConcurrentMap<Integer, SignalSignedKeyPair> remoteSignedKeyPairs;
    private final ConcurrentMap<Integer, SignalPreKeyPair> localPreKeyPairs;

    public InMemorySignalDataStore() {
        this.localRegistrationId = ThreadLocalRandom.current().nextInt();
        this.localIdentityKeyPair = SignalIdentityKeyPair.random();
        this.sessions = new ConcurrentHashMap<>();
        this.senderKeys = new ConcurrentHashMap<>();
        this.remoteSignedKeyPairs = new ConcurrentHashMap<>();
        this.localPreKeyPairs = new ConcurrentHashMap<>();
    }

    @Override
    public int registrationId() {
        return localRegistrationId;
    }

    @Override
    public SignalIdentityKeyPair identityKeyPair() {
        return localIdentityKeyPair;
    }

    @Override
    public Optional<SignalSessionRecord> findSessionByAddress(SignalAddress remoteAddress) {
        return Optional.ofNullable(sessions.get(remoteAddress));
    }

    @Override
    public void addSession(SignalAddress remoteAddress, SignalSessionRecord record) {
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
    public boolean hasTrust(SignalAddress remoteAddress, SignalIdentityPublicKey theirIdentityKey, SignalKeyDirection direction) {
        return true;
    }

    @Override
    public Optional<SignalSignedKeyPair> findSignedPreKeyById(Integer id) {
        return Optional.ofNullable(remoteSignedKeyPairs.get(id));
    }

    @Override
    public void addSignedPreKey(SignalSignedKeyPair signedKeyPair) {
        remoteSignedKeyPairs.put(signedKeyPair.id(), signedKeyPair);
    }

    @Override
    public Optional<SignalPreKeyPair> findPreKeyById(Integer preKeyId) {
        return Optional.ofNullable(localPreKeyPairs.get(preKeyId));
    }

    @Override
    public void addPreKey(SignalPreKeyPair preKeyPair) {
        localPreKeyPairs.put(preKeyPair.id(), preKeyPair);
    }

    @Override
    public boolean removePreKey(int preKeyId) {
        return localPreKeyPairs.remove(preKeyId) != null;
    }
}