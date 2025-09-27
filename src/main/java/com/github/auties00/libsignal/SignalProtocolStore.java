package com.github.auties00.libsignal;

import com.github.auties00.libsignal.groups.SignalSenderKeyName;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyRecord;
import com.github.auties00.libsignal.key.*;
import com.github.auties00.libsignal.state.SignalSessionRecord;

import java.util.Optional;

public interface SignalProtocolStore {
    int registrationId();
    SignalIdentityKeyPair identityKeyPair();

    Optional<SignalSessionRecord> findSessionByAddress(SignalProtocolAddress remoteAddress);
    void addSession(SignalProtocolAddress remoteAddress, SignalSessionRecord record);

    Optional<SignalSenderKeyRecord> findSenderKeyByName(SignalSenderKeyName senderKeyName);
    void addSenderKey(SignalSenderKeyName senderKeyName, SignalSenderKeyRecord record);

    Optional<SignalSignedKeyPair> findSignedPreKeyById(Integer id);
    void addSignedPreKey(SignalSignedKeyPair signedKeyPair);

    Optional<SignalPreKeyPair> findPreKeyById(Integer id);
    void addPreKey(SignalPreKeyPair preKeyPair);
    boolean removePreKey(int id);

    boolean isTrustedIdentity(SignalProtocolAddress remoteAddress, SignalIdentityPublicKey theirIdentityKey, SignalKeyDirection direction);
    void addTrustedIdentity(SignalProtocolAddress remoteAddress, SignalIdentityPublicKey identityKey);
}
