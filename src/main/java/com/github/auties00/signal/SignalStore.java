package com.github.auties00.signal;

import com.github.auties00.signal.group.SignalSenderKeyName;
import com.github.auties00.signal.group.state.SignalSenderKeyRecord;
import com.github.auties00.signal.key.*;
import com.github.auties00.signal.state.SignalSessionRecord;

import java.util.Optional;

public interface SignalStore {
    int localRegistrationId();
    SignalIdentityKeyPair localIdentityKeyPair();

    Optional<SignalSessionRecord> findSessionByAddress(SignalAddress remoteAddress);
    void addSession(SignalAddress remoteAddress, SignalSessionRecord record);

    Optional<SignalSenderKeyRecord> findSenderKeyByName(SignalSenderKeyName senderKeyName);
    void addSenderKey(SignalSenderKeyName senderKeyName, SignalSenderKeyRecord record);

    boolean hasTrust(SignalAddress remoteAddress, SignalIdentityPublicKey theirIdentityKey, SignalKeyDirection direction);

    Optional<SignalSignedKeyPair> findRemoteSignedKeyPairById(Integer id);

    Optional<SignalPreKeyPair> findLocalPreKeyById(Integer preKeyId);
    boolean removePreKey(int asInt);
}
