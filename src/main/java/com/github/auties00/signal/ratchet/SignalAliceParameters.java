package com.github.auties00.signal.ratchet;

import com.github.auties00.signal.key.SignalIdentityKeyPair;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

@ProtobufMessage
public final class SignalAliceParameters {
    @ProtobufProperty(index = 1, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourIdentityKey;

    @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourBaseKey;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirIdentityKey;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirSignedPreKey;

    @ProtobufProperty(index = 5, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirOneTimePreKey;

    @ProtobufProperty(index = 6, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirRatchetKey;

    SignalAliceParameters(SignalIdentityKeyPair ourIdentityKey, SignalIdentityKeyPair ourBaseKey, SignalIdentityPublicKey theirIdentityKey, SignalIdentityPublicKey theirSignedPreKey, SignalIdentityPublicKey theirOneTimePreKey, SignalIdentityPublicKey theirRatchetKey) {
        this.ourIdentityKey = ourIdentityKey;
        this.ourBaseKey = ourBaseKey;
        this.theirIdentityKey = theirIdentityKey;
        this.theirSignedPreKey = theirSignedPreKey;
        this.theirOneTimePreKey = theirOneTimePreKey;
        this.theirRatchetKey = theirRatchetKey;
    }

    public SignalIdentityKeyPair ourIdentityKey() {
        return ourIdentityKey;
    }

    public SignalIdentityKeyPair ourBaseKey() {
        return ourBaseKey;
    }

    public SignalIdentityPublicKey theirIdentityKey() {
        return theirIdentityKey;
    }

    public SignalIdentityPublicKey theirSignedPreKey() {
        return theirSignedPreKey;
    }

    public SignalIdentityPublicKey theirOneTimePreKey() {
        return theirOneTimePreKey;
    }

    public SignalIdentityPublicKey theirRatchetKey() {
        return theirRatchetKey;
    }
}
