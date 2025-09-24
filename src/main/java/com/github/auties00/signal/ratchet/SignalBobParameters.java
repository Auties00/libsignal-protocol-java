package com.github.auties00.signal.ratchet;

import com.github.auties00.signal.key.SignalIdentityKeyPair;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

@ProtobufMessage
public final class SignalBobParameters {
    @ProtobufProperty(index = 1, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourIdentityKey;

    @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourSignedPreKey;

    @ProtobufProperty(index = 3, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourOneTimePreKey;

    @ProtobufProperty(index = 4, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourRatchetKey;

    @ProtobufProperty(index = 5, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirIdentityKey;

    @ProtobufProperty(index = 6, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirBaseKey;

    SignalBobParameters(SignalIdentityKeyPair ourIdentityKey, SignalIdentityKeyPair ourSignedPreKey, SignalIdentityKeyPair ourOneTimePreKey, SignalIdentityKeyPair ourRatchetKey, SignalIdentityPublicKey theirIdentityKey, SignalIdentityPublicKey theirBaseKey) {
        this.ourIdentityKey = ourIdentityKey;
        this.ourSignedPreKey = ourSignedPreKey;
        this.ourOneTimePreKey = ourOneTimePreKey;
        this.ourRatchetKey = ourRatchetKey;
        this.theirIdentityKey = theirIdentityKey;
        this.theirBaseKey = theirBaseKey;
    }

    public SignalIdentityKeyPair ourIdentityKey() {
        return ourIdentityKey;
    }

    public SignalIdentityKeyPair ourSignedPreKey() {
        return ourSignedPreKey;
    }

    public SignalIdentityKeyPair ourOneTimePreKey() {
        return ourOneTimePreKey;
    }

    public SignalIdentityKeyPair ourRatchetKey() {
        return ourRatchetKey;
    }

    public SignalIdentityPublicKey theirIdentityKey() {
        return theirIdentityKey;
    }

    public SignalIdentityPublicKey theirBaseKey() {
        return theirBaseKey;
    }
}
