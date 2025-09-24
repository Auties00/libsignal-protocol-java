package com.github.auties00.signal.ratchet;

import com.github.auties00.signal.key.SignalIdentityKeyPair;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

@ProtobufMessage
public final class SignalSymmetricParameters {
    @ProtobufProperty(index = 1, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourBaseKey;

    @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourRatchetKey;

    @ProtobufProperty(index = 3, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair ourIdentityKey;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirBaseKey;

    @ProtobufProperty(index = 5, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirRatchetKey;

    @ProtobufProperty(index = 6, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey theirIdentityKey;

    SignalSymmetricParameters(SignalIdentityKeyPair ourBaseKey, SignalIdentityKeyPair ourRatchetKey, SignalIdentityKeyPair ourIdentityKey, SignalIdentityPublicKey theirBaseKey, SignalIdentityPublicKey theirRatchetKey, SignalIdentityPublicKey theirIdentityKey) {
        this.ourBaseKey = ourBaseKey;
        this.ourRatchetKey = ourRatchetKey;
        this.ourIdentityKey = ourIdentityKey;
        this.theirBaseKey = theirBaseKey;
        this.theirRatchetKey = theirRatchetKey;
        this.theirIdentityKey = theirIdentityKey;
    }

    public SignalIdentityKeyPair ourBaseKey() {
        return ourBaseKey;
    }

    public SignalIdentityKeyPair ourRatchetKey() {
        return ourRatchetKey;
    }

    public SignalIdentityKeyPair ourIdentityKey() {
        return ourIdentityKey;
    }

    public SignalIdentityPublicKey theirBaseKey() {
        return theirBaseKey;
    }

    public SignalIdentityPublicKey theirRatchetKey() {
        return theirRatchetKey;
    }

    public SignalIdentityPublicKey theirIdentityKey() {
        return theirIdentityKey;
    }
}
