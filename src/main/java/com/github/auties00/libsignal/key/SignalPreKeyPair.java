package com.github.auties00.libsignal.key;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Objects;

@ProtobufMessage
public final class SignalPreKeyPair implements SignalKeyPair {
    @ProtobufProperty(index = 1, type = ProtobufType.INT32)
    final int id;

    @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair keyPair;

    SignalPreKeyPair(int id, SignalIdentityKeyPair keyPair) {
        this.id = id;
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair cannot be null");
    }

    public static SignalPreKeyPair random(int id) {
        return new SignalPreKeyPair(id, SignalIdentityKeyPair.random());
    }

    @Override
    public SignalIdentityPublicKey publicKey() {
        return keyPair.publicKey();
    }

    @Override
    public SignalIdentityPrivateKey privateKey() {
        return keyPair.privateKey();
    }

    public int id() {
        return id;
    }

    public SignalIdentityKeyPair keyPair() {
        return keyPair;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SignalPreKeyPair that
                && id == that.id
                && Objects.equals(keyPair, that.keyPair);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, keyPair);
    }

    @Override
    public String toString() {
        return "SignalPreKeyPair[" +
                "id=" + id + ", " +
                "keyPair=" + keyPair + ']';
    }

}
