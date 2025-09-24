package com.github.auties00.signal.key;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Objects;

@ProtobufMessage
public record SignalPreKeyPair(
        @ProtobufProperty(index = 1, type = ProtobufType.INT32)
        int id,
        @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
        SignalIdentityKeyPair keyPair
) implements SignalKeyPair {
    public SignalPreKeyPair {
        Objects.requireNonNull(keyPair, "keyPair cannot be null");
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
}
