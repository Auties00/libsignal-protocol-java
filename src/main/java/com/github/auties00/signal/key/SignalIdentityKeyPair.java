package com.github.auties00.signal.key;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Objects;

@ProtobufMessage
public record SignalIdentityKeyPair(
        @ProtobufProperty(index = 1, type = ProtobufType.BYTES)
        SignalIdentityPublicKey publicKey,
        @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
        SignalIdentityPrivateKey privateKey
) implements SignalKeyPair {
    public SignalIdentityKeyPair(SignalIdentityPublicKey publicKey, SignalIdentityPrivateKey privateKey) {
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey cannot be null");
        this.privateKey = privateKey;
    }

    public SignalIdentityKeyPair(SignalIdentityPublicKey publicKey) {
        this(publicKey, null);
    }

    public static SignalIdentityKeyPair random() {
        var privateKey = SignalIdentityPrivateKey.random();
        var publicKey = SignalIdentityPublicKey.of(privateKey);
        return new SignalIdentityKeyPair(publicKey, privateKey);
    }
}
