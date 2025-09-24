package com.github.auties00.signal.key;

import it.auties.curve25519.Curve25519;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Objects;

@ProtobufMessage
public record SignalSignedKeyPair(
        @ProtobufProperty(index = 1, type = ProtobufType.INT32)
        int id,
        @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
        SignalIdentityKeyPair keyPair,
        @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
        byte[] signature
) implements SignalKeyPair {
    public SignalSignedKeyPair {
        Objects.requireNonNull(signature, "signature cannot be null");
        Objects.requireNonNull(keyPair, "keyPair cannot be null");
    }

    public static SignalSignedKeyPair of(int id, SignalIdentityKeyPair signatureKey) {
        var keypair = SignalIdentityKeyPair.random();
        var privateKey = signatureKey.privateKey().toEncodedPoint();
        var message = keypair.publicKey().toSerialized();
        var signature = Curve25519.sign(privateKey, message);
        return new SignalSignedKeyPair(id, keypair, signature);
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
