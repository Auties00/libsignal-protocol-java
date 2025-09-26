package com.github.auties00.libsignal.key;

import com.github.auties00.curve25519.Curve25519;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Arrays;
import java.util.Objects;

@ProtobufMessage
public final class SignalSignedKeyPair implements SignalKeyPair {
    @ProtobufProperty(index = 1, type = ProtobufType.INT32)
    final int id;

    @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
    final SignalIdentityKeyPair keyPair;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
    final byte[] signature;

    SignalSignedKeyPair(int id, SignalIdentityKeyPair keyPair, byte[] signature) {
        this.id = id;
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair cannot be null");
        this.signature = Objects.requireNonNull(signature, "signature cannot be null");
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

    public int id() {
        return id;
    }

    public SignalIdentityKeyPair keyPair() {
        return keyPair;
    }

    public byte[] signature() {
        return signature;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SignalSignedKeyPair that
                && id == that.id
                && Objects.equals(keyPair, that.keyPair)
                && Objects.deepEquals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, keyPair, Arrays.hashCode(signature));
    }

    @Override
    public String toString() {
        return "SignalSignedKeyPair[" +
                "id=" + id + ", " +
                "keyPair=" + keyPair + ", " +
                "signature=" + Arrays.toString(signature) + ']';
    }

}
