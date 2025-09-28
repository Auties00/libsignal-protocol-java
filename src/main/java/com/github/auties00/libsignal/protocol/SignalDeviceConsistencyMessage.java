package com.github.auties00.libsignal.protocol;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.devices.SignalDeviceConsistencyCommitment;
import com.github.auties00.libsignal.devices.SignalDeviceConsistencySignature;
import com.github.auties00.libsignal.devices.SignalDeviceConsistencySignatureBuilder;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.security.SignatureException;
import java.util.Objects;

@ProtobufMessage
public final class SignalDeviceConsistencyMessage extends SignalPlaintextMessage {
    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int generation;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final byte[] signature;

    private SignalDeviceConsistencySignature signatureMessage;

    SignalDeviceConsistencyMessage(int generation, byte[] signature) {
        this.generation = generation;
        this.signature = Objects.requireNonNull(signature, "signature cannot be null");
        // Don't set signatureMessage, it will be set by ofSerialized
    }

    // TODO: Use this constructor as the default builder and make it package private
    public SignalDeviceConsistencyMessage(SignalDeviceConsistencyCommitment commitment, SignalIdentityKeyPair identityKeyPair) throws SignatureException {
        var signatureBytes = Curve25519.signVrf(identityKeyPair.privateKey().encodedPoint(), commitment.toSerialized());
        var vrfOutputBytes = Curve25519.verifyVrfSignature(identityKeyPair.publicKey().toEncodedPoint(), commitment.toSerialized(), signatureBytes);
        this.generation = commitment.generation();
        this.signature = signatureBytes;
        this.signatureMessage = new SignalDeviceConsistencySignatureBuilder()
                .signature(signatureBytes)
                .vrfOutput(vrfOutputBytes)
                .build();
    }

    public static SignalDeviceConsistencyMessage ofSerialized(byte[] serialized, SignalDeviceConsistencyCommitment commitment, SignalIdentityKeyPair identityKey) throws SignatureException {
        var message = SignalDeviceConsistencyMessageSpec.decode(serialized);
        var vrfOutputBytes = Curve25519.verifyVrfSignature(identityKey.publicKey().toEncodedPoint(), commitment.toSerialized(), message.signature);
        message.signatureMessage = new SignalDeviceConsistencySignatureBuilder()
                .signature(message.signature)
                .vrfOutput(vrfOutputBytes)
                .build();
        message.serialized = serialized;
        return message;
    }

    @Override
    byte[] serialize() {
        return SignalDeviceConsistencyMessageSpec.encode(this);
    }

    public int generation() {
        return generation;
    }

    public SignalDeviceConsistencySignature signature() {
        if (signatureMessage == null) {
            throw new InternalError();
        }
        return signatureMessage;
    }
}