package com.github.auties00.signal.protocol;

import com.github.auties00.signal.key.SignalIdentityPrivateKey;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import it.auties.curve25519.Curve25519;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;
import it.auties.protobuf.stream.ProtobufInputStream;
import it.auties.protobuf.stream.ProtobufOutputStream;

import java.util.Arrays;

@ProtobufMessage(name = "SenderKeyMessage")
public final class SignalSenderKeyMessage implements SignalCiphertextMessage {
    private static final Integer SIGNATURE_LENGTH = 64;

    private Integer version;

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final Integer id;

    @ProtobufProperty(index = 2, type = ProtobufType.UINT32)
    final Integer iteration;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
    final byte[] cipherText;

    private byte[] signature;

    SignalSenderKeyMessage(Integer id, Integer iteration, byte[] cipherText) {
        // Don't set the version, it will be set by ofSerialized
        this.id = id;
        this.iteration = iteration;
        this.cipherText = cipherText;
    }

    public SignalSenderKeyMessage(Integer version, Integer id, Integer iteration, byte[] cipherText, SignalIdentityPrivateKey signaturePrivateKey) {
        this.version = version;
        this.id = id;
        this.iteration = iteration;
        this.cipherText = cipherText;
        var messageLength = SignalSenderKeyMessageSpec.sizeOf(this);
        var serialized = new byte[1 + messageLength];
        serialized[0] = (byte) (version << 4 | CURRENT_VERSION);
        SignalSenderKeyMessageSpec.encode(this, ProtobufOutputStream.toBytes(serialized, 1));
        this.signature = Curve25519.sign(signaturePrivateKey.toEncodedPoint(), serialized, null);
    }

    public static SignalSenderKeyMessage ofSerialized(byte[] serialized) {
        var signature = Arrays.copyOfRange(serialized, serialized.length - SIGNATURE_LENGTH, serialized.length);
        var result = SignalSenderKeyMessageSpec.decode(ProtobufInputStream.fromBytes(serialized, 1, serialized.length - 1 - SIGNATURE_LENGTH));
        result.version = Byte.toUnsignedInt(serialized[0]) >> 4;
        result.signature = signature;
        return result;
    }

    @Override
    public int type() {
        return SENDER_KEY_TYPE;
    }

    @Override
    public int version() {
        if (version == null) {
            throw new InternalError();
        }

        return version;
    }

    @Override
    public byte[] toSerialized() {
        var messageLength = SignalSenderKeyMessageSpec.sizeOf(this);
        var serialized = new byte[1 + messageLength + SIGNATURE_LENGTH];
        if (version == null) {
            throw new InternalError();
        }
        serialized[0] = (byte) (version << 4 | CURRENT_VERSION);
        SignalSenderKeyMessageSpec.encode(this, ProtobufOutputStream.toBytes(serialized, 1));
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            throw new InternalError();
        }
        System.arraycopy(signature, 0, serialized, 1 + messageLength, signature.length);
        return serialized;
    }

    public boolean verifySignature(SignalIdentityPublicKey key) {
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            throw new InternalError();
        }
        var messageLength = SignalSenderKeyMessageSpec.sizeOf(this);
        var serialized = new byte[1 + messageLength + SIGNATURE_LENGTH];
        if (version == null) {
            throw new InternalError();
        }
        serialized[0] = (byte) (version << 4 | CURRENT_VERSION);
        SignalSenderKeyMessageSpec.encode(this, ProtobufOutputStream.toBytes(serialized, 1));
        return Curve25519.verifySignature(key.toEncodedPoint(), serialized, signature);
    }

    public Integer id() {
        return id;
    }

    public Integer iteration() {
        return iteration;
    }

    public byte[] cipherText() {
        return cipherText;
    }
}
