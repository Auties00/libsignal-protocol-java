package com.github.auties00.libsignal.protocol;

import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;
import it.auties.protobuf.stream.ProtobufInputStream;
import it.auties.protobuf.stream.ProtobufOutputStream;

import java.util.OptionalInt;

@ProtobufMessage(name = "PreKeySignalMessage")
public final class SignalPreKeyMessage extends SignalCiphertextMessage {
    private Integer version;

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final Integer preKeyId;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey baseKey;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey identityKey;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final byte[] serializedSignalMessage;

    @ProtobufProperty(index = 5, type = ProtobufType.UINT32)
    final Integer registrationId;

    @ProtobufProperty(index = 6, type = ProtobufType.UINT32)
    final Integer signedPreKeyId;

    SignalPreKeyMessage(Integer preKeyId, SignalIdentityPublicKey baseKey, SignalIdentityPublicKey identityKey, byte[] serializedSignalMessage, Integer registrationId, Integer signedPreKeyId) {
        // Don't set the version, it will be set by ofSerialized
        this.preKeyId = preKeyId;
        this.baseKey = baseKey;
        this.identityKey = identityKey;
        this.serializedSignalMessage = serializedSignalMessage;
        this.registrationId = registrationId;
        this.signedPreKeyId = signedPreKeyId;
    }

    // TODO: Use this constructor as the default builder and make it package private
    public SignalPreKeyMessage(Integer version, Integer preKeyId, SignalIdentityPublicKey baseKey, SignalIdentityPublicKey identityKey, byte[] serializedSignalMessage, Integer registrationId, Integer signedPreKeyId) {
        this.version = version;
        this.preKeyId = preKeyId;
        this.baseKey = baseKey;
        this.identityKey = identityKey;
        this.serializedSignalMessage = serializedSignalMessage;
        this.registrationId = registrationId;
        this.signedPreKeyId = signedPreKeyId;
    }

    public static SignalPreKeyMessage ofSerialized(byte[] serialized) {
        var result = SignalPreKeyMessageSpec.decode(ProtobufInputStream.fromBytes(serialized, 1, serialized.length - 1));
        result.version = Byte.toUnsignedInt(serialized[0]) >> 4;
        result.serialized = serialized;
        return result;
    }

    @Override
    public int type() {
        return PRE_KEY_TYPE;
    }

    @Override
    public int version() {
        if (version == null) {
            throw new InternalError();
        }

        return version;
    }

    @Override
    byte[] serialize() {
        var serialized = new byte[1 + SignalPreKeyMessageSpec.sizeOf(this)];
        if (version == null) {
            throw new InternalError();
        }
        serialized[0] = (byte) (version << 4 | CURRENT_VERSION);
        SignalPreKeyMessageSpec.encode(this, ProtobufOutputStream.toBytes(serialized, 1));
        return serialized;
    }

    public SignalMessage signalMessage() {
        return SignalMessage.ofSerialized(serializedSignalMessage);
    }

    public OptionalInt preKeyId() {
        return preKeyId == null ? OptionalInt.empty() : OptionalInt.of(preKeyId);
    }

    public SignalIdentityPublicKey baseKey() {
        return baseKey;
    }

    public SignalIdentityPublicKey identityKey() {
        return identityKey;
    }

    public Integer registrationId() {
        return registrationId;
    }

    public Integer signedPreKeyId() {
        return signedPreKeyId;
    }
}
