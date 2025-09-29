package com.github.auties00.libsignal.protocol;

import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.mixins.AesSecretKeySpecMixin;
import it.auties.protobuf.annotation.ProtobufBuilder;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;
import it.auties.protobuf.stream.ProtobufInputStream;
import it.auties.protobuf.stream.ProtobufOutputStream;

import javax.crypto.spec.SecretKeySpec;

@ProtobufMessage(generateBuilder = false)
public final class SignalSenderKeyDistributionMessage extends SignalCiphertextMessage {
    private Integer version;

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final Integer id;

    @ProtobufProperty(index = 2, type = ProtobufType.UINT32)
    final Integer iteration;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES, mixins = AesSecretKeySpecMixin.class)
    final SecretKeySpec chainKey;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey signatureKey;

    SignalSenderKeyDistributionMessage(Integer id, Integer iteration, SecretKeySpec chainKey, SignalIdentityPublicKey signatureKey) {
        // Don't set the version, it will be set by ofSerialized
        this.id = id;
        this.iteration = iteration;
        this.chainKey = chainKey;
        this.signatureKey = signatureKey;
    }

    @ProtobufBuilder(className = "SignalSenderKeyDistributionMessageBuilder")
    SignalSenderKeyDistributionMessage(Integer version, Integer id, Integer iteration, SecretKeySpec chainKey, SignalIdentityPublicKey signatureKey) {
        this.version = version;
        this.id = id;
        this.iteration = iteration;
        this.chainKey = chainKey;
        this.signatureKey = signatureKey;
    }

    public static SignalSenderKeyDistributionMessage ofSerialized(byte[] serialized) {
        var result = SignalSenderKeyDistributionMessageSpec.decode(ProtobufInputStream.fromBytes(serialized, 1, serialized.length - 1));
        result.version = Byte.toUnsignedInt(serialized[0]) >> 4;
        result.serialized = serialized;
        return result;
    }

    @Override
    public int type() {
        return SENDER_KEY_DISTRIBUTION_TYPE;
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
        var serialized = new byte[1 + SignalSenderKeyDistributionMessageSpec.sizeOf(this)];
        if (version == null) {
            throw new InternalError();
        }
        serialized[0] = (byte) (version << 4 | CURRENT_VERSION);
        SignalSenderKeyDistributionMessageSpec.encode(this, ProtobufOutputStream.toBytes(serialized, 1));
        return serialized;
    }

    public Integer id() {
        return id;
    }

    public Integer iteration() {
        return iteration;
    }

    public SecretKeySpec chainKey() {
        return chainKey;
    }

    public SignalIdentityPublicKey signatureKey() {
        return signatureKey;
    }
}
