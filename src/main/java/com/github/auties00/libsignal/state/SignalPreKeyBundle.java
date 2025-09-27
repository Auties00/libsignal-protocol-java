package com.github.auties00.libsignal.state;

import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

@ProtobufMessage
public final class SignalPreKeyBundle {
    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int registrationId;

    @ProtobufProperty(index = 2, type = ProtobufType.UINT32)
    final int deviceId;

    @ProtobufProperty(index = 3, type = ProtobufType.UINT32)
    final int preKeyId;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey preKeyPublic;

    @ProtobufProperty(index = 5, type = ProtobufType.UINT32)
    final int signedPreKeyId;

    @ProtobufProperty(index = 6, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey signedPreKeyPublic;

    @ProtobufProperty(index = 7, type = ProtobufType.BYTES)
    final byte[] signedPreKeySignature;

    @ProtobufProperty(index = 8, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey identityKey;

    public SignalPreKeyBundle(int registrationId, int deviceId, int preKeyId, SignalIdentityPublicKey preKeyPublic, int signedPreKeyId, SignalIdentityPublicKey signedPreKeyPublic, byte[] signedPreKeySignature, SignalIdentityPublicKey identityKey) {
        this.registrationId = registrationId;
        this.deviceId = deviceId;
        this.preKeyId = preKeyId;
        this.preKeyPublic = preKeyPublic;
        this.signedPreKeyId = signedPreKeyId;
        this.signedPreKeyPublic = signedPreKeyPublic;
        this.signedPreKeySignature = signedPreKeySignature;
        this.identityKey = identityKey;
    }

    public int registrationId() {
        return registrationId;
    }

    public int deviceId() {
        return deviceId;
    }

    public int preKeyId() {
        return preKeyId;
    }

    public SignalIdentityPublicKey preKeyPublic() {
        return preKeyPublic;
    }

    public int signedPreKeyId() {
        return signedPreKeyId;
    }

    public SignalIdentityPublicKey signedPreKeyPublic() {
        return signedPreKeyPublic;
    }

    public byte[] signedPreKeySignature() {
        return signedPreKeySignature;
    }

    public SignalIdentityPublicKey identityKey() {
        return identityKey;
    }
}
