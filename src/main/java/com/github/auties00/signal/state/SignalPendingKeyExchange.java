package com.github.auties00.signal.state;

import com.github.auties00.signal.key.SignalIdentityPrivateKey;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Objects;

@ProtobufMessage
public final class SignalPendingKeyExchange {
    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int sequence;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey localBaseKey;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
    final SignalIdentityPrivateKey localBaseKeyPrivate;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey localRatchetKey;

    @ProtobufProperty(index = 5, type = ProtobufType.BYTES)
    final SignalIdentityPrivateKey localRatchetKeyPrivate;

    @ProtobufProperty(index = 6, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey localIdentityKey;

    @ProtobufProperty(index = 7, type = ProtobufType.BYTES)
    final SignalIdentityPrivateKey localIdentityKeyPrivate;

    SignalPendingKeyExchange(int sequence, SignalIdentityPublicKey localBaseKey, SignalIdentityPrivateKey localBaseKeyPrivate, SignalIdentityPublicKey localRatchetKey, SignalIdentityPrivateKey localRatchetKeyPrivate, SignalIdentityPublicKey localIdentityKey, SignalIdentityPrivateKey localIdentityKeyPrivate) {
        this.sequence = sequence;
        this.localBaseKey = localBaseKey;
        this.localBaseKeyPrivate = localBaseKeyPrivate;
        this.localRatchetKey = localRatchetKey;
        this.localRatchetKeyPrivate = localRatchetKeyPrivate;
        this.localIdentityKey = localIdentityKey;
        this.localIdentityKeyPrivate = localIdentityKeyPrivate;
    }

    public int sequence() {
        return sequence;
    }

    public SignalIdentityPublicKey localBaseKey() {
        return localBaseKey;
    }

    public SignalIdentityPrivateKey localBaseKeyPrivate() {
        return localBaseKeyPrivate;
    }

    public SignalIdentityPublicKey localRatchetKey() {
        return localRatchetKey;
    }

    public SignalIdentityPrivateKey localRatchetKeyPrivate() {
        return localRatchetKeyPrivate;
    }

    public SignalIdentityPublicKey localIdentityKey() {
        return localIdentityKey;
    }

    public SignalIdentityPrivateKey localIdentityKeyPrivate() {
        return localIdentityKeyPrivate;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SignalPendingKeyExchange that
                && sequence == that.sequence
                && Objects.equals(localBaseKey, that.localBaseKey)
                && Objects.equals(localBaseKeyPrivate, that.localBaseKeyPrivate)
                && Objects.equals(localRatchetKey, that.localRatchetKey)
                && Objects.equals(localRatchetKeyPrivate, that.localRatchetKeyPrivate)
                && Objects.equals(localIdentityKey, that.localIdentityKey)
                && Objects.equals(localIdentityKeyPrivate, that.localIdentityKeyPrivate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sequence, localBaseKey, localBaseKeyPrivate, localRatchetKey, localRatchetKeyPrivate, localIdentityKey, localIdentityKeyPrivate);
    }
}