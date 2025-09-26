package com.github.auties00.libsignal.fingerprint;

import com.github.auties00.libsignal.util.ByteUtils;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Objects;

@ProtobufMessage
public final class SignalCombinedFingerprint {
    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int version;

    @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
    final SignalLogicalFingerprint localFingerprint;

    @ProtobufProperty(index = 3, type = ProtobufType.MESSAGE)
    final SignalLogicalFingerprint remoteFingerprint;

    SignalCombinedFingerprint(int version, SignalLogicalFingerprint localFingerprint, SignalLogicalFingerprint remoteFingerprint) {
        this.version = version;
        this.localFingerprint = localFingerprint;
        this.remoteFingerprint = remoteFingerprint;
    }

    public String toDisplayText() {
        var localFingerprintNumbers = getDisplayStringFor(localFingerprint.content());
        var remoteFingerprintNumbers = getDisplayStringFor(remoteFingerprint.content());
        if (localFingerprintNumbers.compareTo(remoteFingerprintNumbers) <= 0) {
            return localFingerprintNumbers + remoteFingerprintNumbers;
        } else {
            return remoteFingerprintNumbers + localFingerprintNumbers;
        }
    }

    private String getDisplayStringFor(byte[] fingerprint) {
        return getEncodedChunk(fingerprint, 0)
                + getEncodedChunk(fingerprint, 5)
                + getEncodedChunk(fingerprint, 10)
                + getEncodedChunk(fingerprint, 15)
                + getEncodedChunk(fingerprint, 20)
                + getEncodedChunk(fingerprint, 25);
    }

    private String getEncodedChunk(byte[] hash, int offset) {
        long chunk = ByteUtils.readInt40(hash, offset) % 100000;
        return String.format("%05d", chunk);
    }

    public int version() {
        return version;
    }

    public SignalLogicalFingerprint localFingerprint() {
        return localFingerprint;
    }

    public SignalLogicalFingerprint remoteFingerprint() {
        return remoteFingerprint;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SignalCombinedFingerprint that
                && version == that.version
                && Objects.equals(localFingerprint, that.localFingerprint)
                && Objects.equals(remoteFingerprint, that.remoteFingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, localFingerprint, remoteFingerprint);
    }

    @Override
    public String toString() {
        return "SignalCombinedFingerprint[" +
                "version=" + version + ", " +
                "localFingerprint=" + localFingerprint + ", " +
                "remoteFingerprint=" + remoteFingerprint + ']';
    }
}