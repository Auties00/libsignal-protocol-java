package com.github.auties00.signal.fingerprint;

import com.github.auties00.signal.util.ByteUtils;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

@ProtobufMessage
public record SignalCombinedFingerprint(
        @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
        int version,
        @ProtobufProperty(index = 2, type = ProtobufType.MESSAGE)
        SignalLogicalFingerprint localFingerprint,
        @ProtobufProperty(index = 3, type = ProtobufType.MESSAGE)
        SignalLogicalFingerprint remoteFingerprint
) {
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
}