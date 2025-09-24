package com.github.auties00.signal.devices;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.Arrays;
import java.util.Objects;

@ProtobufMessage
public final class SignalDeviceConsistencySignature implements Comparable<SignalDeviceConsistencySignature> {
    @ProtobufProperty(index = 1, type = ProtobufType.BYTES)
    final byte[] signature;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final byte[] vrfOutput;

    SignalDeviceConsistencySignature(byte[] signature, byte[] vrfOutput) {
        this.signature = Objects.requireNonNull(signature, "signature cannot be null");
        this.vrfOutput = Objects.requireNonNull(vrfOutput, "vrfOutput cannot be null");
    }

    public byte[] signature() {
        return signature;
    }

    public byte[] vrfOutput() {
        return vrfOutput;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SignalDeviceConsistencySignature that
                && Arrays.equals(signature, that.signature)
                && Arrays.equals(vrfOutput, that.vrfOutput);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(signature), Arrays.hashCode(vrfOutput));
    }

    @Override
    public String toString() {
        return "SignalDeviceConsistencySignature[" +
                "signature=" + Arrays.toString(signature) + ", " +
                "vrfOutput=" + Arrays.toString(vrfOutput) + ']';
    }

    @Override
    public int compareTo(SignalDeviceConsistencySignature that) {
        if (that == null) {
            return 1;
        }

        for (int i = 0, j = 0; i < vrfOutput.length && j < that.vrfOutput.length; i++, j++) {
            var leftItem = (vrfOutput[i] & 0xff);
            var rightItem = (that.vrfOutput[j] & 0xff);
            if (leftItem != rightItem) {
                return leftItem - rightItem;
            }
        }

        return vrfOutput.length - that.vrfOutput.length;
    }
}