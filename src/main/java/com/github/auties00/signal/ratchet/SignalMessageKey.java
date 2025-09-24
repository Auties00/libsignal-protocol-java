package com.github.auties00.signal.ratchet;

import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

@ProtobufMessage
public final class SignalMessageKey {
    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int index;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final byte[] cipherKey;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
    final byte[] macKey;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final byte[] iv;

    SignalMessageKey(int index, byte[] cipherKey, byte[] macKey, byte[] iv) {
        this.index = index;
        this.cipherKey = cipherKey;
        this.macKey = macKey;
        this.iv = iv;
    }

    public int index() {
        return index;
    }

    public byte[] cipherKey() {
        return cipherKey;
    }

    public byte[] macKey() {
        return macKey;
    }

    public byte[] iv() {
        return iv;
    }
}