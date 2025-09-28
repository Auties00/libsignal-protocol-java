package com.github.auties00.libsignal.protocol;

public sealed abstract class SignalProtocolMessage
        permits SignalCiphertextMessage, SignalPlaintextMessage {
    volatile byte[] serialized;

    abstract byte[] serialize();

    public final byte[] toSerialized() {
        if(serialized == null) {
            synchronized (this) {
                if(serialized == null) {
                    this.serialized = serialize();
                }
            }
        }
        return serialized;
    }
}
