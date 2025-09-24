package com.github.auties00.signal.protocol;

public interface SignalCiphertextMessage {
    int CURRENT_VERSION = 3;

    int WHISPER_TYPE = 2;
    int PRE_KEY_TYPE = 3;
    int SENDER_KEY_TYPE = 4;
    int SENDER_KEY_DISTRIBUTION_TYPE = 5;

    int version();
    int type();
    byte[] toSerialized();
}