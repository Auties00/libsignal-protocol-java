package com.github.auties00.libsignal.protocol;

public sealed abstract class SignalCiphertextMessage extends SignalProtocolMessage
        permits SignalMessage, SignalPreKeyMessage, SignalSenderKeyDistributionMessage, SignalSenderKeyMessage {
    public static final int CURRENT_VERSION = 3;

    public static final int WHISPER_TYPE = 2;
    public static final int PRE_KEY_TYPE = 3;
    public static final int SENDER_KEY_TYPE = 4;
    public static final int SENDER_KEY_DISTRIBUTION_TYPE = 5;

    public abstract int version();
    public abstract int type();
}