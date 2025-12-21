package com.github.auties00.libsignal.exception;

import com.github.auties00.libsignal.groups.SignalSenderKeyName;

import java.util.Objects;

public final class SignalMissingSenderKeyException
        extends SignalException {
    private final SignalSenderKeyName senderKeyName;
    public SignalMissingSenderKeyException(SignalSenderKeyName senderKeyName) {
        Objects.requireNonNull(senderKeyName, "senderKeyName must not be null");
        super("No sender key found for " + senderKeyName);
        this.senderKeyName = senderKeyName;
    }

    public SignalSenderKeyName senderKeyName() {
        return senderKeyName;
    }
}
