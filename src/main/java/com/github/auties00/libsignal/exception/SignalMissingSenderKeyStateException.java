package com.github.auties00.libsignal.exception;

import com.github.auties00.libsignal.groups.SignalSenderKeyName;

import java.util.Objects;
import java.util.OptionalInt;

public final class SignalMissingSenderKeyStateException
        extends SignalException {
    private final SignalSenderKeyName senderKeyName;
    private final Integer id;
    public SignalMissingSenderKeyStateException(SignalSenderKeyName senderKeyName) {
        Objects.requireNonNull(senderKeyName, "senderKeyName must not be null");
        super("No sender key state found for " + senderKeyName);
        this.senderKeyName = senderKeyName;
        this.id = null;
    }

    public SignalMissingSenderKeyStateException(SignalSenderKeyName senderKeyName, Integer id) {
        Objects.requireNonNull(senderKeyName, "senderKeyName must not be null");
        super("No sender key state found for " + senderKeyName + " with id " + id);
        this.senderKeyName = senderKeyName;
        this.id = id;
    }

    public SignalSenderKeyName senderKeyName() {
        return senderKeyName;
    }

    public OptionalInt id() {
        return id == null ? OptionalInt.empty() : OptionalInt.of(id);
    }
}
