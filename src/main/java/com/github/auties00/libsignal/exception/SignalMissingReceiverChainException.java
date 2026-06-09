package com.github.auties00.libsignal.exception;

import com.github.auties00.libsignal.key.SignalIdentityPublicKey;

import java.util.Objects;

public final class SignalMissingReceiverChainException
        extends SignalException {
    private final SignalIdentityPublicKey senderRatchetKey;
    public SignalMissingReceiverChainException(SignalIdentityPublicKey senderRatchetKey) {
        Objects.requireNonNull(senderRatchetKey, "senderRatchetKey must not be null");
        super("No receiver chain found for " + senderRatchetKey);
        this.senderRatchetKey = senderRatchetKey;
    }

    public SignalIdentityPublicKey senderRatchetKey() {
        return senderRatchetKey;
    }
}
