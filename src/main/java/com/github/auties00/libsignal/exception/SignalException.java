package com.github.auties00.libsignal.exception;

public abstract sealed class SignalException
        extends RuntimeException
        permits SignalDecryptException, SignalEncryptException, SignalMissingSenderKeyException, SignalMissingSenderKeyStateException, SignalMissingSessionException, SignalSessionInitializationException, SignalUninitializedSessionException, SignalUntrustedIdentityException {
    public SignalException(String message) {
        super(message);
    }

    public SignalException(Throwable cause) {
        super(cause);
    }

    public SignalException(String message, Throwable cause) {
        super(message, cause);
    }
}
