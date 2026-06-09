package com.github.auties00.libsignal.exception;

public abstract sealed class SignalException
        extends RuntimeException
        permits SignalDecryptException, SignalDuplicateMessageException, SignalEncryptException, SignalInvalidSignatureException, SignalMalformedMessageException, SignalMissingPreKeyException, SignalMissingReceiverChainException, SignalMissingSenderKeyException, SignalMissingSenderKeyStateException, SignalMissingSessionException, SignalMissingSignedPreKeyException, SignalSessionInitializationException, SignalUninitializedSessionException, SignalUntrustedIdentityException {
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
