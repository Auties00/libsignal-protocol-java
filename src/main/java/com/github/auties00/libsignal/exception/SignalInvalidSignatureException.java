package com.github.auties00.libsignal.exception;

public final class SignalInvalidSignatureException
        extends SignalException {
    public SignalInvalidSignatureException(String message) {
        super(message);
    }

    public SignalInvalidSignatureException(Throwable cause) {
        super(cause);
    }

    public SignalInvalidSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
