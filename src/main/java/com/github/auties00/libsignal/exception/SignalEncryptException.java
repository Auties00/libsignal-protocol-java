package com.github.auties00.libsignal.exception;

public final class SignalEncryptException
        extends SignalException {
    public SignalEncryptException(String message) {
        super(message);
    }

    public SignalEncryptException(Throwable cause) {
        super(cause);
    }

    public SignalEncryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
