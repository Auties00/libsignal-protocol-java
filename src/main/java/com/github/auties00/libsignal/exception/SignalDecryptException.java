package com.github.auties00.libsignal.exception;

public final class SignalDecryptException
        extends SignalException {
    public SignalDecryptException(String message) {
        super(message);
    }

    public SignalDecryptException(Throwable cause) {
        super(cause);
    }

    public SignalDecryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
