package com.github.auties00.libsignal.exception;

public final class SignalSessionInitializationException
        extends SignalException {
    public SignalSessionInitializationException(String message) {
        super(message);
    }

    public SignalSessionInitializationException(Throwable cause) {
        super(cause);
    }

    public SignalSessionInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
