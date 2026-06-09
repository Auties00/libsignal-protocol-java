package com.github.auties00.libsignal.exception;

public final class SignalMalformedMessageException
        extends SignalException {
    public SignalMalformedMessageException(String message) {
        super(message);
    }

    public SignalMalformedMessageException(Throwable cause) {
        super(cause);
    }

    public SignalMalformedMessageException(String message, Throwable cause) {
        super(message, cause);
    }
}
