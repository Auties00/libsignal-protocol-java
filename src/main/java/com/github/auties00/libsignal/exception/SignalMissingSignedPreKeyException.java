package com.github.auties00.libsignal.exception;

public final class SignalMissingSignedPreKeyException
        extends SignalException {
    private final int id;
    public SignalMissingSignedPreKeyException(int id) {
        super("No signed prekey found with id " + id);
        this.id = id;
    }

    public int id() {
        return id;
    }
}
