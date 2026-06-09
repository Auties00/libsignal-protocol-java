package com.github.auties00.libsignal.exception;

public final class SignalMissingPreKeyException
        extends SignalException {
    private final int id;
    public SignalMissingPreKeyException(int id) {
        super("No prekey found with id " + id);
        this.id = id;
    }

    public int id() {
        return id;
    }
}
