package com.github.auties00.libsignal.exception;

import com.github.auties00.libsignal.SignalProtocolAddress;

import java.util.Objects;

public final class SignalUntrustedIdentityException
        extends SignalException {
    private final SignalProtocolAddress address;
    public SignalUntrustedIdentityException(SignalProtocolAddress address) {
        Objects.requireNonNull(address, "address cannot be null");
        super("Initialized session for address " + address);
        this.address = address;
    }

    public SignalProtocolAddress address() {
        return address;
    }
}
