package com.github.auties00.libsignal.key;

public sealed interface SignalIdentityKey permits SignalIdentityPrivateKey, SignalIdentityPublicKey {
    byte[] toEncodedPoint();

    int writeEncodedPoint(byte[] destination, int offset);
}
