package com.github.auties00.signal.key;

public sealed interface SignalIdentityKey permits SignalIdentityPrivateKey, SignalIdentityPublicKey {
    byte[] encodedPoint();

    int writePoint(byte[] destination, int offset);
}
