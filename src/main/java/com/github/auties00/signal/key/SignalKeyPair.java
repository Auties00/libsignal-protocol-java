package com.github.auties00.signal.key;

public sealed interface SignalKeyPair permits SignalIdentityKeyPair, SignalPreKeyPair, SignalSignedKeyPair {
    SignalIdentityPublicKey publicKey();
    SignalIdentityPrivateKey privateKey();
}
