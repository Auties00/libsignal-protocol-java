package com.github.auties00.libsignal.ratchet;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.kdf.HKDF;
import com.github.auties00.libsignal.key.SignalIdentityPrivateKey;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufSerializer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;


public final class SignalRootKey {
    private static final byte[] CHAIN_INFO = "WhisperRatchet".getBytes(StandardCharsets.UTF_8);

    private final SignalIdentityPublicKey key;

    private SignalRootKey(SignalIdentityPublicKey key) {
        this.key = key;
    }

    @ProtobufDeserializer
    public static SignalRootKey of(byte[] key) {
        return new SignalRootKey(SignalIdentityPublicKey.ofDirect(key));
    }

    public static SignalRootKey of(SignalIdentityPublicKey receiverRootKeyData) {
        return new SignalRootKey(receiverRootKeyData);
    }

    @ProtobufSerializer
    public SignalIdentityPublicKey key() {
        return key;
    }

    public Chain createChain(HKDF hkdf, Mac mac, SignalIdentityPrivateKey ourRatchetKey, SignalIdentityPublicKey theirRatchetKey) {
        try {
            var sharedSecret = Curve25519.sharedKey(ourRatchetKey.toEncodedPoint(), theirRatchetKey.toEncodedPoint());
            var senderDerivedSecrets = hkdf.deriveSecrets(mac, sharedSecret, key.toEncodedPoint(), CHAIN_INFO, 64);
            var rootKeyData = SignalIdentityPublicKey.ofCopy(senderDerivedSecrets, 0, 32);
            var rootKey = new SignalRootKey(rootKeyData);
            var chainKeyData = new SecretKeySpec(senderDerivedSecrets, 32, 32, "HmacSHA256");
            var senderChainKey = new SignalChainKey(0, chainKeyData);
            return new Chain(rootKey, senderChainKey);
        } catch (GeneralSecurityException e) {
            throw new InternalError(e);
        }
    }

    public static final class Chain {
        private final SignalRootKey rootKey;
        private final SignalChainKey chainKey;

        private Chain(SignalRootKey rootKey, SignalChainKey chainKey) {
            this.rootKey = rootKey;
            this.chainKey = chainKey;
        }

        public SignalRootKey rootKey() {
            return rootKey;
        }

        public SignalChainKey chainKey() {
            return chainKey;
        }
    }
}
