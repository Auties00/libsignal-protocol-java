package com.github.auties00.signal.state;

import com.github.auties00.signal.key.SignalIdentityPrivateKey;
import com.github.auties00.signal.key.SignalIdentityPublicKey;
import com.github.auties00.signal.ratchet.SignalChainKey;
import com.github.auties00.signal.ratchet.SignalChainKeyBuilder;
import it.auties.curve25519.Curve25519;
import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufSerializer;

import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

// TODO: Refactor this class when next ModernProtobuf update is ready
public final class SignalSessionRootKey {
    private final KDF kdf;
    private final SignalIdentityPublicKey key;

    SignalSessionRootKey(KDF kdf, SignalIdentityPublicKey key) {
        this.kdf = kdf;
        this.key = key;
    }

    @ProtobufSerializer
    public SignalIdentityPublicKey key() {
        return key;
    }

    @ProtobufDeserializer
    public static SignalSessionRootKey of(byte[] key) {
        try {
            var kdf = KDF.getInstance("HKDF-SHA256");
            var identityKey = SignalIdentityPublicKey.of(key);
            return new SignalSessionRootKey(kdf, identityKey);
        } catch (NoSuchAlgorithmException exception) {
            throw new AssertionError("Missing KDF algorithm", exception);
        }
    }

    public static SignalSessionRootKey of(byte[] key, int offset, int length) {
        try {
            var kdf = KDF.getInstance("HKDF-SHA256");
            var identityKey = SignalIdentityPublicKey.of(key, offset, length);
            return new SignalSessionRootKey(kdf, identityKey);
        } catch (NoSuchAlgorithmException exception) {
            throw new AssertionError("Missing KDF algorithm", exception);
        }
    }

    public Chain createChain(SignalIdentityPublicKey theirRatchetKey, SignalIdentityPrivateKey ourRatchetKey) {
        try {
            var sharedSecret = Curve25519.sharedKey(theirRatchetKey.encodedPoint(), ourRatchetKey.encodedPoint());
            var senderParams = HKDFParameterSpec.ofExtract().addIKM(new SecretKeySpec(sharedSecret, "AES")).thenExpand("WhisperRatchet".getBytes(StandardCharsets.UTF_8), 64);
            var senderDerivedSecrets = kdf.deriveData(senderParams);
            var rootKeyData = SignalIdentityPublicKey.of(senderDerivedSecrets, 0, 32);
            var rootKey = new SignalSessionRootKey(kdf, rootKeyData);
            var chainKeyData = Arrays.copyOfRange(senderDerivedSecrets, 32, 64);
            var senderChainKey = new SignalChainKeyBuilder().key(chainKeyData).index(0).build();
            return new Chain(rootKey, senderChainKey);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new AssertionError("Misconfigured KDF", exception);
        }
    }

    public static final class Chain {
        private final SignalSessionRootKey rootKey;
        private final SignalChainKey chainKey;

        private Chain(SignalSessionRootKey rootKey, SignalChainKey chainKey) {
            this.rootKey = rootKey;
            this.chainKey = chainKey;
        }

        public SignalSessionRootKey rootKey() {
            return rootKey;
        }

        public SignalChainKey chainKey() {
            return chainKey;
        }
    }
}
