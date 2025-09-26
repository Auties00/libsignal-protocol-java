package com.github.auties00.libsignal.groups.ratchet;

import com.github.auties00.libsignal.kdf.HKDF;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

@ProtobufMessage
public final class SignalSenderMessageKey {
    private static final byte[] GROUP_INFO = "WhisperGroup".getBytes(StandardCharsets.UTF_8);

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int iteration;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final byte[] seed;

    private final IvParameterSpec iv;

    private final SecretKeySpec cipherKey;

    SignalSenderMessageKey(int iteration, byte[] seed) {
        try {
            var chunks = HKDF.ofCurrent().deriveSecrets(seed, GROUP_INFO, 48);
            this.iteration = iteration;
            this.seed = seed;
            this.iv = new IvParameterSpec(chunks, 0, 16);
            this.cipherKey = new SecretKeySpec(chunks, 16, 32, "AES");
        } catch (GeneralSecurityException e) {
            throw new InternalError(e);
        }
    }

    public int iteration() {
        return iteration;
    }

    public byte[] seed() {
        return seed;
    }

    public IvParameterSpec iv() {
        return iv;
    }

    public SecretKeySpec cipherKey() {
        return cipherKey;
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || obj instanceof SignalSenderMessageKey that
                && this.iteration == that.iteration &&
                Arrays.equals(this.seed, that.seed);
    }

    @Override
    public int hashCode() {
        return Objects.hash(iteration, Arrays.hashCode(seed));
    }

    @Override
    public String toString() {
        return "SenderMessageKey[" +
                "iteration=" + iteration + ", " +
                "seed=" + Arrays.toString(seed) + ']';
    }
}