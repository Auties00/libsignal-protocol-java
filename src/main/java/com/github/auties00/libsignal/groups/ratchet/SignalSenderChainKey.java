package com.github.auties00.libsignal.groups.ratchet;

import com.github.auties00.libsignal.mixins.HmacSha256KeySpecMixin;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Objects;

@ProtobufMessage
public final class SignalSenderChainKey {
    private static final byte[] MESSAGE_KEY_SEED = {0x01};
    private static final byte[] CHAIN_KEY_SEED = {0x02};

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int iteration;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES, mixins = HmacSha256KeySpecMixin.class)
    final SecretKeySpec seed;

    SignalSenderChainKey(int iteration, SecretKeySpec seed) {
        this.iteration = iteration;
        this.seed = seed;
    }

    public int iteration() {
        return iteration;
    }

    public SecretKeySpec seed() {
        return seed;
    }

    public SignalSenderMessageKey toSenderMessageKey(Mac mac) {
        try {
            mac.init(seed);
            var messageKeySeed = mac.doFinal(MESSAGE_KEY_SEED);
            return new SignalSenderMessageKey(mac, iteration, messageKeySeed);
        } catch (InvalidKeyException e) {
            throw new InternalError(e);
        }
    }

    public SignalSenderChainKey next(Mac mac) {
        try {
            mac.init(seed);
            var nextSeed = new SecretKeySpec(mac.doFinal(CHAIN_KEY_SEED), "HmacSHA256");
            return new SignalSenderChainKey(iteration + 1, nextSeed);
        } catch (InvalidKeyException e) {
            throw new InternalError(e);
        }
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this ||
                obj instanceof SignalSenderChainKey that && this.iteration == that.iteration;
    }

    @Override
    public int hashCode() {
        return Objects.hash(iteration);
    }

    @Override
    public String toString() {
        return "SenderChainKey[" +
                "iteration=" + iteration + ", " +
                "seed=" + Arrays.toString(seed.getEncoded()) + ']';
    }
}