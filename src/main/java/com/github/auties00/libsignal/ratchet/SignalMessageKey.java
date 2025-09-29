package com.github.auties00.libsignal.ratchet;

import com.github.auties00.libsignal.mixins.AesSecretKeySpecMixin;
import com.github.auties00.libsignal.mixins.HmacSha256KeySpecMixin;
import com.github.auties00.libsignal.mixins.IvParameterSpecMixin;
import it.auties.protobuf.annotation.*;
import it.auties.protobuf.model.ProtobufType;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@ProtobufMessage
public final class SignalMessageKey {
    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int counter;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES, mixins = AesSecretKeySpecMixin.class)
    final SecretKeySpec cipherKey;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES, mixins = HmacSha256KeySpecMixin.class)
    final SecretKeySpec macKey;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES, mixins = IvParameterSpecMixin.class)
    final IvParameterSpec iv;

    SignalMessageKey(int counter, SecretKeySpec cipherKey, SecretKeySpec macKey, IvParameterSpec iv) {
        this.counter = counter;
        this.cipherKey = cipherKey;
        this.macKey = macKey;
        this.iv = iv;
    }

    public int counter() {
        return counter;
    }

    public SecretKeySpec cipherKey() {
        return cipherKey;
    }

    public SecretKeySpec macKey() {
        return macKey;
    }

    public IvParameterSpec iv() {
        return iv;
    }
}