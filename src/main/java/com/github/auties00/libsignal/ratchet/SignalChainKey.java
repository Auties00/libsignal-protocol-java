package com.github.auties00.libsignal.ratchet;

import com.github.auties00.libsignal.kdf.HKDF;
import com.github.auties00.libsignal.mixins.HmacSha256KeySpecMixin;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@ProtobufMessage
public final class SignalChainKey {
    private static final byte[] MESSAGE_KEY_SEED = {0x01};
    private static final byte[] CHAIN_KEY_SEED = {0x02};
    private static final byte[] MESSAGE_KEY_INFO = "WhisperMessageKeys".getBytes(StandardCharsets.UTF_8);

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int index;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES, mixins = HmacSha256KeySpecMixin.class)
    final SecretKeySpec key;

    SignalChainKey(int index, SecretKeySpec key) {
        this.index = index;
        this.key = key;
    }

    public int index() {
        return index;
    }

    public SecretKeySpec key() {
        return key;
    }

    public SignalChainKey next() {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            return next(mac);
        }catch (NoSuchAlgorithmException e) {
            throw new InternalError(e);
        }
    }

    public SignalChainKey next(Mac mac) {
        try {
            mac.init(key);
            var nextKey = new SecretKeySpec(mac.doFinal(CHAIN_KEY_SEED), "HmacSHA256");
            return new SignalChainKey(index + 1, nextKey);
        }catch (InvalidKeyException e) {
            throw new InternalError(e);
        }
    }

    public SignalMessageKey toMessageKeys(HKDF hkdf) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            return toMessageKeys(hkdf, mac);
        }catch (GeneralSecurityException e) {
            throw new InternalError(e);
        }
    }

    public SignalMessageKey toMessageKeys(HKDF hkdf, Mac mac) {
        try {
            mac.init(key);
            var inputKeyMaterial = mac.doFinal(MESSAGE_KEY_SEED);
            var data = hkdf.deriveSecrets(mac, inputKeyMaterial, MESSAGE_KEY_INFO, 80);
            var cipherKey = new SecretKeySpec(data, 0, 32, "AES");
            var macKey = new SecretKeySpec(data, 32, 32, "HmacSHA256");
            var iv = new IvParameterSpec(data, 64,  16);
            return new SignalMessageKey(index, cipherKey, macKey, iv);
        }catch (InvalidKeyException e) {
            throw new InternalError(e);
        }
    }
}