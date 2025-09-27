package com.github.auties00.libsignal.ratchet;

import com.github.auties00.libsignal.kdf.HKDF;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

// TODO: Disable builder
@ProtobufMessage
public final class SignalChainKey {
    private static final byte[] MESSAGE_KEY_SEED = {0x01};
    private static final byte[] CHAIN_KEY_SEED = {0x02};
    private static final byte[] MESSAGE_KEY_INFO = "WhisperMessageKeys".getBytes(StandardCharsets.UTF_8);

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    final int index;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final byte[] key;

    SignalChainKey(int index, byte[] key) {
        this.index = index;
        this.key = key;
    }

    public int index() {
        return index;
    }

    public byte[] key() {
        return key;
    }

    public SignalChainKey next() {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            var nextKey = mac.doFinal(CHAIN_KEY_SEED);
            return new SignalChainKey(index + 1, nextKey);
        }catch (GeneralSecurityException e) {
            throw new InternalError(e);
        }
    }

    public SignalMessageKey toMessageKeys(HKDF hkdf) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            var inputKeyMaterial = mac.doFinal(MESSAGE_KEY_SEED);
            var data = hkdf.deriveSecrets(mac, inputKeyMaterial, MESSAGE_KEY_INFO, 80);
            var cipherKey = Arrays.copyOfRange(data, 0, 32);
            var macKey = Arrays.copyOfRange(data, 32, 64);
            var iv = Arrays.copyOfRange(data, 64, 80);
            return new SignalMessageKey(index, cipherKey, macKey, iv);
        }catch (GeneralSecurityException e) {
            throw new InternalError(e);
        }
    }
}