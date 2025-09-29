package com.github.auties00.libsignal.mixins;

import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufMixin;
import it.auties.protobuf.annotation.ProtobufSerializer;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

@ProtobufMixin
public final class AesSecretKeySpecMixin {
    @ProtobufDeserializer
    public static SecretKeySpec deserialize(ByteBuffer buffer) {
        if (buffer.hasArray()) {
            return new SecretKeySpec(buffer.array(), buffer.position(), buffer.remaining(), "AES");
        } else {
            var array = new byte[buffer.remaining()];
            buffer.get(array);
            return new SecretKeySpec(array, "AES");
        }
    }

    @ProtobufSerializer
    public static ByteBuffer serialize(SecretKeySpec key) {
        return ByteBuffer.wrap(key.getEncoded());
    }
}
