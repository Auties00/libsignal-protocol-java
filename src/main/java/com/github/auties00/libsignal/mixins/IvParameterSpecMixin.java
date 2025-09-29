package com.github.auties00.libsignal.mixins;

import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufMixin;
import it.auties.protobuf.annotation.ProtobufSerializer;

import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;

@ProtobufMixin
public final class IvParameterSpecMixin {
    @ProtobufDeserializer
    public static IvParameterSpec deserialize(ByteBuffer buffer) {
        if (buffer.hasArray()) {
            return new IvParameterSpec(buffer.array(), buffer.position(), buffer.remaining());
        } else {
            var array = new byte[buffer.remaining()];
            buffer.get(array);
            return new IvParameterSpec(array);
        }
    }

    @ProtobufSerializer
    public static ByteBuffer serialize(IvParameterSpec iv) {
        return ByteBuffer.wrap(iv.getIV());
    }
}
