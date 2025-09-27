package com.github.auties00.libsignal;

import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufSerializer;

import java.util.Objects;

public record SignalProtocolAddress(String name, int id) {
    @ProtobufDeserializer
    public static SignalProtocolAddress of(String serialized) {
        var split = serialized.split(":", 2);
        if (split.length != 2) {
            throw new IllegalArgumentException("Malformed address: " + serialized);
        }
        return new SignalProtocolAddress(split[0], Integer.parseInt(split[1]));
    }

    @ProtobufSerializer
    @Override
    public String toString() {
        return "%s:%s".formatted(name(), id());
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, id);
    }
}
