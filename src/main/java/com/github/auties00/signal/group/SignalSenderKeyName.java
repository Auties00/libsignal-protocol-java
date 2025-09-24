package com.github.auties00.signal.group;

import com.github.auties00.signal.SignalAddress;
import it.auties.protobuf.annotation.ProtobufDeserializer;
import it.auties.protobuf.annotation.ProtobufSerializer;

public record SignalSenderKeyName(String groupId, SignalAddress sender) {
    @ProtobufDeserializer
    public static SignalSenderKeyName of(String serialized) {
        var split = serialized.split("::", 3);
        var groupJid = split[0];
        var address = new SignalAddress(split[1], Integer.parseUnsignedInt(split[2]));
        return new SignalSenderKeyName(groupJid, address);
    }

    @ProtobufSerializer
    @Override
    public String toString() {
        return "%s::%s::%s".formatted(groupId, sender.name(), sender.id());
    }
}
