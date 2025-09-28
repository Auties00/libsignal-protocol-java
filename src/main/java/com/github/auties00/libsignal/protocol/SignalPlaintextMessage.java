package com.github.auties00.libsignal.protocol;

public sealed abstract class SignalPlaintextMessage extends SignalProtocolMessage
        permits SignalDeviceConsistencyMessage {
}
