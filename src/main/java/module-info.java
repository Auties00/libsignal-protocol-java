module com.github.auties00.libsignal {
    requires com.github.auties00.curve25519;
    requires it.auties.protobuf.base;

    exports com.github.auties00.libsignal;
    exports com.github.auties00.libsignal.devices;
    exports com.github.auties00.libsignal.fingerprint;
    exports com.github.auties00.libsignal.groups;
    exports com.github.auties00.libsignal.groups.ratchet;
    exports com.github.auties00.libsignal.groups.state;
    exports com.github.auties00.libsignal.key;
    exports com.github.auties00.libsignal.protocol;
    exports com.github.auties00.libsignal.ratchet;
    exports com.github.auties00.libsignal.state;
    exports com.github.auties00.libsignal.kdf;
}