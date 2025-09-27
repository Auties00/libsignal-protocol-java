package com.github.auties00.libsignal;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalKeyDirection;
import com.github.auties00.libsignal.protocol.SignalPreKeyMessage;
import com.github.auties00.libsignal.ratchet.SignalAliceParametersBuilder;
import com.github.auties00.libsignal.ratchet.SignalBobParametersBuilder;
import com.github.auties00.libsignal.ratchet.SignalRatchetingSession;
import com.github.auties00.libsignal.state.SignalPendingPreKeyBuilder;
import com.github.auties00.libsignal.state.SignalPreKeyBundle;
import com.github.auties00.libsignal.state.SignalSessionRecord;

import java.util.OptionalInt;

public final class SignalSessionBuilder {
    private final SignalProtocolStore store;
    private final SignalProtocolAddress remoteAddress;

    public SignalSessionBuilder(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
        this.store = store;
        this.remoteAddress = remoteAddress;
    }

    OptionalInt process(SignalSessionRecord sessionRecord, SignalPreKeyMessage message) {
        var theirIdentityKey = message.identityKey();
        if (!store.isTrustedIdentity(remoteAddress, theirIdentityKey, SignalKeyDirection.INCOMING)) {
            throw new SecurityException("The identity key of the incoming message is not trusted");
        }

        var unsignedPreKeyId = processV3(sessionRecord, message);
        store.addTrustedIdentity(remoteAddress, theirIdentityKey);
        return unsignedPreKeyId;
    }

    private OptionalInt processV3(SignalSessionRecord sessionRecord, SignalPreKeyMessage message) {
        if (sessionRecord.hasSessionState(message.version(), message.baseKey().toSerialized())) {
            return OptionalInt.empty();
        }

        var ourSignedPreKey = store.findSignedPreKeyById(message.signedPreKeyId())
                .orElseThrow(() -> new IllegalStateException("No signed prekey found with id " + message.signedPreKeyId()));
        var parameters = new SignalBobParametersBuilder()
                .theirBaseKey(message.baseKey())
                .theirIdentityKey(message.identityKey())
                .ourIdentityKey(store.identityKeyPair())
                .ourSignedPreKey(ourSignedPreKey.keyPair())
                .ourRatchetKey(ourSignedPreKey.keyPair());

        message.preKeyId().ifPresent(preKeyId -> {
            var preKey = store.findPreKeyById(preKeyId)
                    .orElseThrow(() -> new IllegalStateException("No prekey found with id " + preKeyId));
            parameters.ourOneTimePreKey(preKey.keyPair());
        });

        if (!sessionRecord.isFresh()) {
            sessionRecord.archiveCurrentState();
        }

        SignalRatchetingSession.initializeSession(sessionRecord.sessionState(), parameters.build());

        sessionRecord.sessionState()
                .setLocalRegistrationId(store.registrationId());
        sessionRecord.sessionState()
                .setRemoteRegistrationId(message.registrationId());
        sessionRecord.sessionState()
                .setBaseKey(message.baseKey().toSerialized());

        return message.preKeyId();
    }

    public void process(SignalPreKeyBundle preKey) {
        if (!store.isTrustedIdentity(remoteAddress, preKey.identityKey(), SignalKeyDirection.OUTGOING)) {
            throw new SecurityException("The identity key of the incoming message is not trusted");
        }

        var theirSignedPreKey = preKey.signedPreKeyPublic();
        if (preKey.signedPreKeyPublic() == null) {
            throw new SecurityException("No signed prekey!");
        }

        if (!Curve25519.verifySignature(preKey.identityKey().toEncodedPoint(),
                theirSignedPreKey.toSerialized(),
                preKey.signedPreKeySignature())) {
            throw new SecurityException("Invalid signature on device key!");
        }

        var sessionRecord = store.findSessionByAddress(remoteAddress)
                .orElseGet(SignalSessionRecord::new);

        var ourBaseKey = SignalIdentityKeyPair.random();

        var theirOneTimePreKey = preKey.preKeyPublic();
        var theirOneTimePreKeyId = theirOneTimePreKey != null ? preKey.preKeyId() : null;

        var parameters = new SignalAliceParametersBuilder()
                .ourBaseKey(ourBaseKey)
                .ourIdentityKey(store.identityKeyPair())
                .theirIdentityKey(preKey.identityKey())
                .theirSignedPreKey(theirSignedPreKey)
                .theirRatchetKey(theirSignedPreKey)
                .theirOneTimePreKey(theirOneTimePreKey);

        if (!sessionRecord.isFresh()) {
            sessionRecord.archiveCurrentState();
        }

        SignalRatchetingSession.initializeSession(sessionRecord.sessionState(), parameters.build());

        var pendingPreKey = new SignalPendingPreKeyBuilder()
                .preKeyId(theirOneTimePreKeyId)
                .signedKeyId(preKey.signedPreKeyId())
                .baseKey(ourBaseKey.publicKey())
                .build();

        sessionRecord.sessionState()
                .setPendingPreKey(pendingPreKey);
        sessionRecord.sessionState()
                .setLocalRegistrationId(store.registrationId());
        sessionRecord.sessionState()
                .setRemoteRegistrationId(preKey.registrationId());
        sessionRecord.sessionState()
                .setBaseKey(ourBaseKey.publicKey().toSerialized());

        store.addTrustedIdentity(remoteAddress, preKey.identityKey());

        sessionRecord.setFresh(false);
        store.addSession(remoteAddress, sessionRecord);
    }
}
