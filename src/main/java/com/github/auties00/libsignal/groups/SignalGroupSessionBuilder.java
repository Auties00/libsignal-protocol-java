package com.github.auties00.libsignal.groups;

import com.github.auties00.libsignal.SignalProtocolStore;
import com.github.auties00.libsignal.groups.state.SignalSenderKeyRecord;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalSenderKeyDistributionMessage;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SignalGroupSessionBuilder {
    private final SignalProtocolStore store;

    public SignalGroupSessionBuilder(SignalProtocolStore store) {
        this.store = store;
    }

    public void process(SignalSenderKeyName senderKeyName, SignalSenderKeyDistributionMessage senderKeyDistributionMessage) {
        var senderKeyRecord = store.findSenderKeyByName(senderKeyName).orElseGet(() -> {
            var record = new SignalSenderKeyRecord();
            store.addSenderKey(senderKeyName, record);
            return record;
        });
        senderKeyRecord.addSenderKeyState(
                senderKeyDistributionMessage.id(),
                senderKeyDistributionMessage.iteration(),
                senderKeyDistributionMessage.chainKey(),
                senderKeyDistributionMessage.signatureKey()
        );
    }

    public SignalSenderKeyDistributionMessage create(SignalSenderKeyName senderKeyName) {
        var senderKeyRecord = store.findSenderKeyByName(senderKeyName).orElseGet(() -> {
            var record = new SignalSenderKeyRecord();
            store.addSenderKey(senderKeyName, record);
            return record;
        });

        if (senderKeyRecord.isEmpty()) {
            var random = getSecureRandom();
            var senderKeyId = random.nextInt(Integer.MAX_VALUE);
            var senderKey = new byte[32];
            random.nextBytes(senderKey);
            senderKeyRecord.setSenderKeyState(
                    senderKeyId,
                    0,
                    senderKey,
                    SignalIdentityKeyPair.random()
            );
        }

        var state = senderKeyRecord.findSenderKeyState()
                .orElseThrow(() -> new IllegalStateException("No sender key state found"));

        // TODO: Switch to builder when possible
        return new SignalSenderKeyDistributionMessage(SignalCiphertextMessage.CURRENT_VERSION, state.id(), state.senderChainKey().iteration(), state.senderChainKey().seed(), state.signatureKey().publicKey());
    }

    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError(e);
        }
    }
}
