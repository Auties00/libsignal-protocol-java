package com.github.auties00.signal.group;

import com.github.auties00.signal.SignalStore;
import com.github.auties00.signal.group.state.SignalSenderKeyRecord;
import com.github.auties00.signal.key.SignalIdentityKeyPair;
import com.github.auties00.signal.protocol.SignalSenderKeyDistributionMessage;
import com.github.auties00.signal.protocol.SignalSenderKeyDistributionMessageBuilder;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SignalGroupSessionBuilder {
    private final SignalStore store;

    public SignalGroupSessionBuilder(SignalStore store) {
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
            var signatureKey = SignalIdentityKeyPair.random().publicKey();
            senderKeyRecord.setSenderKeyState(
                    senderKeyId,
                    0,
                    senderKey,
                    signatureKey
            );
        }

        var state = senderKeyRecord.findSenderKeyState()
                .orElseThrow(() -> new IllegalStateException("No sender key state found"));

        return new SignalSenderKeyDistributionMessageBuilder()
                .id(state.id())
                .iteration(state.chainKey().iteration())
                .chainKey(state.chainKey().seed())
                .signatureKey(state.signatureKey().publicKey())
                .build();
    }

    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        }catch (NoSuchAlgorithmException exception) {
            throw new AssertionError("No secure random algorithm", exception);
        }
    }
}
