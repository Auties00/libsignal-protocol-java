package com.github.auties00.libsignal.state;

import com.github.auties00.libsignal.key.SignalIdentityPrivateKey;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.ratchet.SignalChainKey;
import com.github.auties00.libsignal.ratchet.SignalMessageKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.*;

@ProtobufMessage
public final class SignalSessionChain {
    @ProtobufProperty(index = 1, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey senderRatchetKey;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    final SignalIdentityPrivateKey senderRatchetKeyPrivate;

    @ProtobufProperty(index = 4, type = ProtobufType.MESSAGE)
    SignalChainKey chainKey;

    @ProtobufProperty(index = 3, type = ProtobufType.MESSAGE)
    final MessageKeys messageKeys;

    SignalSessionChain(SignalIdentityPublicKey senderRatchetKey, SignalIdentityPrivateKey senderRatchetKeyPrivate, SignalChainKey chainKey, MessageKeys messageKeys) {
        this.senderRatchetKey = senderRatchetKey;
        this.senderRatchetKeyPrivate = senderRatchetKeyPrivate;
        this.chainKey = chainKey;
        this.messageKeys = messageKeys;
    }

    public SignalIdentityPublicKey senderRatchetKey() {
        return senderRatchetKey;
    }

    public SignalIdentityPrivateKey senderRatchetKeyPrivate() {
        return senderRatchetKeyPrivate;
    }

    public SignalChainKey chainKey() {
        return chainKey;
    }

    public void setChainKey(SignalChainKey chainKey) {
        this.chainKey = chainKey;
    }

    public boolean hasMessageKey(int index) {
        return messageKeys.contains(index);
    }

    public void addMessageKey(SignalMessageKey senderMessageKey) {
        messageKeys.add(senderMessageKey);
    }

    public Optional<SignalMessageKey> removeMessageKey(int index) {
        return messageKeys.remove(index);
    }

    public SequencedCollection<? extends SignalMessageKey> messageKeys() {
        return messageKeys.values();
    }

    public void setMessageKeys(SequencedCollection<? extends SignalMessageKey> messageKeys) {
        this.messageKeys.clear();
        this.messageKeys.addAll(messageKeys);
    }

    static final class MessageKeys extends AbstractCollection<SignalMessageKey> {
        private static final int MAX_MESSAGE_KEYS = 2000;

        private final SequencedMap<Integer, SignalMessageKey> backing;

        public MessageKeys() {
            this.backing = new LinkedHashMap<>(MAX_MESSAGE_KEYS, 0.75F, true);
        }


        public Optional<SignalMessageKey> remove(int index) {
            return Optional.ofNullable(backing.remove(index));
        }

        public boolean contains(int index) {
            return backing.get(index) != null;
        }

        @Override
        public void clear() {
            backing.clear();
        }

        @Override
        public boolean add(SignalMessageKey senderKeyState) {
            if (backing.size() == MAX_MESSAGE_KEYS) {
                backing.pollFirstEntry();
            }

            backing.put(senderKeyState.counter(), senderKeyState);
            return true;
        }

        @Override
        public Iterator<SignalMessageKey> iterator() {
            return backing.sequencedValues().iterator();
        }

        @Override
        public int size() {
            return backing.size();
        }

        public SequencedCollection<? extends SignalMessageKey> values() {
            return Collections.unmodifiableSequencedCollection(backing.sequencedValues());
        }
    }
}