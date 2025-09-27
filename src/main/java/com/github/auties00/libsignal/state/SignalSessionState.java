package com.github.auties00.libsignal.state;

import com.github.auties00.libsignal.groups.ratchet.SignalSenderMessageKey;
import com.github.auties00.libsignal.kdf.HKDF;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.ratchet.SignalRootKey;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;

import java.util.*;

@ProtobufMessage
public final class SignalSessionState {
    private static final int DEFAULT_SESSION_VERSION = 2;

    @ProtobufProperty(index = 1, type = ProtobufType.UINT32)
    Integer sessionVersion;

    @ProtobufProperty(index = 2, type = ProtobufType.BYTES)
    SignalIdentityPublicKey localIdentityPublic;

    @ProtobufProperty(index = 3, type = ProtobufType.BYTES)
    SignalIdentityPublicKey remoteIdentityPublic;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    SignalRootKey rootKey;

    @ProtobufProperty(index = 5, type = ProtobufType.UINT32)
    Integer previousCounter;

    @ProtobufProperty(index = 6, type = ProtobufType.MESSAGE)
    SignalSessionChain senderChain;

    @ProtobufProperty(index = 7, type = ProtobufType.MESSAGE)
    final ReceiverChains receiverChains;

    @ProtobufProperty(index = 8, type = ProtobufType.MESSAGE)
    SignalPendingKeyExchange pendingKeyExchange;

    @ProtobufProperty(index = 9, type = ProtobufType.MESSAGE)
    SignalPendingPreKey pendingPreKey;

    @ProtobufProperty(index = 10, type = ProtobufType.UINT32)
    Integer remoteRegistrationId;

    @ProtobufProperty(index = 11, type = ProtobufType.UINT32)
    Integer localRegistrationId;

    @ProtobufProperty(index = 12, type = ProtobufType.BOOL)
    boolean needsRefresh;

    @ProtobufProperty(index = 13, type = ProtobufType.BYTES)
    byte[] baseKey;

    public SignalSessionState() {
        this.receiverChains = new ReceiverChains();
    }

    SignalSessionState(Integer sessionVersion, SignalIdentityPublicKey localIdentityPublic, SignalIdentityPublicKey remoteIdentityPublic, SignalRootKey rootKey, Integer previousCounter, SignalSessionChain senderChain, ReceiverChains receiverChains, SignalPendingKeyExchange pendingKeyExchange, SignalPendingPreKey pendingPreKey, Integer remoteRegistrationId, Integer localRegistrationId, boolean needsRefresh, byte[] baseKey) {
        this.sessionVersion = sessionVersion;
        this.localIdentityPublic = localIdentityPublic;
        this.remoteIdentityPublic = remoteIdentityPublic;
        this.previousCounter = previousCounter;
        this.senderChain = senderChain;
        this.receiverChains = receiverChains;
        this.pendingKeyExchange = pendingKeyExchange;
        this.pendingPreKey = pendingPreKey;
        this.remoteRegistrationId = remoteRegistrationId;
        this.localRegistrationId = localRegistrationId;
        this.needsRefresh = needsRefresh;
        this.baseKey = baseKey;
        this.rootKey = rootKey;
    }

    public byte[] baseKey() {
        return baseKey;
    }

    public void setBaseKey(byte[] baseKey) {
        this.baseKey = baseKey;
    }

    public void setSessionVersion(Integer sessionVersion) {
        this.sessionVersion = sessionVersion;
    }

    public int sessionVersion() {
        return Objects.requireNonNullElse(sessionVersion, DEFAULT_SESSION_VERSION);
    }

    public void setRemoteIdentityPublic(SignalIdentityPublicKey remoteIdentityPublic) {
        this.remoteIdentityPublic = remoteIdentityPublic;
    }

    public void setLocalIdentityPublic(SignalIdentityPublicKey localIdentityPublic) {
        this.localIdentityPublic = localIdentityPublic;
    }

    public SignalIdentityPublicKey remoteIdentityPublic() {
        return remoteIdentityPublic;
    }

    public SignalIdentityPublicKey localIdentityPublic() {
        return localIdentityPublic;
    }

    public Integer previousCounter() {
        return previousCounter;
    }

    public void setPreviousCounter(Integer previousCounter) {
        this.previousCounter = previousCounter;
    }

    public SignalRootKey rootKey() {
        return rootKey;
    }

    public void setRootKey(SignalRootKey rootKey) {
        this.rootKey = rootKey;
    }

    public Optional<SignalSessionChain> findReceiverChain(SignalIdentityPublicKey senderEphemeral) {
        return senderEphemeral == null ? Optional.empty() : receiverChains.get(senderEphemeral);
    }

    public void addReceiverChain(SignalSessionChain chain) {
        receiverChains.add(chain);
    }

    public Integer localRegistrationId() {
        return localRegistrationId;
    }

    public void setLocalRegistrationId(Integer localRegistrationId) {
        this.localRegistrationId = localRegistrationId;
    }

    public Integer remoteRegistrationId() {
        return remoteRegistrationId;
    }

    public void setRemoteRegistrationId(Integer remoteRegistrationId) {
        this.remoteRegistrationId = remoteRegistrationId;
    }

    public Optional<SignalPendingPreKey> pendingPreKey() {
        return Optional.ofNullable(pendingPreKey);
    }

    public void setPendingPreKey(SignalPendingPreKey pendingPreKey) {
        this.pendingPreKey = pendingPreKey;
    }

    public Optional<SignalSessionChain> senderChain() {
        return Optional.ofNullable(senderChain);
    }

    public void setSenderChain(SignalSessionChain chain) {
        this.senderChain = chain;
    }

    public SequencedCollection<? extends SignalSessionChain> receiverChains() {
        return receiverChains.values();
    }

    public boolean needsRefresh() {
        return needsRefresh;
    }

    public void setNeedsRefresh(boolean needsRefresh) {
        this.needsRefresh = needsRefresh;
    }

    public SignalPendingKeyExchange pendingKeyExchange() {
        return pendingKeyExchange;
    }

    public void setPendingKeyExchange(SignalPendingKeyExchange pendingKeyExchange) {
        this.pendingKeyExchange = pendingKeyExchange;
    }

    public void setReceiverChains(SequencedCollection<? extends SignalSessionChain> chains) {
        receiverChains.clear();
        receiverChains.addAll(chains);
    }

    static final class ReceiverChains extends AbstractCollection<SignalSessionChain> {
        private static final int MAX_RECEIVER_CHAINS = 5;

        private final SequencedMap<SignalIdentityPublicKey, SignalSessionChain> backing;

        public ReceiverChains() {
            this.backing = new LinkedHashMap<>(MAX_RECEIVER_CHAINS, 0.75F, true);
        }

        public Optional<SignalSessionChain> get(SignalIdentityPublicKey publicKey) {
            return Optional.ofNullable(backing.get(publicKey));
        }

        @Override
        public boolean add(SignalSessionChain chain) {
            if (backing.size() == MAX_RECEIVER_CHAINS) {
                backing.pollFirstEntry();
            }
            backing.put(chain.senderRatchetKey(), chain);
            return true;
        }

        @Override
        public void clear() {
            backing.clear();
        }

        @Override
        public Iterator<SignalSessionChain> iterator() {
            return backing.sequencedValues()
                    .iterator();
        }

        @Override
        public int size() {
            return backing.size();
        }

        public SequencedCollection<? extends SignalSessionChain> values() {
            return Collections.unmodifiableSequencedCollection(backing.sequencedValues());
        }
    }
}
