package com.github.auties00.libsignal.test;

import com.github.auties00.libsignal.SignalProtocolAddress;
import com.github.auties00.libsignal.SignalSessionBuilder;
import com.github.auties00.libsignal.SignalSessionCipher;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalMessage;
import com.github.auties00.libsignal.ratchet.SignalAliceParametersBuilder;
import com.github.auties00.libsignal.ratchet.SignalBobParametersBuilder;
import com.github.auties00.libsignal.ratchet.SignalRatchetingSession;
import com.github.auties00.libsignal.state.SignalSessionRecord;
import com.github.auties00.libsignal.state.SignalSessionState;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class SignalSessionCipherTest {
    @Test
    public void testBasicSessionV3() {
        var aliceSessionRecord = new SignalSessionRecord();
        var bobSessionRecord = new SignalSessionRecord();

        initializeSessionsV3(aliceSessionRecord.sessionState(), bobSessionRecord.sessionState());
        runInteraction(aliceSessionRecord, bobSessionRecord);
    }

    @Test
    public void testMessageKeyLimits()  {
        var aliceSessionRecord = new SignalSessionRecord();
        var bobSessionRecord = new SignalSessionRecord();

        initializeSessionsV3(aliceSessionRecord.sessionState(), bobSessionRecord.sessionState());

        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceAddress = new SignalProtocolAddress("+14159999999", 1);
        aliceSessionRecord.setFresh(false);
        aliceStore.addSession(aliceAddress, aliceSessionRecord);

        var bobAddress = new SignalProtocolAddress("+14158888888", 1);
        bobSessionRecord.setFresh(false);
        bobStore.addSession(bobAddress, bobSessionRecord);

        var aliceBuilder = new SignalSessionBuilder(aliceStore, aliceAddress);
        var aliceCipher = new SignalSessionCipher(aliceStore, aliceBuilder, aliceAddress);
        var bobBuilder = new SignalSessionBuilder(bobStore, bobAddress);
        var bobCipher = new SignalSessionCipher(bobStore, bobBuilder, bobAddress);

        List<SignalCiphertextMessage> inflight = new LinkedList<>();

        for (var i = 0; i < 2010; i++) {
            inflight.add(aliceCipher.encrypt("you've never been so hungry, you've never been so cold".getBytes()));
        }

        bobCipher.decrypt(SignalMessage.ofSerialized(inflight.get(1000).toSerialized()));
        bobCipher.decrypt(SignalMessage.ofSerialized(inflight.getLast().toSerialized()));

        try {
            bobCipher.decrypt(SignalMessage.ofSerialized(inflight.get(0).toSerialized()));
            throw new InternalError("Should have failed!");
        } catch (Throwable dme) {
            // good
        }
    }

    private void runInteraction(SignalSessionRecord aliceSessionRecord, SignalSessionRecord bobSessionRecord) {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceAddress = new SignalProtocolAddress("+14159999999", 1);
        aliceSessionRecord.setFresh(false);
        aliceStore.addSession(aliceAddress, aliceSessionRecord);

        var bobAddress = new SignalProtocolAddress("+14158888888", 1);
        bobSessionRecord.setFresh(false);
        bobStore.addSession(bobAddress, bobSessionRecord);

        var aliceBuilder = new SignalSessionBuilder(aliceStore, aliceAddress);
        var aliceCipher = new SignalSessionCipher(aliceStore, aliceBuilder, aliceAddress);
        var bobBuilder = new  SignalSessionBuilder(bobStore, bobAddress);
        var bobCipher = new SignalSessionCipher(bobStore, bobBuilder, bobAddress);

        var alicePlaintext = "This is a plaintext message.".getBytes();
        var message = aliceCipher.encrypt(alicePlaintext);
        var bobPlaintext = bobCipher.decrypt(SignalMessage.ofSerialized(message.toSerialized()));

        assertArrayEquals(alicePlaintext, bobPlaintext);

        var bobReply = "This is a message from Bob.".getBytes();
        var reply = bobCipher.encrypt(bobReply);
        var receivedReply = aliceCipher.decrypt(SignalMessage.ofSerialized(reply.toSerialized()));

        assertArrayEquals(bobReply, receivedReply);

        List<SignalCiphertextMessage> aliceCiphertextMessages = new ArrayList<>();
        List<byte[]> alicePlaintextMessages = new ArrayList<>();

        for (var i = 0; i < 50; i++) {
            alicePlaintextMessages.add(("смерть за смерть " + i).getBytes());
            aliceCiphertextMessages.add(aliceCipher.encrypt(("смерть за смерть " + i).getBytes()));
        }

        var seed = System.currentTimeMillis();

        Collections.shuffle(aliceCiphertextMessages, new Random(seed));
        Collections.shuffle(alicePlaintextMessages, new Random(seed));

        for (var i = 0; i < aliceCiphertextMessages.size() / 2; i++) {
            var receivedPlaintext = bobCipher.decrypt(SignalMessage.ofSerialized(aliceCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, alicePlaintextMessages.get(i));
        }

        List<SignalCiphertextMessage> bobCiphertextMessages = new ArrayList<>();
        List<byte[]> bobPlaintextMessages = new ArrayList<>();

        for (var i = 0; i < 20; i++) {
            bobPlaintextMessages.add(("смерть за смерть " + i).getBytes());
            bobCiphertextMessages.add(bobCipher.encrypt(("смерть за смерть " + i).getBytes()));
        }

        seed = System.currentTimeMillis();

        Collections.shuffle(bobCiphertextMessages, new Random(seed));
        Collections.shuffle(bobPlaintextMessages, new Random(seed));

        for (var i = 0; i < bobCiphertextMessages.size() / 2; i++) {
            var receivedPlaintext = aliceCipher.decrypt(SignalMessage.ofSerialized(bobCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, bobPlaintextMessages.get(i));
        }

        for (var i = aliceCiphertextMessages.size() / 2; i < aliceCiphertextMessages.size(); i++) {
            var receivedPlaintext = bobCipher.decrypt(SignalMessage.ofSerialized(aliceCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, alicePlaintextMessages.get(i));
        }

        for (var i = bobCiphertextMessages.size() / 2; i < bobCiphertextMessages.size(); i++) {
            var receivedPlaintext = aliceCipher.decrypt(SignalMessage.ofSerialized(bobCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, bobPlaintextMessages.get(i));
        }
    }

    private void initializeSessionsV3(SignalSessionState aliceSessionState, SignalSessionState bobSessionState)
    {
        var aliceIdentityKeyPair = SignalIdentityKeyPair.random();
        var aliceIdentityKey = new SignalIdentityKeyPair(aliceIdentityKeyPair.publicKey(), aliceIdentityKeyPair.privateKey());
        var aliceBaseKey = SignalIdentityKeyPair.random();
        var aliceEphemeralKey = SignalIdentityKeyPair.random();

        var alicePreKey = aliceBaseKey;

        var bobIdentityKeyPair = SignalIdentityKeyPair.random();
        var bobIdentityKey = new SignalIdentityKeyPair(bobIdentityKeyPair.publicKey(),
                bobIdentityKeyPair.privateKey());
        var bobBaseKey = SignalIdentityKeyPair.random();
        var bobEphemeralKey = bobBaseKey;

        var bobPreKey = SignalIdentityKeyPair.random();

        var aliceParameters = new SignalAliceParametersBuilder()
                .ourBaseKey(aliceBaseKey)
                .ourIdentityKey(aliceIdentityKey)
                .theirOneTimePreKey((SignalIdentityPublicKey) null)
                .theirRatchetKey(bobEphemeralKey.publicKey())
                .theirSignedPreKey(bobBaseKey.publicKey())
                .theirIdentityKey(bobIdentityKey.publicKey())
                .build();

        var bobParameters = new SignalBobParametersBuilder()
                .ourRatchetKey(bobEphemeralKey)
                .ourSignedPreKey(bobBaseKey)
                .ourOneTimePreKey(null)
                .ourIdentityKey(bobIdentityKey)
                .theirIdentityKey(aliceIdentityKey.publicKey())
                .theirBaseKey(aliceBaseKey.publicKey())
                .build();

        SignalRatchetingSession.initializeSession(aliceSessionState, aliceParameters);
        SignalRatchetingSession.initializeSession(bobSessionState, bobParameters);
    }

}