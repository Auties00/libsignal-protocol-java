/*
package com.github.auties00.libsignal.test;

import com.github.auties00.libsignal.SignalAddress;
import com.github.auties00.libsignal.SignalSessionCipher;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalMessage;
import com.github.auties00.libsignal.state.SignalSessionRecord;
import com.github.auties00.libsignal.state.SignalSessionState;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class SessionCipherTest {
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

        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        aliceStore.addSession(new SignalAddress("+14159999999", 1), aliceSessionRecord);
        bobStore.addSession(new SignalAddress("+14158888888", 1), bobSessionRecord);

        var aliceCipher = new SignalSessionCipher(aliceStore, new SignalAddress("+14159999999", 1));
        var bobCipher = new SignalSessionCipher(bobStore, new SignalAddress("+14158888888", 1));

        List<SignalCiphertextMessage> inflight = new LinkedList<>();

        for (int i = 0; i < 2010; i++) {
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
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        aliceStore.addSession(new SignalAddress("+14159999999", 1), aliceSessionRecord);
        bobStore.addSession(new SignalAddress("+14158888888", 1), bobSessionRecord);

        var aliceCipher = new SignalSessionCipher(aliceStore, new SignalAddress("+14159999999", 1));
        var bobCipher = new SignalSessionCipher(bobStore, new SignalAddress("+14158888888", 1));

        byte[] alicePlaintext = "This is a plaintext message.".getBytes();
        var message = aliceCipher.encrypt(alicePlaintext);
        byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));

        assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));

        byte[] bobReply = "This is a message from Bob.".getBytes();
        var reply = bobCipher.encrypt(bobReply);
        byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));

        assertTrue(Arrays.equals(bobReply, receivedReply));

        List<SignalCiphertextMessage> aliceCiphertextMessages = new ArrayList<>();
        List<byte[]> alicePlaintextMessages = new ArrayList<>();

        for (int i = 0; i < 50; i++) {
            alicePlaintextMessages.add(("смерть за смерть " + i).getBytes());
            aliceCiphertextMessages.add(aliceCipher.encrypt(("смерть за смерть " + i).getBytes()));
        }

        long seed = System.currentTimeMillis();

        Collections.shuffle(aliceCiphertextMessages, new Random(seed));
        Collections.shuffle(alicePlaintextMessages, new Random(seed));

        for (int i = 0; i < aliceCiphertextMessages.size() / 2; i++) {
            byte[] receivedPlaintext = bobCipher.decrypt(SignalMessage.ofSerialized(aliceCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, alicePlaintextMessages.get(i));
        }

        List<SignalCiphertextMessage> bobCiphertextMessages = new ArrayList<>();
        List<byte[]> bobPlaintextMessages = new ArrayList<>();

        for (int i = 0; i < 20; i++) {
            bobPlaintextMessages.add(("смерть за смерть " + i).getBytes());
            bobCiphertextMessages.add(bobCipher.encrypt(("смерть за смерть " + i).getBytes()));
        }

        seed = System.currentTimeMillis();

        Collections.shuffle(bobCiphertextMessages, new Random(seed));
        Collections.shuffle(bobPlaintextMessages, new Random(seed));

        for (int i = 0; i < bobCiphertextMessages.size() / 2; i++) {
            byte[] receivedPlaintext = aliceCipher.decrypt(SignalMessage.ofSerialized(bobCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, bobPlaintextMessages.get(i));
        }

        for (int i = aliceCiphertextMessages.size() / 2; i < aliceCiphertextMessages.size(); i++) {
            byte[] receivedPlaintext = bobCipher.decrypt(SignalMessage.ofSerialized(aliceCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, alicePlaintextMessages.get(i));
        }

        for (int i = bobCiphertextMessages.size() / 2; i < bobCiphertextMessages.size(); i++) {
            byte[] receivedPlaintext = aliceCipher.decrypt(SignalMessage.ofSerialized(bobCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, bobPlaintextMessages.get(i));
        }
    }

    private void initializeSessionsV3(SignalSessionState aliceSessionState, SignalSessionState bobSessionState)
             {
        ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                aliceIdentityKeyPair.getPrivateKey());
        ECKeyPair aliceBaseKey = Curve.generateKeyPair();
        ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

        ECKeyPair alicePreKey = aliceBaseKey;

        ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                bobIdentityKeyPair.getPrivateKey());
        ECKeyPair bobBaseKey = Curve.generateKeyPair();
        ECKeyPair bobEphemeralKey = bobBaseKey;

        ECKeyPair bobPreKey = Curve.generateKeyPair();

        AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.newBuilder()
                .setOurBaseKey(aliceBaseKey)
                .setOurIdentityKey(aliceIdentityKey)
                .setTheirOneTimePreKey(Optional.<ECPublicKey>absent())
                .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                .create();

        BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.newBuilder()
                .setOurRatchetKey(bobEphemeralKey)
                .setOurSignedPreKey(bobBaseKey)
                .setOurOneTimePreKey(Optional.<ECKeyPair>absent())
                .setOurIdentityKey(bobIdentityKey)
                .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                .setTheirBaseKey(aliceBaseKey.getPublicKey())
                .create();

        RatchetingSession.initializeSession(aliceSessionState, aliceParameters);
        RatchetingSession.initializeSession(bobSessionState, bobParameters);
    }

}

 */