/*
package com.github.auties00.libsignal.test.groups;

import com.github.auties00.libsignal.SignalAddress;
import com.github.auties00.libsignal.groups.SignalGroupCipher;
import com.github.auties00.libsignal.groups.SignalGroupSessionBuilder;
import com.github.auties00.libsignal.groups.SignalSenderKeyName;
import com.github.auties00.libsignal.protocol.SignalSenderKeyDistributionMessage;
import com.github.auties00.libsignal.test.InMemorySignalDataStore;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SignalGroupSessionCipherTest {

    private static final SignalAddress SENDER_ADDRESS = new SignalAddress("+14150001111", 1);
    private static final SignalSenderKeyName GROUP_SENDER = new SignalSenderKeyName("nihilist history reading group", SENDER_ADDRESS);

    @Test
    public void testNoSession() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, GROUP_SENDER);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, GROUP_SENDER);

        var sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
        var receivedAliceDistributionMessage = SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());

        //    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt("smert ze smert".getBytes());
        try {
            var plaintextFromAlice = bobSignalGroupCipher.decrypt(ciphertextFromAlice);
            throw new InternalError("Should be no session!");
        } catch (RuntimeException e) {
            // good
        }
    }

    @Test
    public void testBasicEncryptDecrypt() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, GROUP_SENDER);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, GROUP_SENDER);

        var sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
        var receivedAliceDistributionMessage = SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());
        bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt("smert ze smert".getBytes());
        var plaintextFromAlice = bobSignalGroupCipher.decrypt(ciphertextFromAlice);

        assertEquals("smert ze smert", new String(plaintextFromAlice));
    }

    @Test
    public void testLargeMessages() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, GROUP_SENDER);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, GROUP_SENDER);

        var sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
        var receivedAliceDistributionMessage = SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());
        bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        var plaintext = new byte[1024 * 1024];
        new Random().nextBytes(plaintext);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt(plaintext);
        var plaintextFromAlice = bobSignalGroupCipher.decrypt(ciphertextFromAlice);

        assertArrayEquals(plaintext, plaintextFromAlice);
    }

    @Test
    public void testBasicRatchet() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);

        var aliceName = GROUP_SENDER;

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, aliceName);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, aliceName);

        var sentAliceDistributionMessage =
                aliceSessionBuilder.create(aliceName);
        var receivedAliceDistributionMessage =
                SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());

        bobSessionBuilder.process(aliceName, receivedAliceDistributionMessage);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt("smert ze smert".getBytes());
        var ciphertextFromAlice2 = aliceSignalGroupCipher.encrypt("smert ze smert2".getBytes());
        var ciphertextFromAlice3 = aliceSignalGroupCipher.encrypt("smert ze smert3".getBytes());

        var plaintextFromAlice = bobSignalGroupCipher.decrypt(ciphertextFromAlice);

        try {
            bobSignalGroupCipher.decrypt(ciphertextFromAlice);
            throw new InternalError("Should have ratcheted forward!");
        } catch (RuntimeException dme) {
            // good
        }

        var plaintextFromAlice2 = bobSignalGroupCipher.decrypt(ciphertextFromAlice2);
        var plaintextFromAlice3 = bobSignalGroupCipher.decrypt(ciphertextFromAlice3);

        assertEquals("smert ze smert", new String(plaintextFromAlice));
        assertEquals("smert ze smert2", new String(plaintextFromAlice2));
        assertEquals("smert ze smert3", new String(plaintextFromAlice3));
    }

    @Test
    public void testLateJoin() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);


        var aliceName = GROUP_SENDER;

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, aliceName);


        var aliceDistributionMessage = aliceSessionBuilder.create(aliceName);
        // Send off to some people.

        for (var i = 0; i < 100; i++) {
            aliceSignalGroupCipher.encrypt("up the punks up the punks up the punks".getBytes());
        }

        // Now Bob Joins.
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, aliceName);


        var distributionMessageToBob = aliceSessionBuilder.create(aliceName);
        bobSessionBuilder.process(aliceName, SignalSenderKeyDistributionMessage.ofSerialized(distributionMessageToBob.toSerialized()));

        var ciphertext = aliceSignalGroupCipher.encrypt("welcome to the group".getBytes());
        var plaintext = bobSignalGroupCipher.decrypt(ciphertext);

        assertEquals("welcome to the group", new String(plaintext));
    }


    @Test
    public void testOutOfOrder() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);

        var aliceName = GROUP_SENDER;

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, aliceName);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, aliceName);

        var aliceDistributionMessage =
                aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        var ciphertexts = new ArrayList<byte[]>(100);

        for (var i = 0; i < 100; i++) {
            ciphertexts.add(aliceSignalGroupCipher.encrypt("up the punks".getBytes()));
        }

        while (!ciphertexts.isEmpty()) {
            var index = randomInt() % ciphertexts.size();
            var ciphertext = ciphertexts.remove(index);
            var plaintext = bobSignalGroupCipher.decrypt(ciphertext);

            assertEquals("up the punks", new String(plaintext));
        }
    }

    @Test
    public void testEncryptNoSession() {
        var aliceStore = new InMemorySignalDataStore();
        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, new SignalSenderKeyName("coolio groupio", new SignalAddress("+10002223333", 1)));
        try {
            aliceSignalGroupCipher.encrypt("up the punks".getBytes());
            throw new InternalError("Should have failed!");
        } catch (RuntimeException nse) {
            // good
        }
    }


    @Test
    public void testTooFarInFuture() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);

        var aliceName = GROUP_SENDER;

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, aliceName);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, aliceName);

        var aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        for (var i = 0; i < 2001; i++) {
            aliceSignalGroupCipher.encrypt("up the punks".getBytes());
        }

        var tooFarCiphertext = aliceSignalGroupCipher.encrypt("notta gonna worka".getBytes());
        try {
            bobSignalGroupCipher.decrypt(tooFarCiphertext);
            throw new InternalError("Should have failed!");
        } catch (RuntimeException e) {
            // good
        }
    }

    @Test
    public void testMessageKeyLimit() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

        var aliceSessionBuilder = new SignalGroupSessionBuilder(aliceStore);
        var bobSessionBuilder = new SignalGroupSessionBuilder(bobStore);

        var aliceName = GROUP_SENDER;

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore, aliceName);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore, aliceName);

        var aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        List<byte[]> inflight = new LinkedList<>();

        for (var i = 0; i < 2010; i++) {
            inflight.add(aliceSignalGroupCipher.encrypt("up the punks".getBytes()));
        }

        bobSignalGroupCipher.decrypt(inflight.get(1000));
        bobSignalGroupCipher.decrypt(inflight.getLast());

        try {
            bobSignalGroupCipher.decrypt(inflight.getFirst());
            throw new InternalError("Should have failed!");
        } catch (RuntimeException e) {
            // good
        }
    }


    private int randomInt() {
        try {
            return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError(e);
        }
    }
}

 */