package com.github.auties00.libsignal.groups;

import com.github.auties00.libsignal.InMemorySignalProtocolStore;
import com.github.auties00.libsignal.SignalProtocolAddress;
import com.github.auties00.libsignal.protocol.SignalSenderKeyDistributionMessage;
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

    private static final SignalProtocolAddress SENDER_ADDRESS = new SignalProtocolAddress("+14150001111", 1);
    private static final SignalSenderKeyName GROUP_SENDER = new SignalSenderKeyName("nihilist history reading group", SENDER_ADDRESS);

    @Test
    public void testNoSession() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);

        var sentAliceDistributionMessage = aliceSignalGroupCipher.create(GROUP_SENDER);
        var receivedAliceDistributionMessage = SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());

        //    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "smert ze smert".getBytes());
        try {
            var plaintextFromAlice = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertextFromAlice.toSerialized());
            throw new InternalError("Should be no session!");
        } catch (RuntimeException e) {
            // good
        }
    }

    @Test
    public void testBasicEncryptDecrypt() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);

        var sentAliceDistributionMessage = aliceSignalGroupCipher.create(GROUP_SENDER);
        var receivedAliceDistributionMessage = SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());
        bobSignalGroupCipher.process(GROUP_SENDER, receivedAliceDistributionMessage);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "smert ze smert".getBytes());
        var plaintextFromAlice = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertextFromAlice.toSerialized());

        assertEquals("smert ze smert", new String(plaintextFromAlice));
    }

    @Test
    public void testLargeMessages() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);

        var sentAliceDistributionMessage = aliceSignalGroupCipher.create(GROUP_SENDER);
        var receivedAliceDistributionMessage = SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());
        bobSignalGroupCipher.process(GROUP_SENDER, receivedAliceDistributionMessage);

        var plaintext = new byte[1024 * 1024];
        new Random().nextBytes(plaintext);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt(GROUP_SENDER, plaintext);
        var plaintextFromAlice = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertextFromAlice.toSerialized());

        assertArrayEquals(plaintext, plaintextFromAlice);
    }

    @Test
    public void testBasicRatchet() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);

        var sentAliceDistributionMessage =
                aliceSignalGroupCipher.create(GROUP_SENDER);
        var receivedAliceDistributionMessage =
                SignalSenderKeyDistributionMessage.ofSerialized(sentAliceDistributionMessage.toSerialized());

        bobSignalGroupCipher.process(GROUP_SENDER, receivedAliceDistributionMessage);

        var ciphertextFromAlice = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "smert ze smert".getBytes());
        var ciphertextFromAlice2 = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "smert ze smert2".getBytes());
        var ciphertextFromAlice3 = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "smert ze smert3".getBytes());

        var plaintextFromAlice = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertextFromAlice.toSerialized());

        try {
            bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertextFromAlice.toSerialized());
            throw new InternalError("Should have ratcheted forward!");
        } catch (RuntimeException dme) {
            // good
        }

        var plaintextFromAlice2 = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertextFromAlice2.toSerialized());
        var plaintextFromAlice3 = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertextFromAlice3.toSerialized());

        assertEquals("smert ze smert", new String(plaintextFromAlice));
        assertEquals("smert ze smert2", new String(plaintextFromAlice2));
        assertEquals("smert ze smert3", new String(plaintextFromAlice3));
    }

    @Test
    public void testLateJoin() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);


        var aliceDistributionMessage = aliceSignalGroupCipher.create(GROUP_SENDER);
        // Send off to some people.

        for (var i = 0; i < 100; i++) {
            aliceSignalGroupCipher.encrypt(GROUP_SENDER, "up the punks up the punks up the punks".getBytes());
        }

        // Now Bob Joins.
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);


        var distributionMessageToBob = aliceSignalGroupCipher.create(GROUP_SENDER);
        bobSignalGroupCipher.process(GROUP_SENDER, SignalSenderKeyDistributionMessage.ofSerialized(distributionMessageToBob.toSerialized()));

        var ciphertext = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "welcome to the group".getBytes());
        var plaintext = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertext.toSerialized());

        assertEquals("welcome to the group", new String(plaintext));
    }


    @Test
    public void testOutOfOrder() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);

        var aliceDistributionMessage =
                aliceSignalGroupCipher.create(GROUP_SENDER);

        bobSignalGroupCipher.process(GROUP_SENDER, aliceDistributionMessage);

        var ciphertexts = new ArrayList<byte[]>(100);

        for (var i = 0; i < 100; i++) {
            var message = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "up the punks".getBytes());
            ciphertexts.add(message.toSerialized());
        }

        while (!ciphertexts.isEmpty()) {
            var index = randomInt() % ciphertexts.size();
            var ciphertext = ciphertexts.remove(index);
            var plaintext = bobSignalGroupCipher.decrypt(GROUP_SENDER, ciphertext);

            assertEquals("up the punks", new String(plaintext));
        }
    }

    @Test
    public void testEncryptNoSession() {
        var aliceStore = new InMemorySignalProtocolStore();
        var senderKeyName = new SignalSenderKeyName("coolio groupio", new SignalProtocolAddress("+10002223333", 1));
        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        try {
            aliceSignalGroupCipher.encrypt(senderKeyName, "up the punks".getBytes());
            throw new InternalError("Should have failed!");
        } catch (RuntimeException nse) {
            // good
        }
    }


    @Test
    public void testTooFarInFuture() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);

        var aliceDistributionMessage = aliceSignalGroupCipher.create(GROUP_SENDER);

        bobSignalGroupCipher.process(GROUP_SENDER, aliceDistributionMessage);

        for (var i = 0; i < 2001; i++) {
            aliceSignalGroupCipher.encrypt(GROUP_SENDER, "up the punks".getBytes());
        }

        var tooFarCiphertext = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "notta gonna worka".getBytes());
        try {
            bobSignalGroupCipher.decrypt(GROUP_SENDER, tooFarCiphertext.toSerialized());
            throw new InternalError("Should have failed!");
        } catch (RuntimeException e) {
            // good
        }
    }

    @Test
    public void testMessageKeyLimit() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSignalGroupCipher = new SignalGroupCipher(aliceStore);
        var bobSignalGroupCipher = new SignalGroupCipher(bobStore);

        var aliceDistributionMessage = aliceSignalGroupCipher.create(GROUP_SENDER);

        bobSignalGroupCipher.process(GROUP_SENDER, aliceDistributionMessage);

        List<byte[]> inflight = new LinkedList<>();

        for (var i = 0; i < 2010; i++) {
            var message = aliceSignalGroupCipher.encrypt(GROUP_SENDER, "up the punks".getBytes());
            inflight.add(message.toSerialized());
        }

        bobSignalGroupCipher.decrypt(GROUP_SENDER, inflight.get(1000));
        bobSignalGroupCipher.decrypt(GROUP_SENDER, inflight.getLast());

        try {
            bobSignalGroupCipher.decrypt(GROUP_SENDER, inflight.getFirst());
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
