package com.github.auties00.libsignal;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalPreKeyPairBuilder;
import com.github.auties00.libsignal.key.SignalSignedKeyPairBuilder;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalMessage;
import com.github.auties00.libsignal.protocol.SignalPreKeyMessage;
import com.github.auties00.libsignal.state.SignalPreKeyBundle;
import org.apache.commons.math3.util.Pair;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class SignalSessionBuilderTest {
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
    private static final SignalProtocolAddress BOB_ADDRESS = new SignalProtocolAddress("+14152222222", 1);

    @Test
    public void testBasicPreKeyV2()
    {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new InMemorySignalProtocolStore();
        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                0, null, null,
                bobStore.identityKeyPair().publicKey());

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new InternalError("Should fail with missing unsigned prekey!");
        } catch (RuntimeException e) {
            // Good!
        }
    }

    @Test
    public void testBasicPreKeyV3() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);

        final SignalProtocolStore bobStore = new InMemorySignalProtocolStore();
        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized());

        var bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                22, bobSignedPreKeyPair.publicKey(),
                bobSignedPreKeySignature,
                bobStore.identityKeyPair().publicKey());

        aliceSessionBuilder.process(bobPreKey);

        var session = aliceStore.findSessionByAddress(BOB_ADDRESS);
        assertTrue(session.isPresent());
        assertEquals(3, session.get().sessionState().sessionVersion());

        final var originalMessage = "L'homme est condamné à être libre";
        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessage.type());

        var incomingMessage = SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized());
        var preKey = new SignalPreKeyPairBuilder()
                .id(bobPreKey.preKeyId())
                .keyPair(bobPreKeyPair)
                .build();
        bobStore.addPreKey(preKey);
        var signedPreKey = new SignalSignedKeyPairBuilder()
                .id(22)
                .keyPair(bobSignedPreKeyPair)
                .signature(bobSignedPreKeySignature)
                .build();
        bobStore.addSignedPreKey(signedPreKey);

        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);
        var plaintext = bobSessionCipher.decrypt(incomingMessage);

        var aliceSession = bobStore.findSessionByAddress(ALICE_ADDRESS);
        assertTrue(aliceSession.isPresent());
        assertEquals(3, aliceSession.get().sessionState().sessionVersion());
        assertNotNull(aliceSession.get().sessionState().baseKey());
        assertEquals(originalMessage, new String(plaintext));

        var bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
        assertEquals(SignalCiphertextMessage.WHISPER_TYPE, bobOutgoingMessage.type());

        var alicePlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(bobOutgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(alicePlaintext));

        runInteraction(aliceStore, bobStore);

        aliceStore = new InMemorySignalProtocolStore();
        aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);

        bobPreKeyPair = SignalIdentityKeyPair.random();
        bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        bobSignedPreKeySignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(), bobSignedPreKeyPair.publicKey().toSerialized());
        bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(),
                1, 31338, bobPreKeyPair.publicKey(),
                23, bobSignedPreKeyPair.publicKey(), bobSignedPreKeySignature,
                bobStore.identityKeyPair().publicKey());

        preKey = new SignalPreKeyPairBuilder()
                .id(bobPreKey.preKeyId())
                .keyPair(bobPreKeyPair)
                .build();
        bobStore.addPreKey(preKey);
        signedPreKey = new SignalSignedKeyPairBuilder()
                .id(23)
                .keyPair(bobSignedPreKeyPair)
                .signature(bobSignedPreKeySignature)
                .build();
        bobStore.addSignedPreKey(signedPreKey);
        aliceSessionBuilder.process(bobPreKey);

        outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        try {
            plaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized()));
            throw new InternalError("shouldn't be trusted!");
        } catch (RuntimeException uie) {
            bobStore.addTrustedIdentity(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized()).identityKey());
        }

        plaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(plaintext));

        bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, SignalIdentityKeyPair.random().publicKey(),
                23, bobSignedPreKeyPair.publicKey(), bobSignedPreKeySignature,
                aliceStore.identityKeyPair().publicKey());

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new InternalError("shoulnd't be trusted!");
        } catch (RuntimeException uie) {
            // good
        }
    }

    @Test
    public void testBadSignedPreKeySignature()  {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobIdentityKeyStore = new InMemorySignalProtocolStore();

        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(bobIdentityKeyStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized());


        for (var i = 0; i < bobSignedPreKeySignature.length * 8; i++) {
            var modifiedSignature = new byte[bobSignedPreKeySignature.length];
            System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

            modifiedSignature[i / 8] ^= (0x01 << (i % 8));

            var bobPreKey = new SignalPreKeyBundle(bobIdentityKeyStore.registrationId(), 1,
                    31337, bobPreKeyPair.publicKey(),
                    22, bobSignedPreKeyPair.publicKey(), modifiedSignature,
                    bobIdentityKeyStore.identityKeyPair().publicKey());

            try {
                aliceSessionBuilder.process(bobPreKey);
                throw new InternalError("Accepted modified device key signature!");
            } catch (RuntimeException ike) {
                // good
            }
        }

        var bobPreKey = new SignalPreKeyBundle(bobIdentityKeyStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                22, bobSignedPreKeyPair.publicKey(), bobSignedPreKeySignature,
                bobIdentityKeyStore.identityKeyPair().publicKey());

        aliceSessionBuilder.process(bobPreKey);
    }

    @Test
    public void testRepeatBundleMessageV2()  {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new InMemorySignalProtocolStore();

        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized());

        var bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                0, null, null,
                bobStore.identityKeyPair().publicKey());

        var preKey = new SignalPreKeyPairBuilder()
                .id(bobPreKey.preKeyId())
                .keyPair(bobPreKeyPair)
                .build();
        bobStore.addPreKey(preKey);
        var signedPreKey = new SignalSignedKeyPairBuilder()
                .id(22)
                .keyPair(bobSignedPreKeyPair)
                .signature(bobSignedPreKeySignature)
                .build();
        bobStore.addSignedPreKey(signedPreKey);

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new InternalError("Should fail with missing signed prekey!");
        } catch (RuntimeException e) {
            // Good!
        }
    }

    @Test
    public void testRepeatBundleMessageV3()  {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new InMemorySignalProtocolStore();

        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized());

        var bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                22, bobSignedPreKeyPair.publicKey(), bobSignedPreKeySignature,
                bobStore.identityKeyPair().publicKey());

        var preKey = new SignalPreKeyPairBuilder()
                .id(bobPreKey.preKeyId())
                .keyPair(bobPreKeyPair)
                .build();
        bobStore.addPreKey(preKey);
        var signedPreKey = new SignalSignedKeyPairBuilder()
                .id(22)
                .keyPair(bobSignedPreKeyPair)
                .signature(bobSignedPreKeySignature)
                .build();
        bobStore.addSignedPreKey(signedPreKey);

        aliceSessionBuilder.process(bobPreKey);

        var originalMessage = "L'homme est condamné à être libre";
        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());
        var outgoingMessageTwo = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessageOne.type());
        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessageTwo.type());

        var incomingMessage = SignalPreKeyMessage.ofSerialized(outgoingMessageOne.toSerialized());

        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        var plaintext = bobSessionCipher.decrypt(incomingMessage);
        assertEquals(originalMessage, new String(plaintext));

        var bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

        var alicePlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(bobOutgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(alicePlaintext));

        // The test

        var incomingMessageTwo = SignalPreKeyMessage.ofSerialized(outgoingMessageTwo.toSerialized());

        plaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(incomingMessageTwo.toSerialized()));
        assertEquals(originalMessage, new String(plaintext));

        bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
        alicePlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(bobOutgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(alicePlaintext));

    }

    @Test
    public void testBadMessageBundle()  {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new InMemorySignalProtocolStore();

        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized());

        var bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                22, bobSignedPreKeyPair.publicKey(), bobSignedPreKeySignature,
                bobStore.identityKeyPair().publicKey());

        var preKey = new SignalPreKeyPairBuilder()
                .id(bobPreKey.preKeyId())
                .keyPair(bobPreKeyPair)
                .build();
        bobStore.addPreKey(preKey);
        var signedPreKey = new SignalSignedKeyPairBuilder()
                .id(22)
                .keyPair(bobSignedPreKeyPair)
                .signature(bobSignedPreKeySignature)
                .build();
        bobStore.addSignedPreKey(signedPreKey);

        aliceSessionBuilder.process(bobPreKey);

        var originalMessage = "L'homme est condamné à être libre";
        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessageOne.type());

        var goodMessage = outgoingMessageOne.toSerialized();
        var badMessage = new byte[goodMessage.length];
        System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

        badMessage[badMessage.length - 10] ^= 0x01;

        var incomingMessage = SignalPreKeyMessage.ofSerialized(badMessage);
        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        var plaintext = new byte[0];

        try {
            plaintext = bobSessionCipher.decrypt(incomingMessage);
            throw new InternalError("Decrypt should have failed!");
        } catch (RuntimeException e) {
            // good.
        }

        assertTrue(bobStore.findPreKeyById(31337).isPresent());

        plaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(goodMessage));

        assertEquals(originalMessage, new String(plaintext));
        assertFalse(bobStore.findPreKeyById(31337).isPresent());
    }

    @Test
    public void testOptionalOneTimePreKey()  {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new InMemorySignalProtocolStore();

        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized());

        var bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                0, null,
                22, bobSignedPreKeyPair.publicKey(),
                bobSignedPreKeySignature,
                bobStore.identityKeyPair().publicKey());

        aliceSessionBuilder.process(bobPreKey);

        var aliceSession = aliceStore.findSessionByAddress(BOB_ADDRESS);
        assertTrue(aliceSession.isPresent());
        assertEquals(3, aliceSession.get().sessionState().sessionVersion());

        var originalMessage = "L'homme est condamné à être libre";
        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessage.type());

        var incomingMessage = SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized());
        assertFalse(incomingMessage.preKeyId().isPresent());

        var preKey = new SignalPreKeyPairBuilder()
                .id(bobPreKey.preKeyId())
                .keyPair(bobPreKeyPair)
                .build();
        bobStore.addPreKey(preKey);
        var signedPreKey = new SignalSignedKeyPairBuilder()
                .id(22)
                .keyPair(bobSignedPreKeyPair)
                .signature(bobSignedPreKeySignature)
                .build();
        bobStore.addSignedPreKey(signedPreKey);

        var bobSessionBuilder = new SignalSessionBuilder(bobStore, BOB_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);
        var plaintext = bobSessionCipher.decrypt(incomingMessage);

        var bobSession = bobStore.findSessionByAddress(ALICE_ADDRESS);
        assertTrue(bobSession.isPresent());
        assertEquals(3, bobSession.get().sessionState().sessionVersion());
        assertNotNull(bobSession.get().sessionState().baseKey());
        assertEquals(originalMessage, new String(plaintext));
    }


    private void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
    {
        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var bobSessionBuilder = new  SignalSessionBuilder(bobStore, ALICE_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        var originalMessage = "smert ze smert";
        var aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.WHISPER_TYPE, aliceMessage.type());

        var plaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceMessage.toSerialized()));
        assertEquals(originalMessage, new String(plaintext));

        var bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.WHISPER_TYPE, bobMessage.type());

        plaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(bobMessage.toSerialized()));
        assertEquals(originalMessage, new String(plaintext));

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            var loopingPlaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            var loopingPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(bobLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        Set<Pair<String, SignalCiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
        }

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            var loopingPlaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("You can only desire based on what you know: " + i);
            var bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            var loopingPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(bobLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        for (var aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
            var outOfOrderPlaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceOutOfOrderMessage.getSecond().toSerialized()));
            assertEquals(new String(outOfOrderPlaintext), aliceOutOfOrderMessage.getFirst());
        }
    }
}