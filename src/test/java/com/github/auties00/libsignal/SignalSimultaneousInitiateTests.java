
package com.github.auties00.libsignal;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalPreKeyPairBuilder;
import com.github.auties00.libsignal.key.SignalSignedKeyPairBuilder;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalMessage;
import com.github.auties00.libsignal.protocol.SignalPreKeyMessage;
import com.github.auties00.libsignal.state.SignalPreKeyBundle;
import com.github.auties00.libsignal.state.SignalPreKeyBundleBuilder;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class SignalSimultaneousInitiateTests {

    private static final SignalProtocolAddress BOB_ADDRESS = new SignalProtocolAddress("+14151231234", 1);
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14159998888", 1);

    private static final SignalIdentityKeyPair aliceSignedPreKey = SignalIdentityKeyPair.random();
    private static final SignalIdentityKeyPair bobSignedPreKey = SignalIdentityKeyPair.random();

    private static final int aliceSignedPreKeyId = new Random().nextInt(0xFFFFFF);
    private static final int bobSignedPreKeyId = new Random().nextInt(0xFFFFFF);

    @Test
    public void testBasicSimultaneousInitiate() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var alicePlaintext = aliceSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
        var bobPlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testLostSimultaneousInitiate()  {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var bobPlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("hey there", new String(bobPlaintext));
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        var aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testSimultaneousInitiateLostMessage() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var alicePlaintext = aliceSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
        var bobPlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

//    byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));
//
//    assertTrue(new String(responsePlaintext).equals("second message"));
//    assertTrue(isSessionIdEqual(aliceStore, bobStore));
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testSimultaneousInitiateRepeatedMessages() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var alicePlaintext = aliceSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
        var bobPlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        for (var i = 0; i < 50; i++) {
            var messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            var messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForBobRepeat.type());
            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintextRepeat = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(messageForAliceRepeat.toSerialized()));
            var bobPlaintextRepeat = bobSessionCipher.decrypt(SignalMessage.ofSerialized(messageForBobRepeat.toSerialized()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        var aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testRepeatedSimultaneousInitiateRepeatedMessages() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

        for (var i = 0; i < 15; i++) {
            var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            var messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
            var messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintext = aliceSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
            var bobPlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

            assertEquals("sample message", new String(alicePlaintext));
            assertEquals("hey there", new String(bobPlaintext));

            assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
            assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (var i = 0; i < 50; i++) {
            var messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            var messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForBobRepeat.type());
            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintextRepeat = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(messageForAliceRepeat.toSerialized()));
            var bobPlaintextRepeat = bobSessionCipher.decrypt(SignalMessage.ofSerialized(messageForBobRepeat.toSerialized()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        var aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testRepeatedSimultaneousInitiateLostMessageRepeatedMessages() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSessionBuilder = new SignalSessionBuilder(aliceStore, BOB_ADDRESS);
        var bobSessionBuilder = new SignalSessionBuilder(bobStore, ALICE_ADDRESS);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore, aliceSessionBuilder, BOB_ADDRESS);
        var bobSessionCipher = new SignalSessionCipher(bobStore, bobSessionBuilder, ALICE_ADDRESS);

//    PreKeyBundle aliceLostPreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobLostPreKeyBundle = createBobPreKeyBundle(bobStore);

        aliceSessionBuilder.process(bobLostPreKeyBundle);
//    bobSessionBuilder.process(aliceLostPreKeyBundle);

        var lostMessageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
//    CiphertextMessage lostMessageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        for (var i = 0; i < 15; i++) {
            var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            var messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
            var messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintext = aliceSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
            var bobPlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

            assertEquals("sample message", new String(alicePlaintext));
            assertEquals("hey there", new String(bobPlaintext));

            assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
            assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (var i = 0; i < 50; i++) {
            var messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            var messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForBobRepeat.type());
            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintextRepeat = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(messageForAliceRepeat.toSerialized()));
            var bobPlaintextRepeat = bobSessionCipher.decrypt(SignalMessage.ofSerialized(messageForBobRepeat.toSerialized()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        var aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var lostMessagePlaintext = bobSessionCipher.decrypt(SignalPreKeyMessage.ofSerialized(lostMessageForBob.toSerialized()));
        assertEquals("hey there", new String(lostMessagePlaintext));

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var blastFromThePast = bobSessionCipher.encrypt("unexpected!".getBytes());
        var blastFromThePastPlaintext = aliceSessionCipher.decrypt(SignalMessage.ofSerialized(blastFromThePast.toSerialized()));

        assertEquals("unexpected!", new String(blastFromThePastPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    private boolean isSessionIdEqual(SignalProtocolStore aliceStore, SignalProtocolStore bobStore) {
        return Arrays.equals(aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().baseKey(),
                bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().baseKey());
    }

    private SignalPreKeyBundle createAlicePreKeyBundle(SignalProtocolStore aliceStore)  {
        var aliceUnsignedPreKey = SignalIdentityKeyPair.random();
        var aliceUnsignedPreKeyId = new Random().nextInt(0xFFFFFF);
        var aliceSignature = Curve25519.sign(aliceStore.identityKeyPair().privateKey().toEncodedPoint(),
                aliceSignedPreKey.publicKey().toSerialized());
        var alicePreKeyBundle = new SignalPreKeyBundleBuilder()
                .registrationId(1)
                .deviceId(1)
                .preKeyId(aliceUnsignedPreKeyId)
                .preKeyPublic(aliceUnsignedPreKey.publicKey())
                .signedPreKeyId(aliceSignedPreKeyId)
                .signedPreKeyPublic(aliceSignedPreKey.publicKey())
                .signedPreKeySignature(aliceSignature)
                .identityKey(aliceStore.identityKeyPair().publicKey())
                .build();
        var aliceSignedKeyPair = new SignalSignedKeyPairBuilder()
                .id(aliceSignedPreKeyId)
                .keyPair(aliceSignedPreKey)
                .signature(aliceSignature)
                .build();
        var alicePreKeyPair = new SignalPreKeyPairBuilder()
                .id(aliceUnsignedPreKeyId)
                .keyPair(aliceUnsignedPreKey)
                .build();
        aliceStore.addSignedPreKey(aliceSignedKeyPair);
        aliceStore.addPreKey(alicePreKeyPair);
        return alicePreKeyBundle;
    }

    private SignalPreKeyBundle createBobPreKeyBundle(SignalProtocolStore bobStore)  {
        var bobUnsignedPreKey = SignalIdentityKeyPair.random();
        var bobUnsignedPreKeyId = new Random().nextInt(0xFFFFFF);
        var bobSignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKey.publicKey().toSerialized());

        var bobPreKeyBundle = new SignalPreKeyBundleBuilder()
                .registrationId(1)
                .deviceId(1)
                .preKeyId(bobUnsignedPreKeyId)
                .preKeyPublic(bobUnsignedPreKey.publicKey())
                .signedPreKeyId(bobSignedPreKeyId)
                .signedPreKeyPublic(bobSignedPreKey.publicKey())
                .signedPreKeySignature(bobSignature)
                .identityKey(bobStore.identityKeyPair().publicKey())
                .build();

        var bobSignedKeyPair = new SignalSignedKeyPairBuilder()
                .id(bobSignedPreKeyId)
                .signature(bobSignature)
                .keyPair(bobSignedPreKey)
                .build();
        var bobPreKeyPair = new SignalPreKeyPairBuilder()
                .id(bobUnsignedPreKeyId)
                .keyPair(bobUnsignedPreKey)
                .build();
        bobStore.addSignedPreKey(bobSignedKeyPair);
        bobStore.addPreKey(bobPreKeyPair);

        return bobPreKeyBundle;
    }
}