/*
package com.github.auties00.libsignal.test;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.SignalAddress;
import com.github.auties00.libsignal.SignalSessionCipher;
import com.github.auties00.libsignal.SignalDataStore;
import com.github.auties00.libsignal.SignalSessionBuilder;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.state.SignalPreKeyBundle;
import com.github.auties00.libsignal.state.SignalPreKeyBundleBuilder;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class SimultaneousInitiateTests {

    private static final SignalAddress BOB_ADDRESS = new SignalAddress("+14151231234", 1);
    private static final SignalAddress ALICE_ADDRESS = new SignalAddress("+14159998888", 1);

    private static final SignalIdentityKeyPair aliceSignedPreKey = SignalIdentityKeyPair.random();
    private static final SignalIdentityKeyPair bobSignedPreKey = SignalIdentityKeyPair.random();

    private static final int aliceSignedPreKeyId = new Random().nextInt(0xFFFFFF);
    private static final int bobSignedPreKeyId = new Random().nextInt(0xFFFFFF);

    @Test
    public void testBasicSimultaneousInitiate() {
        var aliceStore = new InMemorySignalDataStore();
        var bobStore = new InMemorySignalDataStore();

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

        assertSame(messageForBob.getType(), SignalCiphertextMessage.PRE_KEY_TYPE);
        assertSame(messageForAlice.getType(), SignalCiphertextMessage.PRE_KEY_TYPE);

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertTrue(aliceStore.findSessionByAddress(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
        assertTrue(bobStore.findSessionByAddress(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testLostSimultaneousInitiate()  {
        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertSame(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
        assertSame(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

        assertEquals("hey there", new String(bobPlaintext));
        assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(aliceResponse.getType(), CiphertextMessage.PREKEY_TYPE);

        byte[] responsePlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(aliceResponse.serialize()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testSimultaneousInitiateLostMessage() {
        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertSame(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
        assertSame(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
        assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

//    byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));
//
//    assertTrue(new String(responsePlaintext).equals("second message"));
//    assertTrue(isSessionIdEqual(aliceStore, bobStore));
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testSimultaneousInitiateRepeatedMessages()
            throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
            InvalidMessageException, DuplicateMessageException, LegacyMessageException,
            InvalidKeyIdException, NoSessionException {
        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertSame(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
        assertSame(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
        assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        for (int i = 0; i < 50; i++) {
            CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(messageForBobRepeat.getType(), CiphertextMessage.WHISPER_TYPE);
            assertSame(messageForAliceRepeat.getType(), CiphertextMessage.WHISPER_TYPE);

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
            byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testRepeatedSimultaneousInitiateRepeatedMessages()
            throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
            InvalidMessageException, DuplicateMessageException, LegacyMessageException,
            InvalidKeyIdException, NoSessionException {
        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();


        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        for (int i = 0; i < 15; i++) {
            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
            assertSame(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

            assertEquals("sample message", new String(alicePlaintext));
            assertEquals("hey there", new String(bobPlaintext));

            assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
            assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (int i = 0; i < 50; i++) {
            CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(messageForBobRepeat.getType(), CiphertextMessage.WHISPER_TYPE);
            assertSame(messageForAliceRepeat.getType(), CiphertextMessage.WHISPER_TYPE);

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
            byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testRepeatedSimultaneousInitiateLostMessageRepeatedMessages() {
        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();


        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

//    PreKeyBundle aliceLostPreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobLostPreKeyBundle = createBobPreKeyBundle(bobStore);

        aliceSessionBuilder.process(bobLostPreKeyBundle);
//    bobSessionBuilder.process(aliceLostPreKeyBundle);

        CiphertextMessage lostMessageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
//    CiphertextMessage lostMessageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        for (int i = 0; i < 15; i++) {
            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
            assertSame(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

            assertEquals("sample message", new String(alicePlaintext));
            assertEquals("hey there", new String(bobPlaintext));

            assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
            assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (int i = 0; i < 50; i++) {
            CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertSame(messageForBobRepeat.getType(), CiphertextMessage.WHISPER_TYPE);
            assertSame(messageForAliceRepeat.getType(), CiphertextMessage.WHISPER_TYPE);

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
            byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertSame(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertSame(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        byte[] lostMessagePlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(lostMessageForBob.serialize()));
        assertEquals("hey there", new String(lostMessagePlaintext));

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage blastFromThePast = bobSessionCipher.encrypt("unexpected!".getBytes());
        byte[] blastFromThePastPlaintext = aliceSessionCipher.decrypt(new SignalMessage(blastFromThePast.serialize()));

        assertEquals("unexpected!", new String(blastFromThePastPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    private boolean isSessionIdEqual(SignalProtocolStore aliceStore, SignalProtocolStore bobStore) {
        return Arrays.equals(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getAliceBaseKey(),
                bobStore.loadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
    }

    private SignalPreKeyBundle createAlicePreKeyBundle(SignalDataStore aliceStore)  {
        var aliceUnsignedPreKey = SignalIdentityKeyPair.random();
        int aliceUnsignedPreKeyId = new Random().nextInt(0xFFFFFF);
        byte[] aliceSignature = Curve25519.sign(aliceStore.identityKeyPair().privateKey().toEncodedPoint(),
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
        aliceStore.addSignedPreKey(aliceSignedPreKeyId, new SignedPreKeyRecord(aliceSignedPreKeyId, System.currentTimeMillis(), aliceSignedPreKey, aliceSignature));
        aliceStore.addPreKey(aliceUnsignedPreKeyId, new PreKeyRecord(aliceUnsignedPreKeyId, aliceUnsignedPreKey));
        return alicePreKeyBundle;
    }

    private SignalPreKeyBundle createBobPreKeyBundle(SignalDataStore bobStore)  {
        var bobUnsignedPreKey = SignalIdentityKeyPair.random();
        int bobUnsignedPreKeyId = new Random().nextInt(0xFFFFFF);
        byte[] bobSignature = Curve.calculateSignature(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKey.publicKey().toSerialized());

        var bobPreKeyBundle = new PreKeyBundle(1, 1,
                bobUnsignedPreKeyId, bobUnsignedPreKey.getPublicKey(),
                bobSignedPreKeyId, bobSignedPreKey.getPublicKey(),
                bobSignature, bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.addSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId, System.currentTimeMillis(), bobSignedPreKey, bobSignature));
        bobStore.addPreKey(bobUnsignedPreKeyId, new PreKeyRecord(bobUnsignedPreKeyId, bobUnsignedPreKey));

        return bobPreKeyBundle;
    }
}

 */