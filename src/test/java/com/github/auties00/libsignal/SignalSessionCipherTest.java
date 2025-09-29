package com.github.auties00.libsignal;

import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.key.SignalPreKeyPairBuilder;
import com.github.auties00.libsignal.key.SignalSignedKeyPairBuilder;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalMessage;
import com.github.auties00.libsignal.protocol.SignalPreKeyMessage;
import com.github.auties00.libsignal.ratchet.SignalAliceParametersBuilder;
import com.github.auties00.libsignal.ratchet.SignalBobParametersBuilder;
import com.github.auties00.libsignal.ratchet.SignalRatchetingSession;
import com.github.auties00.libsignal.state.SignalPreKeyBundle;
import com.github.auties00.libsignal.state.SignalPreKeyBundleBuilder;
import com.github.auties00.libsignal.state.SignalSessionRecord;
import com.github.auties00.libsignal.state.SignalSessionState;
import org.apache.commons.math3.util.Pair;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class SignalSessionCipherTest {
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
    private static final SignalProtocolAddress BOB_ADDRESS = new SignalProtocolAddress("+14152222222", 1);

    private static final SignalIdentityKeyPair ALICE_SIGNED_PRE_KEY = SignalIdentityKeyPair.random();
    private static final SignalIdentityKeyPair BOB_SIGNED_PRE_KEY = SignalIdentityKeyPair.random();

    private static final int ALICE_SIGNED_PRE_KEY_ID = new Random().nextInt(0xFFFFFF);
    private static final int BOB_SIGNED_PRE_KEY_ID = new Random().nextInt(0xFFFFFF);


    @Test
    public void testBasicSessionV3() throws NoSuchAlgorithmException {
        var aliceSessionRecord = new SignalSessionRecord();
        var bobSessionRecord = new SignalSessionRecord();

        initializeSessionsV3(aliceSessionRecord.sessionState(), bobSessionRecord.sessionState());
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        aliceSessionRecord.setFresh(false);
        aliceStore.addSession(BOB_ADDRESS, bobSessionRecord);

        bobSessionRecord.setFresh(false);
        bobStore.addSession(ALICE_ADDRESS, aliceSessionRecord);

        var aliceCipher = new SignalSessionCipher(aliceStore);
        var bobCipher = new SignalSessionCipher(bobStore);

        var alicePlaintext = "This is a plaintext message.".getBytes();
        var message = aliceCipher.encrypt(BOB_ADDRESS, alicePlaintext);
        var bobPlaintext = bobCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(message.toSerialized()));

        assertArrayEquals(alicePlaintext, bobPlaintext);

        var bobReply = "This is a message from Bob.".getBytes();
        var reply = bobCipher.encrypt(ALICE_ADDRESS, bobReply);
        var receivedReply = aliceCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(reply.toSerialized()));

        assertArrayEquals(bobReply, receivedReply);

        List<SignalCiphertextMessage> aliceCiphertextMessages = new ArrayList<>();
        List<byte[]> alicePlaintextMessages = new ArrayList<>();

        for (var i = 0; i < 50; i++) {
            alicePlaintextMessages.add(("смерть за смерть " + i).getBytes());
            aliceCiphertextMessages.add(aliceCipher.encrypt(BOB_ADDRESS, ("смерть за смерть " + i).getBytes()));
        }

        var seed = System.currentTimeMillis();

        Collections.shuffle(aliceCiphertextMessages, new Random(seed));
        Collections.shuffle(alicePlaintextMessages, new Random(seed));

        for (var i = 0; i < aliceCiphertextMessages.size() / 2; i++) {
            var receivedPlaintext = bobCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, alicePlaintextMessages.get(i));
        }

        List<SignalCiphertextMessage> bobCiphertextMessages = new ArrayList<>();
        List<byte[]> bobPlaintextMessages = new ArrayList<>();

        for (var i = 0; i < 20; i++) {
            bobPlaintextMessages.add(("смерть за смерть " + i).getBytes());
            bobCiphertextMessages.add(bobCipher.encrypt(ALICE_ADDRESS, ("смерть за смерть " + i).getBytes()));
        }

        seed = System.currentTimeMillis();

        Collections.shuffle(bobCiphertextMessages, new Random(seed));
        Collections.shuffle(bobPlaintextMessages, new Random(seed));

        for (var i = 0; i < bobCiphertextMessages.size() / 2; i++) {
            var receivedPlaintext = aliceCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, bobPlaintextMessages.get(i));
        }

        for (var i = aliceCiphertextMessages.size() / 2; i < aliceCiphertextMessages.size(); i++) {
            var receivedPlaintext = bobCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, alicePlaintextMessages.get(i));
        }

        for (var i = bobCiphertextMessages.size() / 2; i < bobCiphertextMessages.size(); i++) {
            var receivedPlaintext = aliceCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobCiphertextMessages.get(i).toSerialized()));
            assertArrayEquals(receivedPlaintext, bobPlaintextMessages.get(i));
        }
    }

    @Test
    public void testMessageKeyLimits() throws NoSuchAlgorithmException {
        var aliceSessionRecord = new SignalSessionRecord();
        var bobSessionRecord = new SignalSessionRecord();

        initializeSessionsV3(aliceSessionRecord.sessionState(), bobSessionRecord.sessionState());

        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        aliceSessionRecord.setFresh(false);
        aliceStore.addSession(BOB_ADDRESS, bobSessionRecord);

        bobSessionRecord.setFresh(false);
        bobStore.addSession(ALICE_ADDRESS, aliceSessionRecord);

        var aliceCipher = new SignalSessionCipher(aliceStore);
        var bobCipher = new SignalSessionCipher(bobStore);

        List<SignalCiphertextMessage> inflight = new LinkedList<>();

        for (var i = 0; i < 2010; i++) {
            inflight.add(aliceCipher.encrypt(BOB_ADDRESS, "you've never been so hungry, you've never been so cold".getBytes()));
        }

        bobCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(inflight.get(1000).toSerialized()));
        bobCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(inflight.getLast().toSerialized()));

        try {
            bobCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(inflight.getFirst().toSerialized()));
            throw new InternalError("Should have failed!");
        } catch (Throwable dme) {
            // good
        }
    }

    private void initializeSessionsV3(SignalSessionState aliceSessionState, SignalSessionState bobSessionState) throws NoSuchAlgorithmException {
        var aliceIdentityKeyPair = SignalIdentityKeyPair.random();
        var aliceIdentityKey = new SignalIdentityKeyPair(aliceIdentityKeyPair.publicKey(), aliceIdentityKeyPair.privateKey());
        var aliceBaseKey = SignalIdentityKeyPair.random();

        var bobIdentityKeyPair = SignalIdentityKeyPair.random();
        var bobIdentityKey = new SignalIdentityKeyPair(bobIdentityKeyPair.publicKey(),
                bobIdentityKeyPair.privateKey());
        var bobEphemeralKey = SignalIdentityKeyPair.random();

        var aliceParameters = new SignalAliceParametersBuilder()
                .ourBaseKey(aliceBaseKey)
                .ourIdentityKey(aliceIdentityKey)
                .theirOneTimePreKey((SignalIdentityPublicKey) null)
                .theirRatchetKey(bobEphemeralKey.publicKey())
                .theirSignedPreKey(bobEphemeralKey.publicKey())
                .theirIdentityKey(bobIdentityKey.publicKey())
                .build();

        var bobParameters = new SignalBobParametersBuilder()
                .ourRatchetKey(bobEphemeralKey)
                .ourSignedPreKey(bobEphemeralKey)
                .ourOneTimePreKey(null)
                .ourIdentityKey(bobIdentityKey)
                .theirIdentityKey(aliceIdentityKey.publicKey())
                .theirBaseKey(aliceBaseKey.publicKey())
                .build();

        var mac = Mac.getInstance("HmacSHA256");
        SignalRatchetingSession.initializeSession(mac, aliceSessionState, aliceParameters);
        SignalRatchetingSession.initializeSession(mac, bobSessionState, bobParameters);
    }

    @Test
    public void testBasicPreKeyV2() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionCipher = new SignalSessionCipher(aliceStore);

        SignalProtocolStore bobStore = new InMemorySignalProtocolStore();
        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                0, null, null,
                bobStore.identityKeyPair().publicKey());

        try {
            aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);
            throw new InternalError("Should fail with missing unsigned prekey!");
        } catch (RuntimeException e) {
            // Good!
        }
    }

    @Test
    public void testBasicPreKeyV3() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionCipher = new SignalSessionCipher(aliceStore);

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

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);

        var session = aliceStore.findSessionByAddress(BOB_ADDRESS);
        assertTrue(session.isPresent());
        assertEquals(3, session.get().sessionState().sessionVersion());

        final var originalMessage = "L'homme est condamné à être libre";
        var outgoingMessage = aliceSessionCipher.encrypt(BOB_ADDRESS, originalMessage.getBytes());

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

        var bobSessionCipher = new SignalSessionCipher(bobStore);
        var plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, incomingMessage);

        var aliceSession = bobStore.findSessionByAddress(ALICE_ADDRESS);
        assertTrue(aliceSession.isPresent());
        assertEquals(3, aliceSession.get().sessionState().sessionVersion());
        assertNotNull(aliceSession.get().sessionState().baseKey());
        assertEquals(originalMessage, new String(plaintext));

        var bobOutgoingMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, originalMessage.getBytes());
        assertEquals(SignalCiphertextMessage.WHISPER_TYPE, bobOutgoingMessage.type());

        var alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobOutgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(alicePlaintext));

        var aliceSessionCipher1 = new SignalSessionCipher(aliceStore);
        var bobSessionCipher1 = new SignalSessionCipher(bobStore);

        var originalMessage1 = "smert ze smert";
        var aliceMessage = aliceSessionCipher1.encrypt(BOB_ADDRESS, originalMessage1.getBytes());

        assertEquals(SignalCiphertextMessage.WHISPER_TYPE, aliceMessage.type());

        var plaintext1 = bobSessionCipher1.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceMessage.toSerialized()));
        assertEquals(originalMessage1, new String(plaintext1));

        var bobMessage = bobSessionCipher1.encrypt(ALICE_ADDRESS, originalMessage1.getBytes());

        assertEquals(SignalCiphertextMessage.WHISPER_TYPE, bobMessage.type());

        plaintext1 = aliceSessionCipher1.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobMessage.toSerialized()));
        assertEquals(originalMessage1, new String(plaintext1));

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var aliceLoopingMessage = aliceSessionCipher1.encrypt(BOB_ADDRESS, loopingMessage.getBytes());

            var loopingPlaintext = bobSessionCipher1.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var bobLoopingMessage = bobSessionCipher1.encrypt(ALICE_ADDRESS, loopingMessage.getBytes());

            var loopingPlaintext = aliceSessionCipher1.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        Set<Pair<String, SignalCiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var aliceLoopingMessage = aliceSessionCipher1.encrypt(BOB_ADDRESS, loopingMessage.getBytes());

            aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
        }

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            var aliceLoopingMessage = aliceSessionCipher1.encrypt(BOB_ADDRESS, loopingMessage.getBytes());

            var loopingPlaintext = bobSessionCipher1.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        for (var i = 0; i < 10; i++) {
            var loopingMessage = ("You can only desire based on what you know: " + i);
            var bobLoopingMessage = bobSessionCipher1.encrypt(ALICE_ADDRESS, loopingMessage.getBytes());

            var loopingPlaintext = aliceSessionCipher1.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobLoopingMessage.toSerialized()));
            assertEquals(new String(loopingPlaintext), loopingMessage);
        }

        for (var aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
            var outOfOrderPlaintext = bobSessionCipher1.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceOutOfOrderMessage.getSecond().toSerialized()));
            assertEquals(new String(outOfOrderPlaintext), aliceOutOfOrderMessage.getFirst());
        }

        aliceStore = new InMemorySignalProtocolStore();
        aliceSessionCipher = new SignalSessionCipher(aliceStore);

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
        aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);

        outgoingMessage = aliceSessionCipher.encrypt(BOB_ADDRESS, originalMessage.getBytes());

        try {
            plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized()));
            throw new InternalError("shouldn't be trusted!");
        } catch (RuntimeException uie) {
            bobStore.addTrustedIdentity(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized()).identityKey());
        }

        plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(outgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(plaintext));

        bobPreKey = new SignalPreKeyBundle(bobStore.registrationId(), 1,
                31337, SignalIdentityKeyPair.random().publicKey(),
                23, bobSignedPreKeyPair.publicKey(), bobSignedPreKeySignature,
                aliceStore.identityKeyPair().publicKey());

        try {
            aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);
            throw new InternalError("shoulnd't be trusted!");
        } catch (RuntimeException uie) {
            // good
        }
    }

    @Test
    public void testBadSignedPreKeySignature() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
        var aliceSessionCipher = new SignalSessionCipher(aliceStore);

        SignalProtocolStore bobIdentityKeyStore = new InMemorySignalProtocolStore();

        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(bobIdentityKeyStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized());


        for (var i = 0; i < bobSignedPreKeySignature.length * 8; i++) {
            var modifiedSignature = new byte[bobSignedPreKeySignature.length];
            System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

            modifiedSignature[i / 8] ^= (byte) (0x01 << (i % 8));

            var bobPreKey = new SignalPreKeyBundle(bobIdentityKeyStore.registrationId(), 1,
                    31337, bobPreKeyPair.publicKey(),
                    22, bobSignedPreKeyPair.publicKey(), modifiedSignature,
                    bobIdentityKeyStore.identityKeyPair().publicKey());

            try {
                aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);
                throw new InternalError("Accepted modified device key signature!");
            } catch (RuntimeException ike) {
                // good
            }
        }

        var bobPreKey = new SignalPreKeyBundle(bobIdentityKeyStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                22, bobSignedPreKeyPair.publicKey(), bobSignedPreKeySignature,
                bobIdentityKeyStore.identityKeyPair().publicKey());

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);
    }

    @Test
    public void testRepeatBundleMessageV2() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
            var aliceSessionCipher = new SignalSessionCipher(aliceStore);

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
            aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);
            throw new InternalError("Should fail with missing signed prekey!");
        } catch (RuntimeException e) {
            // Good!
        }
    }

    @Test
    public void testRepeatBundleMessageV3() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
            var aliceSessionCipher = new SignalSessionCipher(aliceStore);

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

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);

        var originalMessage = "L'homme est condamné à être libre";
        var outgoingMessageOne = aliceSessionCipher.encrypt(BOB_ADDRESS, originalMessage.getBytes());
        var outgoingMessageTwo = aliceSessionCipher.encrypt(BOB_ADDRESS, originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessageOne.type());
        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessageTwo.type());

        var incomingMessage = SignalPreKeyMessage.ofSerialized(outgoingMessageOne.toSerialized());

        new SignalSessionCipher(bobStore);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

        var plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, incomingMessage);
        assertEquals(originalMessage, new String(plaintext));

        var bobOutgoingMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, originalMessage.getBytes());

        var alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobOutgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(alicePlaintext));

        // The test

        var incomingMessageTwo = SignalPreKeyMessage.ofSerialized(outgoingMessageTwo.toSerialized());

        plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(incomingMessageTwo.toSerialized()));
        assertEquals(originalMessage, new String(plaintext));

        bobOutgoingMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, originalMessage.getBytes());
        alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(bobOutgoingMessage.toSerialized()));
        assertEquals(originalMessage, new String(alicePlaintext));

    }

    @Test
    public void testBadMessageBundle() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
            var aliceSessionCipher = new SignalSessionCipher(aliceStore);

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

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);

        var originalMessage = "L'homme est condamné à être libre";
        var outgoingMessageOne = aliceSessionCipher.encrypt(BOB_ADDRESS, originalMessage.getBytes());

        assertEquals(SignalCiphertextMessage.PRE_KEY_TYPE, outgoingMessageOne.type());

        var goodMessage = outgoingMessageOne.toSerialized();
        var badMessage = new byte[goodMessage.length];
        System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

        badMessage[badMessage.length - 10] ^= 0x01;

        var incomingMessage = SignalPreKeyMessage.ofSerialized(badMessage);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

        var plaintext = new byte[0];

        try {
            plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, incomingMessage);
            throw new InternalError("Decrypt should have failed!");
        } catch (RuntimeException e) {
            // good.
        }

        assertTrue(bobStore.findPreKeyById(31337).isPresent());

        plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(goodMessage));

        assertEquals(originalMessage, new String(plaintext));
        assertFalse(bobStore.findPreKeyById(31337).isPresent());
    }

    @Test
    public void testOptionalOneTimePreKey() {
        SignalProtocolStore aliceStore = new InMemorySignalProtocolStore();
            var aliceSessionCipher = new SignalSessionCipher(aliceStore);

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

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKey);

        var aliceSession = aliceStore.findSessionByAddress(BOB_ADDRESS);
        assertTrue(aliceSession.isPresent());
        assertEquals(3, aliceSession.get().sessionState().sessionVersion());

        var originalMessage = "L'homme est condamné à être libre";
        var outgoingMessage = aliceSessionCipher.encrypt(BOB_ADDRESS, originalMessage.getBytes());

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

        var bobSessionCipher = new SignalSessionCipher(bobStore);
        var plaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, incomingMessage);

        var bobSession = bobStore.findSessionByAddress(ALICE_ADDRESS);
        assertTrue(bobSession.isPresent());
        assertEquals(3, bobSession.get().sessionState().sessionVersion());
        assertNotNull(bobSession.get().sessionState().baseKey());
        assertEquals(originalMessage, new String(plaintext));
    }

    @Test
    public void testBasicSimultaneousInitiate() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKeyBundle);
        bobSessionCipher.process(ALICE_ADDRESS, alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
        var bobPlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var aliceResponse = aliceSessionCipher.encrypt(BOB_ADDRESS, "second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, "third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testLostSimultaneousInitiate() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKeyBundle);
        bobSessionCipher.process(ALICE_ADDRESS, alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var bobPlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("hey there", new String(bobPlaintext));
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        var aliceResponse = aliceSessionCipher.encrypt(BOB_ADDRESS, "second message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, "third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testSimultaneousInitiateLostMessage() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKeyBundle);
        bobSessionCipher.process(ALICE_ADDRESS, alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
        var bobPlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var aliceResponse = aliceSessionCipher.encrypt(BOB_ADDRESS, "second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

//    byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));
//
//    assertTrue(new String(responsePlaintext).equals("second message"));
//    assertTrue(isSessionIdEqual(aliceStore, bobStore));
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, "third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testSimultaneousInitiateRepeatedMessages() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        var aliceSessionCipher = new SignalSessionCipher(aliceStore);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

        aliceSessionCipher.process(BOB_ADDRESS, bobPreKeyBundle);
        bobSessionCipher.process(ALICE_ADDRESS, alicePreKeyBundle);

        var messageForBob = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
        var messageForAlice = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
        assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
        var bobPlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

        assertEquals("sample message", new String(alicePlaintext));
        assertEquals("hey there", new String(bobPlaintext));

        assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
        assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        for (var i = 0; i < 50; i++) {
            var messageForBobRepeat = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
            var messageForAliceRepeat = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForBobRepeat.type());
            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintextRepeat = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(messageForAliceRepeat.toSerialized()));
            var bobPlaintextRepeat = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(messageForBobRepeat.toSerialized()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        var aliceResponse = aliceSessionCipher.encrypt(BOB_ADDRESS, "second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, "third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testRepeatedSimultaneousInitiateRepeatedMessages() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSessionCipher = new SignalSessionCipher(aliceStore);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

        for (var i = 0; i < 15; i++) {
            var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionCipher.process(BOB_ADDRESS, bobPreKeyBundle);
            bobSessionCipher.process(ALICE_ADDRESS, alicePreKeyBundle);

            var messageForBob = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
            var messageForAlice = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
            var bobPlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

            assertEquals("sample message", new String(alicePlaintext));
            assertEquals("hey there", new String(bobPlaintext));

            assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
            assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (var i = 0; i < 50; i++) {
            var messageForBobRepeat = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
            var messageForAliceRepeat = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForBobRepeat.type());
            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintextRepeat = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(messageForAliceRepeat.toSerialized()));
            var bobPlaintextRepeat = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(messageForBobRepeat.toSerialized()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        var aliceResponse = aliceSessionCipher.encrypt(BOB_ADDRESS, "second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, "third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void testRepeatedSimultaneousInitiateLostMessageRepeatedMessages() {
        var aliceStore = new InMemorySignalProtocolStore();
        var bobStore = new InMemorySignalProtocolStore();

        var aliceSessionCipher = new SignalSessionCipher(aliceStore);
        var bobSessionCipher = new SignalSessionCipher(bobStore);

//    PreKeyBundle aliceLostPreKeyBundle = createAlicePreKeyBundle(aliceStore);
        var bobLostPreKeyBundle = createBobPreKeyBundle(bobStore);

        aliceSessionCipher.process(BOB_ADDRESS, bobLostPreKeyBundle);
//    bobSessionBuilder.process(aliceLostPreKeyBundle);

        var lostMessageForBob = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
//    CiphertextMessage lostMessageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        for (var i = 0; i < 15; i++) {
            var alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            var bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionCipher.process(BOB_ADDRESS, bobPreKeyBundle);
            bobSessionCipher.process(ALICE_ADDRESS, alicePreKeyBundle);

            var messageForBob = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
            var messageForAlice = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForBob.type());
            assertSame(SignalCiphertextMessage.PRE_KEY_TYPE, messageForAlice.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForAlice.toSerialized()));
            var bobPlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(messageForBob.toSerialized()));

            assertEquals("sample message", new String(alicePlaintext));
            assertEquals("hey there", new String(bobPlaintext));

            assertEquals(3, aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().sessionVersion());
            assertEquals(3, bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().sessionVersion());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (var i = 0; i < 50; i++) {
            var messageForBobRepeat = aliceSessionCipher.encrypt(BOB_ADDRESS, "hey there".getBytes());
            var messageForAliceRepeat = bobSessionCipher.encrypt(ALICE_ADDRESS, "sample message".getBytes());

            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForBobRepeat.type());
            assertSame(SignalCiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.type());

            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            var alicePlaintextRepeat = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(messageForAliceRepeat.toSerialized()));
            var bobPlaintextRepeat = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(messageForBobRepeat.toSerialized()));

            assertEquals("sample message", new String(alicePlaintextRepeat));
            assertEquals("hey there", new String(bobPlaintextRepeat));

            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        var aliceResponse = aliceSessionCipher.encrypt(BOB_ADDRESS, "second message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, aliceResponse.type());

        var responsePlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalMessage.ofSerialized(aliceResponse.toSerialized()));

        assertEquals("second message", new String(responsePlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var finalMessage = bobSessionCipher.encrypt(ALICE_ADDRESS, "third message".getBytes());

        assertSame(SignalCiphertextMessage.WHISPER_TYPE, finalMessage.type());

        var finalPlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(finalMessage.toSerialized()));

        assertEquals("third message", new String(finalPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        var lostMessagePlaintext = bobSessionCipher.decrypt(ALICE_ADDRESS, SignalPreKeyMessage.ofSerialized(lostMessageForBob.toSerialized()));
        assertEquals("hey there", new String(lostMessagePlaintext));

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        var blastFromThePast = bobSessionCipher.encrypt(ALICE_ADDRESS, "unexpected!".getBytes());
        var blastFromThePastPlaintext = aliceSessionCipher.decrypt(BOB_ADDRESS, SignalMessage.ofSerialized(blastFromThePast.toSerialized()));

        assertEquals("unexpected!", new String(blastFromThePastPlaintext));
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    private boolean isSessionIdEqual(SignalProtocolStore aliceStore, SignalProtocolStore bobStore) {
        return Arrays.equals(aliceStore.findSessionByAddress(BOB_ADDRESS).orElseThrow().sessionState().baseKey(),
                bobStore.findSessionByAddress(ALICE_ADDRESS).orElseThrow().sessionState().baseKey());
    }

    private SignalPreKeyBundle createAlicePreKeyBundle(SignalProtocolStore aliceStore) {
        var aliceUnsignedPreKey = SignalIdentityKeyPair.random();
        var aliceUnsignedPreKeyId = new Random().nextInt(0xFFFFFF);
        var aliceSignature = Curve25519.sign(aliceStore.identityKeyPair().privateKey().toEncodedPoint(),
                ALICE_SIGNED_PRE_KEY.publicKey().toSerialized());
        var alicePreKeyBundle = new SignalPreKeyBundleBuilder()
                .registrationId(1)
                .deviceId(1)
                .preKeyId(aliceUnsignedPreKeyId)
                .preKeyPublic(aliceUnsignedPreKey.publicKey())
                .signedPreKeyId(ALICE_SIGNED_PRE_KEY_ID)
                .signedPreKeyPublic(ALICE_SIGNED_PRE_KEY.publicKey())
                .signedPreKeySignature(aliceSignature)
                .identityKey(aliceStore.identityKeyPair().publicKey())
                .build();
        var aliceSignedKeyPair = new SignalSignedKeyPairBuilder()
                .id(ALICE_SIGNED_PRE_KEY_ID)
                .keyPair(ALICE_SIGNED_PRE_KEY)
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

    private SignalPreKeyBundle createBobPreKeyBundle(SignalProtocolStore bobStore) {
        var bobUnsignedPreKey = SignalIdentityKeyPair.random();
        var bobUnsignedPreKeyId = new Random().nextInt(0xFFFFFF);
        var bobSignature = Curve25519.sign(bobStore.identityKeyPair().privateKey().toEncodedPoint(),
                BOB_SIGNED_PRE_KEY.publicKey().toSerialized());

        var bobPreKeyBundle = new SignalPreKeyBundleBuilder()
                .registrationId(1)
                .deviceId(1)
                .preKeyId(bobUnsignedPreKeyId)
                .preKeyPublic(bobUnsignedPreKey.publicKey())
                .signedPreKeyId(BOB_SIGNED_PRE_KEY_ID)
                .signedPreKeyPublic(BOB_SIGNED_PRE_KEY.publicKey())
                .signedPreKeySignature(bobSignature)
                .identityKey(bobStore.identityKeyPair().publicKey())
                .build();

        var bobSignedKeyPair = new SignalSignedKeyPairBuilder()
                .id(BOB_SIGNED_PRE_KEY_ID)
                .signature(bobSignature)
                .keyPair(BOB_SIGNED_PRE_KEY)
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