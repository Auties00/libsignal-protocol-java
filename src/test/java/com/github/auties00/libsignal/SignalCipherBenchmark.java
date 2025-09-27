/*
 I've left a lot of comments in the code to help explain the benchmarking process.
 Benchmarking is HARD.
 Remember to run with --enable-native-access=ALL-UNNAMED
 */

package com.github.auties00.libsignal;

// My Java lib imports
import com.github.auties00.curve25519.Curve25519;
import com.github.auties00.libsignal.groups.SignalGroupCipher;
import com.github.auties00.libsignal.groups.SignalGroupSessionBuilder;
import com.github.auties00.libsignal.groups.SignalSenderKeyName;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalPreKeyPairBuilder;
import com.github.auties00.libsignal.key.SignalSignedKeyPairBuilder;
import com.github.auties00.libsignal.protocol.SignalCiphertextMessage;
import com.github.auties00.libsignal.protocol.SignalMessage;
import com.github.auties00.libsignal.protocol.SignalPreKeyMessage;
import com.github.auties00.libsignal.state.SignalPreKeyBundle;

// Rust bindings lib imports
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.SessionBuilder;
import org.signal.libsignal.protocol.SessionCipher;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.groups.GroupCipher;
import org.signal.libsignal.protocol.groups.GroupSessionBuilder;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.PreKeySignalMessage;
import org.signal.libsignal.protocol.state.PreKeyBundle;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
// All benchmarks should take at least 1 ms to be considered valid
// This is because we are using @Setup(Level.Invocation).
// For the technical explanation on why, check the Javadoc for Setup,
// but TLDR if the method takes a very short amount of time to execute,
// we saturate the benchmark system with timestamp requests,
// which introduce artificial latency, throughput, and scalability bottlenecks.
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class SignalCipherBenchmark {
    // Test messages of various sizes (static to avoid recreation)
    private static final byte[] SMALL_MESSAGE = "Hello, this is a typical text message".getBytes();
    private static final byte[] MEDIUM_MESSAGE = generateRandomMessage(1024); // 1KB
    private static final byte[] LARGE_MESSAGE = generateRandomMessage(64 * 1024); // 64KB
    private static final byte[] EXTRA_LARGE_MESSAGE = generateRandomMessage(1024 * 1024); // 1MB

    // Recipients for groups
    private static final SignalSenderKeyName newLibRecipient = new SignalSenderKeyName("benchmark_group", new SignalProtocolAddress("+14150001111", 1));
    private static final UUID oldLibRecipient = UUID.randomUUID();

    private static byte[] generateRandomMessage(int size) {
        var message = new byte[size];
        new Random(42).nextBytes(message); // Deterministic for consistent benchmarks
        return message;
    }

    // ================== NEW LIB SIGNAL SESSION CIPHER BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class NewLibSessionEncryptState {
        SignalSessionCipher aliceSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibSessionDecryptSmallState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibSessionDecryptMediumState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibSessionDecryptLargeState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibSessionDecryptExtraLargeState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibSessionCipherState {
        SignalSessionCipher aliceSessionCipher;
        SignalSessionCipher bobSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
            bobSessionCipher = setupResult.bobSessionCipher;
        }
    }

    private static NewLibSessionCipherSetup setupNewLibSessionCiphers() {
        // Initialize stores and addresses
        var aliceSessionStore = new InMemorySignalProtocolStore();
        var bobSessionStore = new InMemorySignalProtocolStore();
        var aliceAddress = new SignalProtocolAddress("+14159999999", 1);
        var bobAddress = new SignalProtocolAddress("+14158888888", 1);

        // Set up session builders
        var aliceSessionBuilder = new SignalSessionBuilder(aliceSessionStore, bobAddress);
        var bobSessionBuilder = new SignalSessionBuilder(bobSessionStore, aliceAddress);

        // Create and process pre-key bundle (simulating initial key exchange)
        var bobPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeyPair = SignalIdentityKeyPair.random();
        var bobSignedPreKeySignature = Curve25519.sign(
                bobSessionStore.identityKeyPair().privateKey().toEncodedPoint(),
                bobSignedPreKeyPair.publicKey().toSerialized()
        );

        var bobPreKey = new SignalPreKeyBundle(
                bobSessionStore.registrationId(), 1,
                31337, bobPreKeyPair.publicKey(),
                22, bobSignedPreKeyPair.publicKey(),
                bobSignedPreKeySignature,
                bobSessionStore.identityKeyPair().publicKey()
        );

        // Add keys to Bob's store
        var preKey = new SignalPreKeyPairBuilder()
                .id(bobPreKey.preKeyId())
                .keyPair(bobPreKeyPair)
                .build();
        bobSessionStore.addPreKey(preKey);

        var signedPreKey = new SignalSignedKeyPairBuilder()
                .id(22)
                .keyPair(bobSignedPreKeyPair)
                .signature(bobSignedPreKeySignature)
                .build();
        bobSessionStore.addSignedPreKey(signedPreKey);

        // Process the bundle to establish session
        aliceSessionBuilder.process(bobPreKey);

        // Create ciphers
        var aliceSessionCipher = new SignalSessionCipher(aliceSessionStore, aliceSessionBuilder, bobAddress);
        var bobSessionCipher = new SignalSessionCipher(bobSessionStore, bobSessionBuilder, aliceAddress);

        return new NewLibSessionCipherSetup(aliceSessionCipher, bobSessionCipher);
    }

    private static class NewLibSessionCipherSetup {
        final SignalSessionCipher aliceSessionCipher;
        final SignalSessionCipher bobSessionCipher;

        NewLibSessionCipherSetup(SignalSessionCipher aliceSessionCipher, SignalSessionCipher bobSessionCipher) {
            this.aliceSessionCipher = aliceSessionCipher;
            this.bobSessionCipher = bobSessionCipher;
        }
    }

    @Benchmark
    public void newLibSignalSessionEncryptSmall(NewLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionEncryptMedium(NewLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionEncryptLarge(NewLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionEncryptExtraLarge(NewLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionDecryptSmall(NewLibSessionDecryptSmallState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionDecryptMedium(NewLibSessionDecryptMediumState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionDecryptLarge(NewLibSessionDecryptLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionDecryptExtraLarge(NewLibSessionDecryptExtraLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // Helper method to handle both SignalMessage and SignalPreKeyMessage cases for new lib
    private byte[] decryptNewLibMessage(SignalSessionCipher cipher, SignalCiphertextMessage message) {
        return switch (message) {
            case SignalPreKeyMessage preKeyMessage -> cipher.decrypt(preKeyMessage);
            case SignalMessage signalMessage -> cipher.decrypt(signalMessage);
            default -> throw new IllegalArgumentException("Unsupported message type: " + message.getClass().getName());
        };
    }

    // ================== OLD LIB SIGNAL SESSION CIPHER BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class OldLibSessionEncryptState {
        SessionCipher aliceSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldLibSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibSessionDecryptSmallState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibSessionDecryptMediumState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibSessionDecryptLargeState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibSessionDecryptExtraLargeState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE));
            }
        }
    }

    private static OldLibSessionCipherSetup setupOldLibSessionCiphers() throws Exception {
        // Initialize stores and addresses
        var aliceSessionStore = new org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore(IdentityKeyPair.generate(), 5);
        var bobSessionStore = new org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore(IdentityKeyPair.generate(), 6);
        var aliceAddress = new org.signal.libsignal.protocol.SignalProtocolAddress("+14159999999", 1);
        var bobAddress = new org.signal.libsignal.protocol.SignalProtocolAddress("+14158888888", 1);

        // Set up session builders
        var aliceSessionBuilder = new SessionBuilder(aliceSessionStore, bobAddress);
        var bobSessionBuilder = new SessionBuilder(bobSessionStore, aliceAddress);

        // Create and process pre-key bundle (simulating initial key exchange)
        var bobPreKeyPair = Curve.generateKeyPair();
        var bobSignedPreKeyPair =  Curve.generateKeyPair();
        var bobSignedPreKeySignature = bobSessionStore.getIdentityKeyPair().getPrivateKey()
                .calculateSignature(bobSignedPreKeyPair.getPublicKey().serialize());

        var bobPreKey = new PreKeyBundle(
                bobSessionStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(),
                bobSignedPreKeySignature,
                bobSessionStore.getIdentityKeyPair().getPublicKey()
        );

        // Add keys to Bob's store
        bobSessionStore.storePreKey(31337, new org.signal.libsignal.protocol.state.PreKeyRecord(31337, bobPreKeyPair));
        bobSessionStore.storeSignedPreKey(22, new org.signal.libsignal.protocol.state.SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        // Process the bundle to establish session
        aliceSessionBuilder.process(bobPreKey);

        // Create ciphers
        var aliceSessionCipher = new SessionCipher(aliceSessionStore, bobAddress);
        var bobSessionCipher = new SessionCipher(bobSessionStore, aliceAddress);

        return new OldLibSessionCipherSetup(aliceSessionCipher, bobSessionCipher);
    }

    private static class OldLibSessionCipherSetup {
        final SessionCipher aliceSessionCipher;
        final SessionCipher bobSessionCipher;

        OldLibSessionCipherSetup(SessionCipher aliceSessionCipher, SessionCipher bobSessionCipher) {
            this.aliceSessionCipher = aliceSessionCipher;
            this.bobSessionCipher = bobSessionCipher;
        }
    }

    @Benchmark
    public void oldLibSignalSessionEncryptSmall(OldLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionEncryptMedium(OldLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionEncryptLarge(OldLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionEncryptExtraLarge(OldLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionDecryptSmall(OldLibSessionDecryptSmallState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionDecryptMedium(OldLibSessionDecryptMediumState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionDecryptLarge(OldLibSessionDecryptLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionDecryptExtraLarge(OldLibSessionDecryptExtraLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // Helper method to handle both OldSignalMessage and PreKeySignalMessage cases for old lib
    private byte[] decryptOldLibMessage(SessionCipher cipher, CiphertextMessage message) throws Exception {
        if (message.getType() == CiphertextMessage.PREKEY_TYPE) {
            return cipher.decrypt(new PreKeySignalMessage(message.serialize()));
        } else if (message.getType() == CiphertextMessage.WHISPER_TYPE) {
            return cipher.decrypt(new org.signal.libsignal.protocol.message.SignalMessage(message.serialize()));
        } else {
            throw new IllegalArgumentException("Unsupported message type: " + message.getType());
        }
    }

    // ================== NEW LIB SIGNAL GROUP CIPHER BENCHMARKS - 2 PARTICIPANTS, ALICE and BOB ==================

    @State(Scope.Benchmark)
    public static class NewLibGroupEncryptState {
        SignalGroupCipher aliceGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibGroupDecryptSmallState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newLibRecipient, SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibGroupDecryptMediumState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newLibRecipient, MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibGroupDecryptLargeState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newLibRecipient, LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibGroupDecryptExtraLargeState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newLibRecipient, EXTRA_LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibGroupCipherState {
        SignalGroupCipher aliceGroupCipher;
        SignalGroupCipher bobGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
            bobGroupCipher = setupResult.bobGroupCipher;
        }
    }

    private static NewLibGroupCipherSetup setupNewLibGroupCiphers() {
        // Initialize stores
        var aliceGroupStore = new InMemorySignalProtocolStore();
        var bobGroupStore = new InMemorySignalProtocolStore();

        // Create group session builders
        var aliceGroupSessionBuilder = new SignalGroupSessionBuilder(aliceGroupStore);
        var bobGroupSessionBuilder = new SignalGroupSessionBuilder(bobGroupStore);

        // Set up group session
        var aliceDistributionMessage = aliceGroupSessionBuilder.create(newLibRecipient);
        bobGroupSessionBuilder.process(newLibRecipient, aliceDistributionMessage);

        // Create group ciphers
        var aliceGroupCipher = new SignalGroupCipher(aliceGroupStore);
        var bobGroupCipher = new SignalGroupCipher(bobGroupStore);

        return new NewLibGroupCipherSetup(aliceGroupCipher, bobGroupCipher);
    }

    private static class NewLibGroupCipherSetup {
        final SignalGroupCipher aliceGroupCipher;
        final SignalGroupCipher bobGroupCipher;

        NewLibGroupCipherSetup(SignalGroupCipher aliceGroupCipher, SignalGroupCipher bobGroupCipher) {
            this.aliceGroupCipher = aliceGroupCipher;
            this.bobGroupCipher = bobGroupCipher;
        }
    }

    @Benchmark
    public void newLibSignalGroupEncryptSmall(NewLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newLibRecipient, SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupEncryptMedium(NewLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newLibRecipient, MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupEncryptLarge(NewLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newLibRecipient, LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupEncryptExtraLarge(NewLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newLibRecipient, EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupDecryptSmall(NewLibGroupDecryptSmallState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupDecryptMedium(NewLibGroupDecryptMediumState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupDecryptLarge(NewLibGroupDecryptLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupDecryptExtraLarge(NewLibGroupDecryptExtraLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // ================== OLD LIB SIGNAL GROUP CIPHER BENCHMARKS - 2 PARTICIPANTS, ALICE and BOB ==================

    @State(Scope.Benchmark)
    public static class OldLibGroupEncryptState {
        GroupCipher aliceGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldLibGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibGroupDecryptSmallState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(oldLibRecipient, SMALL_MESSAGE).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibGroupDecryptMediumState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(oldLibRecipient, MEDIUM_MESSAGE).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibGroupDecryptLargeState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(oldLibRecipient, LARGE_MESSAGE).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibGroupDecryptExtraLargeState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(oldLibRecipient, EXTRA_LARGE_MESSAGE).serialize());
            }
        }
    }

    private static OldLibGroupCipherSetup setupOldLibGroupCiphers() {
        // Initialize stores
        var aliceGroupStore = new org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore(IdentityKeyPair.generate(), 5);
        var bobGroupStore = new org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore(IdentityKeyPair.generate(), 6);

        // Create group session builders
        var aliceGroupSessionBuilder = new GroupSessionBuilder(aliceGroupStore);
        var bobGroupSessionBuilder = new GroupSessionBuilder(bobGroupStore);

        // Create sender key name
        var senderAddress = new org.signal.libsignal.protocol.SignalProtocolAddress("+14150001111", 1);

        // Set up group session
        var aliceDistributionMessage = aliceGroupSessionBuilder.create(senderAddress, oldLibRecipient);
        bobGroupSessionBuilder.process(senderAddress, aliceDistributionMessage);

        // Create group ciphers
        var aliceGroupCipher = new GroupCipher(aliceGroupStore, senderAddress);
        var bobGroupCipher = new GroupCipher(bobGroupStore, senderAddress);

        return new OldLibGroupCipherSetup(aliceGroupCipher, bobGroupCipher);
    }

    private static class OldLibGroupCipherSetup {
        final GroupCipher aliceGroupCipher;
        final GroupCipher bobGroupCipher;

        OldLibGroupCipherSetup(GroupCipher aliceGroupCipher, GroupCipher bobGroupCipher) {
            this.aliceGroupCipher = aliceGroupCipher;
            this.bobGroupCipher = bobGroupCipher;
        }
    }

    @Benchmark
    public void oldLibSignalGroupEncryptSmall(OldLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(oldLibRecipient, SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupEncryptMedium(OldLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(oldLibRecipient, MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupEncryptLarge(OldLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(oldLibRecipient, LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupEncryptExtraLarge(OldLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(oldLibRecipient, EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupDecryptSmall(OldLibGroupDecryptSmallState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupDecryptMedium(OldLibGroupDecryptMediumState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupDecryptLarge(OldLibGroupDecryptLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupDecryptExtraLarge(OldLibGroupDecryptExtraLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // ================== NEW LIB SIGNAL EDGE CASE BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class NewLibSessionOutOfOrderState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("Out of order message " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibGroupOutOfOrderState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(newLibRecipient, ("Out of order message " + i).getBytes()));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibSessionMessageKeyLimitStressState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            for (var i = 0; i < 2000; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("stress test " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewLibGroupMessageKeyLimitStressState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Create many messages to test message key limits
            for (var i = 0; i < 2000; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(newLibRecipient, ("stress test " + i).getBytes()));
            }
        }
    }

    @Benchmark
    public void newLibSignalSessionOutOfOrderDecrypt(NewLibSessionOutOfOrderState state, Blackhole bh) {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = decryptNewLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupOutOfOrderDecrypt(NewLibGroupOutOfOrderState state, Blackhole bh) {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = state.bobGroupCipher.decrypt(newLibRecipient, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalSessionMessageKeyLimitStress(NewLibSessionMessageKeyLimitStressState state, Blackhole bh) {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = decryptNewLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newLibSignalGroupMessageKeyLimitStress(NewLibGroupMessageKeyLimitStressState state, Blackhole bh) {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = state.bobGroupCipher.decrypt(newLibRecipient, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    // ================== OLD LIB SIGNAL EDGE CASE BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class OldLibSessionOutOfOrderState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("Out of order message " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibGroupOutOfOrderState {
        GroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(oldLibRecipient, ("Out of order message " + i).getBytes()).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibSessionMessageKeyLimitStressState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            for (var i = 0; i < 2000; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("stress test " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldLibGroupMessageKeyLimitStressState {
        GroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Create many messages to test message key limits
            for (var i = 0; i < 2000; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(oldLibRecipient, ("stress test " + i).getBytes()).serialize());
            }
        }
    }

    @Benchmark
    public void oldLibSignalSessionOutOfOrderDecrypt(OldLibSessionOutOfOrderState state, Blackhole bh) throws Exception {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = decryptOldLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupOutOfOrderDecrypt(OldLibGroupOutOfOrderState state, Blackhole bh) throws Exception {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalSessionMessageKeyLimitStress(OldLibSessionMessageKeyLimitStressState state, Blackhole bh) throws Exception {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = decryptOldLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldLibSignalGroupMessageKeyLimitStress(OldLibGroupMessageKeyLimitStressState state, Blackhole bh) throws Exception {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }
}