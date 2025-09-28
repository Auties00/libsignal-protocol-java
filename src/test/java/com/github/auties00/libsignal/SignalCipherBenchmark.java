/*
 I've left a lot of comments in the code to help explain the benchmarking process.
 Benchmarking is HARD, so if you have any issues with my implementation, please open an issue, I could very well be doing something wrong.
 Remember to run with --enable-native-access=ALL-UNNAMED
 */

package com.github.auties00.libsignal;

// New Java lib imports
import archived.org.whispersystems.libsignal.IdentityKey;
import archived.org.whispersystems.libsignal.groups.SenderKeyName;
import archived.org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import archived.org.whispersystems.libsignal.groups.state.SenderKeyStore;
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

import java.io.IOException;
import java.util.*;
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
@Fork(3)
public class SignalCipherBenchmark {
    // Test messages of various sizes (static to avoid recreation)
    private static final byte[] SMALL_MESSAGE = "Hello, this is a typical text message".getBytes();
    private static final byte[] MEDIUM_MESSAGE = generateRandomMessage(1024); // 1KB
    private static final byte[] LARGE_MESSAGE = generateRandomMessage(64 * 1024); // 64KB
    private static final byte[] EXTRA_LARGE_MESSAGE = generateRandomMessage(1024 * 1024); // 1MB

    // Recipients for groups
    private static final SignalSenderKeyName newJavaLibRecipient = new SignalSenderKeyName("benchmark_group", new SignalProtocolAddress("+14150001111", 1));
    private static final SenderKeyName oldJavaLibRecipient = new SenderKeyName("benchmark_group", new archived.org.whispersystems.libsignal.SignalProtocolAddress("+14150001111", 1));
    private static final UUID rustBindingsLibRecipient = UUID.randomUUID();

    private static byte[] generateRandomMessage(int size) {
        var message = new byte[size];
        new Random(42).nextBytes(message); // Deterministic for consistent benchmarks
        return message;
    }

    // ================== NEW JAVA LIB SIGNAL SESSION CIPHER BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionEncryptState {
        SignalSessionCipher aliceSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionDecryptSmallState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionDecryptMediumState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionDecryptLargeState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionDecryptExtraLargeState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionCipherState {
        SignalSessionCipher aliceSessionCipher;
        SignalSessionCipher bobSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
            bobSessionCipher = setupResult.bobSessionCipher;
        }
    }

    private static NewJavaLibSessionCipherSetup setupNewJavaLibSessionCiphers() {
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

        return new NewJavaLibSessionCipherSetup(aliceSessionCipher, bobSessionCipher);
    }

    private static class NewJavaLibSessionCipherSetup {
        final SignalSessionCipher aliceSessionCipher;
        final SignalSessionCipher bobSessionCipher;

        NewJavaLibSessionCipherSetup(SignalSessionCipher aliceSessionCipher, SignalSessionCipher bobSessionCipher) {
            this.aliceSessionCipher = aliceSessionCipher;
            this.bobSessionCipher = bobSessionCipher;
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionEncryptSmall(NewJavaLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionEncryptMedium(NewJavaLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionEncryptLarge(NewJavaLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionEncryptExtraLarge(NewJavaLibSessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionDecryptSmall(NewJavaLibSessionDecryptSmallState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionDecryptMedium(NewJavaLibSessionDecryptMediumState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionDecryptLarge(NewJavaLibSessionDecryptLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionDecryptExtraLarge(NewJavaLibSessionDecryptExtraLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptNewJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // Helper method to handle both SignalMessage and SignalPreKeyMessage cases for new java lib
    private byte[] decryptNewJavaLibMessage(SignalSessionCipher cipher, SignalCiphertextMessage message) {
        return switch (message) {
            case SignalPreKeyMessage preKeyMessage -> cipher.decrypt(preKeyMessage);
            case SignalMessage signalMessage -> cipher.decrypt(signalMessage);
            default -> throw new IllegalArgumentException("Unsupported message type: " + message.getClass().getName());
        };
    }

    // ================== RUST BINDINGS LIB SIGNAL SESSION CIPHER BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class RustBindingsLibSessionEncryptState {
        SessionCipher aliceSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupRustBindingsLibSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibSessionDecryptSmallState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupRustBindingsLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibSessionDecryptMediumState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupRustBindingsLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibSessionDecryptLargeState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupRustBindingsLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibSessionDecryptExtraLargeState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupRustBindingsLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE));
            }
        }
    }

    private static RustBindingsLibSessionCipherSetup setupRustBindingsLibSessionCiphers() throws Exception {
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

        return new RustBindingsLibSessionCipherSetup(aliceSessionCipher, bobSessionCipher);
    }

    private static class RustBindingsLibSessionCipherSetup {
        final SessionCipher aliceSessionCipher;
        final SessionCipher bobSessionCipher;

        RustBindingsLibSessionCipherSetup(SessionCipher aliceSessionCipher, SessionCipher bobSessionCipher) {
            this.aliceSessionCipher = aliceSessionCipher;
            this.bobSessionCipher = bobSessionCipher;
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionEncryptSmall(RustBindingsLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionEncryptMedium(RustBindingsLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionEncryptLarge(RustBindingsLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionEncryptExtraLarge(RustBindingsLibSessionEncryptState state, Blackhole   bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionDecryptSmall(RustBindingsLibSessionDecryptSmallState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptRustBindingsLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionDecryptMedium(RustBindingsLibSessionDecryptMediumState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptRustBindingsLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionDecryptLarge(RustBindingsLibSessionDecryptLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptRustBindingsLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionDecryptExtraLarge(RustBindingsLibSessionDecryptExtraLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptRustBindingsLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // Helper method to handle both SignalMessage and PreKeySignalMessage cases for rust bindings lib
    private byte[] decryptRustBindingsLibMessage(SessionCipher cipher, CiphertextMessage message) throws Exception {
        if (message.getType() == CiphertextMessage.PREKEY_TYPE) {
            return cipher.decrypt(new PreKeySignalMessage(message.serialize()));
        } else if (message.getType() == CiphertextMessage.WHISPER_TYPE) {
            return cipher.decrypt(new org.signal.libsignal.protocol.message.SignalMessage(message.serialize()));
        } else {
            throw new IllegalArgumentException("Unsupported message type: " + message.getType());
        }
    }

    // ================== OLD JAVA LIB SIGNAL SESSION CIPHER BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class OldJavaLibSessionEncryptState {
        archived.org.whispersystems.libsignal.SessionCipher aliceSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldJavaLibSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibSessionDecryptSmallState {
        archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher;
        List<archived.org.whispersystems.libsignal.protocol.CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibSessionDecryptMediumState {
        archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher;
        List<archived.org.whispersystems.libsignal.protocol.CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibSessionDecryptLargeState {
        archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher;
        List<archived.org.whispersystems.libsignal.protocol.CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibSessionDecryptExtraLargeState {
        archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher;
        List<archived.org.whispersystems.libsignal.protocol.CiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE));
            }
        }
    }

    private static OldJavaLibSessionCipherSetup setupOldJavaLibSessionCiphers() throws Exception {
        // Initialize stores and addresses
        var aliceSessionStore = new archived.org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore(generateOldIdentityKeyPair(), 5);
        var bobSessionStore = new archived.org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore(generateOldIdentityKeyPair(), 6);
        var aliceAddress = new archived.org.whispersystems.libsignal.SignalProtocolAddress("+14159999999", 1);
        var bobAddress = new archived.org.whispersystems.libsignal.SignalProtocolAddress("+14158888888", 1);

        // Set up session builders
        var aliceSessionBuilder = new archived.org.whispersystems.libsignal.SessionBuilder(aliceSessionStore, bobAddress);
        var bobSessionBuilder = new archived.org.whispersystems.libsignal.SessionBuilder(bobSessionStore, aliceAddress);

        // Create and process pre-key bundle (simulating initial key exchange)
        var bobPreKeyPair = archived.org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
        var bobSignedPreKeyPair = archived.org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
        var bobSignedPreKeySignature = Curve25519.sign(bobSessionStore.getIdentityKeyPair().getPrivateKey().serialize(), bobSignedPreKeyPair.getPublicKey().serialize());

        var bobPreKey = new archived.org.whispersystems.libsignal.state.PreKeyBundle(
                bobSessionStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(),
                bobSignedPreKeySignature,
                bobSessionStore.getIdentityKeyPair().getPublicKey()
        );

        // Add keys to Bob's store
        bobSessionStore.storePreKey(31337, new archived.org.whispersystems.libsignal.state.PreKeyRecord(31337, bobPreKeyPair));
        bobSessionStore.storeSignedPreKey(22, new archived.org.whispersystems.libsignal.state.SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        // Process the bundle to establish session
        aliceSessionBuilder.process(bobPreKey);

        // Create ciphers
        var aliceSessionCipher = new archived.org.whispersystems.libsignal.SessionCipher(aliceSessionStore, bobAddress);
        var bobSessionCipher = new archived.org.whispersystems.libsignal.SessionCipher(bobSessionStore, aliceAddress);

        return new OldJavaLibSessionCipherSetup(aliceSessionCipher, bobSessionCipher);
    }

    private static archived.org.whispersystems.libsignal.IdentityKeyPair generateOldIdentityKeyPair() {
        var keyPair = archived.org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
        var publicKey = new IdentityKey(keyPair.getPublicKey());
        var privateKey = keyPair.getPrivateKey();
        return new archived.org.whispersystems.libsignal.IdentityKeyPair(publicKey, privateKey);
    }

    private static class OldJavaLibSessionCipherSetup {
        final archived.org.whispersystems.libsignal.SessionCipher aliceSessionCipher;
        final archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher;

        OldJavaLibSessionCipherSetup(archived.org.whispersystems.libsignal.SessionCipher aliceSessionCipher, archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher) {
            this.aliceSessionCipher = aliceSessionCipher;
            this.bobSessionCipher = bobSessionCipher;
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionEncryptSmall(OldJavaLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionEncryptMedium(OldJavaLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionEncryptLarge(OldJavaLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionEncryptExtraLarge(OldJavaLibSessionEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionDecryptSmall(OldJavaLibSessionDecryptSmallState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionDecryptMedium(OldJavaLibSessionDecryptMediumState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionDecryptLarge(OldJavaLibSessionDecryptLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionDecryptExtraLarge(OldJavaLibSessionDecryptExtraLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptOldJavaLibMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // Helper method to handle both SignalMessage and PreKeySignalMessage cases for old java lib
    private byte[] decryptOldJavaLibMessage(archived.org.whispersystems.libsignal.SessionCipher cipher, archived.org.whispersystems.libsignal.protocol.CiphertextMessage message) throws Exception {
        if (message.getType() == archived.org.whispersystems.libsignal.protocol.CiphertextMessage.PREKEY_TYPE) {
            return cipher.decrypt(new archived.org.whispersystems.libsignal.protocol.PreKeySignalMessage(message.serialize()));
        } else if (message.getType() == archived.org.whispersystems.libsignal.protocol.CiphertextMessage.WHISPER_TYPE) {
            return cipher.decrypt(new archived.org.whispersystems.libsignal.protocol.SignalMessage(message.serialize()));
        } else {
            throw new IllegalArgumentException("Unsupported message type: " + message.getType());
        }
    }

    // ================== NEW JAVA LIB SIGNAL GROUP CIPHER BENCHMARKS - 2 PARTICIPANTS, ALICE and BOB ==================

    @State(Scope.Benchmark)
    public static class NewJavaLibGroupEncryptState {
        SignalGroupCipher aliceGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibGroupDecryptSmallState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newJavaLibRecipient, SMALL_MESSAGE).toSerialized());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibGroupDecryptMediumState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newJavaLibRecipient, MEDIUM_MESSAGE).toSerialized());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibGroupDecryptLargeState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newJavaLibRecipient, LARGE_MESSAGE).toSerialized());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibGroupDecryptExtraLargeState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(newJavaLibRecipient, EXTRA_LARGE_MESSAGE).toSerialized());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibGroupCipherState {
        SignalGroupCipher aliceGroupCipher;
        SignalGroupCipher bobGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
            bobGroupCipher = setupResult.bobGroupCipher;
        }
    }

    private static NewJavaLibGroupCipherSetup setupNewJavaLibGroupCiphers() {
        // Initialize stores
        var aliceGroupStore = new InMemorySignalProtocolStore();
        var bobGroupStore = new InMemorySignalProtocolStore();

        // Create group session builders
        var aliceGroupSessionBuilder = new SignalGroupSessionBuilder(aliceGroupStore);
        var bobGroupSessionBuilder = new SignalGroupSessionBuilder(bobGroupStore);

        // Set up group session
        var aliceDistributionMessage = aliceGroupSessionBuilder.create(newJavaLibRecipient);
        bobGroupSessionBuilder.process(newJavaLibRecipient, aliceDistributionMessage);

        // Create group ciphers
        var aliceGroupCipher = new SignalGroupCipher(aliceGroupStore);
        var bobGroupCipher = new SignalGroupCipher(bobGroupStore);

        return new NewJavaLibGroupCipherSetup(aliceGroupCipher, bobGroupCipher);
    }

    private static class NewJavaLibGroupCipherSetup {
        final SignalGroupCipher aliceGroupCipher;
        final SignalGroupCipher bobGroupCipher;

        NewJavaLibGroupCipherSetup(SignalGroupCipher aliceGroupCipher, SignalGroupCipher bobGroupCipher) {
            this.aliceGroupCipher = aliceGroupCipher;
            this.bobGroupCipher = bobGroupCipher;
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupEncryptSmall(NewJavaLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newJavaLibRecipient, SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupEncryptMedium(NewJavaLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newJavaLibRecipient, MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupEncryptLarge(NewJavaLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newJavaLibRecipient, LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupEncryptExtraLarge(NewJavaLibGroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(newJavaLibRecipient, EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupDecryptSmall(NewJavaLibGroupDecryptSmallState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newJavaLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupDecryptMedium(NewJavaLibGroupDecryptMediumState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newJavaLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupDecryptLarge(NewJavaLibGroupDecryptLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newJavaLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupDecryptExtraLarge(NewJavaLibGroupDecryptExtraLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(newJavaLibRecipient, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // ================== RUST BINDINGS LIB SIGNAL GROUP CIPHER BENCHMARKS - 2 PARTICIPANTS, ALICE and BOB ==================

    @State(Scope.Benchmark)
    public static class RustBindingsLibGroupEncryptState {
        GroupCipher aliceGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupRustBindingsLibGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibGroupDecryptSmallState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupRustBindingsLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(rustBindingsLibRecipient, SMALL_MESSAGE).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibGroupDecryptMediumState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupRustBindingsLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(rustBindingsLibRecipient, MEDIUM_MESSAGE).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibGroupDecryptLargeState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupRustBindingsLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(rustBindingsLibRecipient, LARGE_MESSAGE).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibGroupDecryptExtraLargeState {
        GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupRustBindingsLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(rustBindingsLibRecipient, EXTRA_LARGE_MESSAGE).serialize());
            }
        }
    }

    private static RustBindingsLibGroupCipherSetup setupRustBindingsLibGroupCiphers() {
        // Initialize stores
        var aliceGroupStore = new org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore(IdentityKeyPair.generate(), 5);
        var bobGroupStore = new org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore(IdentityKeyPair.generate(), 6);

        // Create group session builders
        var aliceGroupSessionBuilder = new GroupSessionBuilder(aliceGroupStore);
        var bobGroupSessionBuilder = new GroupSessionBuilder(bobGroupStore);

        // Create sender key name
        var senderAddress = new org.signal.libsignal.protocol.SignalProtocolAddress("+14150001111", 1);

        // Set up group session
        var aliceDistributionMessage = aliceGroupSessionBuilder.create(senderAddress, rustBindingsLibRecipient);
        bobGroupSessionBuilder.process(senderAddress, aliceDistributionMessage);

        // Create group ciphers
        var aliceGroupCipher = new GroupCipher(aliceGroupStore, senderAddress);
        var bobGroupCipher = new GroupCipher(bobGroupStore, senderAddress);

        return new RustBindingsLibGroupCipherSetup(aliceGroupCipher, bobGroupCipher);
    }

    private static class RustBindingsLibGroupCipherSetup {
        final GroupCipher aliceGroupCipher;
        final GroupCipher bobGroupCipher;

        RustBindingsLibGroupCipherSetup(GroupCipher aliceGroupCipher, GroupCipher bobGroupCipher) {
            this.aliceGroupCipher = aliceGroupCipher;
            this.bobGroupCipher = bobGroupCipher;
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupEncryptSmall(RustBindingsLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(rustBindingsLibRecipient, SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupEncryptMedium(RustBindingsLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(rustBindingsLibRecipient, MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupEncryptLarge(RustBindingsLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(rustBindingsLibRecipient, LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupEncryptExtraLarge(RustBindingsLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(rustBindingsLibRecipient, EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupDecryptSmall(RustBindingsLibGroupDecryptSmallState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupDecryptMedium(RustBindingsLibGroupDecryptMediumState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupDecryptLarge(RustBindingsLibGroupDecryptLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupDecryptExtraLarge(RustBindingsLibGroupDecryptExtraLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // ================== OLD JAVA LIB SIGNAL GROUP CIPHER BENCHMARKS - 2 PARTICIPANTS, ALICE and BOB ==================

    @State(Scope.Benchmark)
    public static class OldJavaLibGroupEncryptState {
        archived.org.whispersystems.libsignal.groups.GroupCipher aliceGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldJavaLibGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibGroupDecryptSmallState {
        archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibGroupDecryptMediumState {
        archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibGroupDecryptLargeState {
        archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibGroupDecryptExtraLargeState {
        archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(EXTRA_LARGE_MESSAGE));
            }
        }
    }

    private static OldJavaLibGroupCipherSetup setupOldJavaLibGroupCiphers() {
        // Initialize stores
        var aliceGroupStore = new ArchivedInMemorySenderKeyStore();
        var bobGroupStore = new ArchivedInMemorySenderKeyStore();

        // Create group session builders
        var aliceGroupSessionBuilder = new archived.org.whispersystems.libsignal.groups.GroupSessionBuilder(aliceGroupStore);
        var bobGroupSessionBuilder = new archived.org.whispersystems.libsignal.groups.GroupSessionBuilder(bobGroupStore);

        // Set up group session
        var aliceDistributionMessage = aliceGroupSessionBuilder.create(oldJavaLibRecipient);
        bobGroupSessionBuilder.process(oldJavaLibRecipient, aliceDistributionMessage);

        // Create group ciphers
        var aliceGroupCipher = new archived.org.whispersystems.libsignal.groups.GroupCipher(aliceGroupStore, oldJavaLibRecipient);
        var bobGroupCipher = new archived.org.whispersystems.libsignal.groups.GroupCipher(bobGroupStore, oldJavaLibRecipient);

        return new OldJavaLibGroupCipherSetup(aliceGroupCipher, bobGroupCipher);
    }

    // In the old library, an implementation for SenderKeyStore is missing
    // They added it with the rust bindings, but for the old one we have to implement it
    private static final class ArchivedInMemorySenderKeyStore implements SenderKeyStore {
        private final Map<SenderKeyName, archived.org.whispersystems.libsignal.groups.state.SenderKeyRecord> store = new HashMap<>();

        @Override
        public void storeSenderKey(SenderKeyName senderKeyName, archived.org.whispersystems.libsignal.groups.state.SenderKeyRecord senderKeyRecord) {
            this.store.put(senderKeyName, senderKeyRecord);
        }

        @Override
        public archived.org.whispersystems.libsignal.groups.state.SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName) {
            try {
                var record = this.store.get(senderKeyName);
                return record == null ? new SenderKeyRecord() : new archived.org.whispersystems.libsignal.groups.state.SenderKeyRecord(record.serialize());
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }
    }

    private static class OldJavaLibGroupCipherSetup {
        final archived.org.whispersystems.libsignal.groups.GroupCipher aliceGroupCipher;
        final archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher;

        OldJavaLibGroupCipherSetup(archived.org.whispersystems.libsignal.groups.GroupCipher aliceGroupCipher, archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher) {
            this.aliceGroupCipher = aliceGroupCipher;
            this.bobGroupCipher = bobGroupCipher;
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupEncryptSmall(OldJavaLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupEncryptMedium(OldJavaLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupEncryptLarge(OldJavaLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupEncryptExtraLarge(OldJavaLibGroupEncryptState state, Blackhole bh) throws Exception {
        // Encrypt 100 messages
        for (var i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(EXTRA_LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupDecryptSmall(OldJavaLibGroupDecryptSmallState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupDecryptMedium(OldJavaLibGroupDecryptMediumState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupDecryptLarge(OldJavaLibGroupDecryptLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupDecryptExtraLarge(OldJavaLibGroupDecryptExtraLargeState state, Blackhole bh) throws Exception {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // ================== NEW JAVA LIB SIGNAL EDGE CASE BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionOutOfOrderState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
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
    public static class NewJavaLibGroupOutOfOrderState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(newJavaLibRecipient, ("Out of order message " + i).getBytes()).toSerialized());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibSessionMessageKeyLimitStressState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupNewJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            for (var i = 0; i < 2000; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("stress test " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class NewJavaLibGroupMessageKeyLimitStressState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupNewJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Create many messages to test message key limits
            for (var i = 0; i < 2000; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(newJavaLibRecipient, ("stress test " + i).getBytes()).toSerialized());
            }
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionOutOfOrderDecrypt(NewJavaLibSessionOutOfOrderState state, Blackhole bh) {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = decryptNewJavaLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupOutOfOrderDecrypt(NewJavaLibGroupOutOfOrderState state, Blackhole bh) {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = state.bobGroupCipher.decrypt(newJavaLibRecipient, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalSessionMessageKeyLimitStress(NewJavaLibSessionMessageKeyLimitStressState state, Blackhole bh) {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = decryptNewJavaLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void newJavaLibSignalGroupMessageKeyLimitStress(NewJavaLibGroupMessageKeyLimitStressState state, Blackhole bh) {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = state.bobGroupCipher.decrypt(newJavaLibRecipient, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    // ================== RUST BINDINGS LIB SIGNAL EDGE CASE BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class RustBindingsLibSessionOutOfOrderState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupRustBindingsLibSessionCiphers();
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
    public static class RustBindingsLibGroupOutOfOrderState {
        GroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupRustBindingsLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(rustBindingsLibRecipient, ("Out of order message " + i).getBytes()).serialize());
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibSessionMessageKeyLimitStressState {
        SessionCipher bobSessionCipher;
        List<CiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupRustBindingsLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            for (var i = 0; i < 2000; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("stress test " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class RustBindingsLibGroupMessageKeyLimitStressState {
        GroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupRustBindingsLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Create many messages to test message key limits
            for (var i = 0; i < 2000; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(rustBindingsLibRecipient, ("stress test " + i).getBytes()).serialize());
            }
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionOutOfOrderDecrypt(RustBindingsLibSessionOutOfOrderState state, Blackhole bh) throws Exception {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = decryptRustBindingsLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupOutOfOrderDecrypt(RustBindingsLibGroupOutOfOrderState state, Blackhole bh) throws Exception {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalSessionMessageKeyLimitStress(RustBindingsLibSessionMessageKeyLimitStressState state, Blackhole bh) throws Exception {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = decryptRustBindingsLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void rustBindingsLibSignalGroupMessageKeyLimitStress(RustBindingsLibGroupMessageKeyLimitStressState state, Blackhole bh) throws Exception {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    // ================== OLD JAVA LIB SIGNAL EDGE CASE BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class OldJavaLibSessionOutOfOrderState {
        archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher;
        List<archived.org.whispersystems.libsignal.protocol.CiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldJavaLibSessionCiphers();
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
    public static class OldJavaLibGroupOutOfOrderState {
        archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (var i = 0; i < 100; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(("Out of order message " + i).getBytes()));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibSessionMessageKeyLimitStressState {
        archived.org.whispersystems.libsignal.SessionCipher bobSessionCipher;
        List<archived.org.whispersystems.libsignal.protocol.CiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() throws Exception {
            var setupResult = setupOldJavaLibSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            for (var i = 0; i < 2000; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("stress test " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class OldJavaLibGroupMessageKeyLimitStressState {
        archived.org.whispersystems.libsignal.groups.GroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() throws Exception {
            var setupResult = setupOldJavaLibGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Create many messages to test message key limits
            for (var i = 0; i < 2000; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(("stress test " + i).getBytes()));
            }
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionOutOfOrderDecrypt(OldJavaLibSessionOutOfOrderState state, Blackhole bh) throws Exception {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = decryptOldJavaLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupOutOfOrderDecrypt(OldJavaLibGroupOutOfOrderState state, Blackhole bh) throws Exception {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (var i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalSessionMessageKeyLimitStress(OldJavaLibSessionMessageKeyLimitStressState state, Blackhole bh) throws Exception {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = decryptOldJavaLibMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void oldJavaLibSignalGroupMessageKeyLimitStress(OldJavaLibGroupMessageKeyLimitStressState state, Blackhole bh) throws Exception {
        // Decrypt every 10th message to create gaps
        for (var i = 0; i < state.messages.size(); i += 10) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }
}