/*
 I've left a lot of comments in the code to help explain the benchmarking process.
 Benchmarking is HARD.
 */

package com.github.auties00.libsignal;

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
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
// All benchmarks should take at least 1 ms to be considered valid
// This is because we are using @Setup(Level.Invocation) which requires all benchmarks to take at least 1 ms.
// For the technical explanation on why, check it's Javadoc,
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
    private static final byte[] MEGABYTE_MESSAGE = generateRandomMessage(1024 * 1024); // 1MB

    private static byte[] generateRandomMessage(int size) {
        byte[] message = new byte[size];
        new Random(42).nextBytes(message); // Deterministic for consistent benchmarks
        return message;
    }

    // ================== SESSION CIPHER BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class SessionEncryptState {
        SignalSessionCipher aliceSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class SessionDecryptSmallState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class SessionDecryptMediumState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class SessionDecryptLargeState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class SessionDecryptMegabyteState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceSessionCipher.encrypt(MEGABYTE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class SessionCipherState {
        SignalSessionCipher aliceSessionCipher;
        SignalSessionCipher bobSessionCipher;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            aliceSessionCipher = setupResult.aliceSessionCipher;
            bobSessionCipher = setupResult.bobSessionCipher;
        }
    }

    private static SessionCipherSetup setupSessionCiphers() {
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

        return new SessionCipherSetup(aliceSessionCipher, bobSessionCipher);
    }

    private static class SessionCipherSetup {
        final SignalSessionCipher aliceSessionCipher;
        final SignalSessionCipher bobSessionCipher;

        SessionCipherSetup(SignalSessionCipher aliceSessionCipher, SignalSessionCipher bobSessionCipher) {
            this.aliceSessionCipher = aliceSessionCipher;
            this.bobSessionCipher = bobSessionCipher;
        }
    }

    @Benchmark
    public void sessionEncryptSmall(SessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void sessionEncryptMedium(SessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void sessionEncryptLarge(SessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void sessionEncryptMegabyte(SessionEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceSessionCipher.encrypt(MEGABYTE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void sessionDecryptSmall(SessionDecryptSmallState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void sessionDecryptMedium(SessionDecryptMediumState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void sessionDecryptLarge(SessionDecryptLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void sessionDecryptMegabyte(SessionDecryptMegabyteState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = decryptMessage(state.bobSessionCipher, encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // Helper method to handle both SignalMessage and SignalPreKeyMessage cases
    private byte[] decryptMessage(SignalSessionCipher cipher, SignalCiphertextMessage message) {
        return switch (message) {
            case SignalPreKeyMessage preKeyMessage -> cipher.decrypt(preKeyMessage);
            case SignalMessage signalMessage -> cipher.decrypt(signalMessage);
            default -> throw new IllegalArgumentException("Unsupported message type: " + message.getClass().getName());
        };
    }

    // ================== GROUP CIPHER BENCHMARKS - 2 PARTICIPANTS, ALICE and BOB ==================

    @State(Scope.Benchmark)
    public static class GroupEncryptState {
        SignalGroupCipher aliceGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
        }
    }

    @State(Scope.Benchmark)
    public static class GroupDecryptSmallState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(SMALL_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class GroupDecryptMediumState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(MEDIUM_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class GroupDecryptLargeState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(LARGE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class GroupDecryptMegabyteState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> encryptedMessages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            encryptedMessages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                encryptedMessages.add(setupResult.aliceGroupCipher.encrypt(MEGABYTE_MESSAGE));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class GroupCipherState {
        SignalGroupCipher aliceGroupCipher;
        SignalGroupCipher bobGroupCipher;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
            bobGroupCipher = setupResult.bobGroupCipher;
        }
    }

    private static GroupCipherSetup setupGroupCiphers() {
        // Initialize stores
        var aliceGroupStore = new InMemorySignalProtocolStore();
        var bobGroupStore = new InMemorySignalProtocolStore();

        // Create group session builders
        var aliceGroupSessionBuilder = new SignalGroupSessionBuilder(aliceGroupStore);
        var bobGroupSessionBuilder = new SignalGroupSessionBuilder(bobGroupStore);

        // Create sender key name
        var senderAddress = new SignalProtocolAddress("+14150001111", 1);
        var groupSender = new SignalSenderKeyName("benchmark_group", senderAddress);

        // Set up group session
        var aliceDistributionMessage = aliceGroupSessionBuilder.create(groupSender);
        bobGroupSessionBuilder.process(groupSender, aliceDistributionMessage);

        // Create group ciphers
        var aliceGroupCipher = new SignalGroupCipher(aliceGroupStore, groupSender);
        var bobGroupCipher = new SignalGroupCipher(bobGroupStore, groupSender);

        return new GroupCipherSetup(aliceGroupCipher, bobGroupCipher);
    }

    private static class GroupCipherSetup {
        final SignalGroupCipher aliceGroupCipher;
        final SignalGroupCipher bobGroupCipher;

        GroupCipherSetup(SignalGroupCipher aliceGroupCipher, SignalGroupCipher bobGroupCipher) {
            this.aliceGroupCipher = aliceGroupCipher;
            this.bobGroupCipher = bobGroupCipher;
        }
    }

    @Benchmark
    public void groupEncryptSmall(GroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(SMALL_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void groupEncryptMedium(GroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(MEDIUM_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void groupEncryptLarge(GroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(LARGE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void groupEncryptMegabyte(GroupEncryptState state, Blackhole bh) {
        // Encrypt 100 messages
        for (int i = 0; i < 100; i++) {
            var encrypted = state.aliceGroupCipher.encrypt(MEGABYTE_MESSAGE);
            bh.consume(encrypted);
        }
    }

    @Benchmark
    public void groupDecryptSmall(GroupDecryptSmallState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void groupDecryptMedium(GroupDecryptMediumState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void groupDecryptLarge(GroupDecryptLargeState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void groupDecryptMegabyte(GroupDecryptMegabyteState state, Blackhole bh) {
        // Decrypt 100 messages
        for (var encryptedMessage : state.encryptedMessages) {
            var decrypted = state.bobGroupCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // ================== GROUP CIPHER BENCHMARKS - 2048 PARTICIPANTS, ALICE and ... ==================

    @State(Scope.Benchmark)
    public static class LargeGroupState {
        SignalGroupCipher aliceGroupCipher;
        List<SignalGroupCipher> recipientGroupCiphers;

        @Setup(Level.Invocation)
        public void setupLargeGroupCipher() {
            var setupResult = setupLargeGroupCiphers();
            aliceGroupCipher = setupResult.aliceGroupCipher;
            recipientGroupCiphers = setupResult.recipientGroupCiphers;
        }
    }

    private static LargeGroupCipherSetup setupLargeGroupCiphers() {
        // Initialize Alice's store
        var aliceGroupStore = new InMemorySignalProtocolStore();
        var aliceGroupSessionBuilder = new SignalGroupSessionBuilder(aliceGroupStore);

        // Create sender key name with Alice as the sender
        var aliceAddress = new SignalProtocolAddress("+14150001111", 1);
        var groupSender = new SignalSenderKeyName("large_group_2047", aliceAddress);

        // Create Alice's group cipher and distribution message
        var aliceDistributionMessage = aliceGroupSessionBuilder.create(groupSender);
        var aliceGroupCipher = new SignalGroupCipher(aliceGroupStore, groupSender);

        // Create 2047 recipient group ciphers
        var recipientGroupCiphers = new ArrayList<SignalGroupCipher>(2047);
        for (int i = 1; i <= 2047; i++) {
            var recipientStore = new InMemorySignalProtocolStore();
            var recipientGroupSessionBuilder = new SignalGroupSessionBuilder(recipientStore);

            // Process Alice's distribution message
            recipientGroupSessionBuilder.process(groupSender, aliceDistributionMessage);

            // Create recipient's group cipher
            var recipientGroupCipher = new SignalGroupCipher(recipientStore, groupSender);
            recipientGroupCiphers.add(recipientGroupCipher);
        }

        return new LargeGroupCipherSetup(aliceGroupCipher, recipientGroupCiphers);
    }

    private static class LargeGroupCipherSetup {
        final SignalGroupCipher aliceGroupCipher;
        final List<SignalGroupCipher> recipientGroupCiphers;

        LargeGroupCipherSetup(SignalGroupCipher aliceGroupCipher, List<SignalGroupCipher> recipientGroupCiphers) {
            this.aliceGroupCipher = aliceGroupCipher;
            this.recipientGroupCiphers = recipientGroupCiphers;
        }
    }

    @Benchmark
    public void largeGroupBroadcastSmall(LargeGroupState state, Blackhole bh) {
        // Alice encrypts a small message once
        var encryptedMessage = state.aliceGroupCipher.encrypt(SMALL_MESSAGE);
        bh.consume(encryptedMessage);

        // All 2047 recipients decrypt the same message
        for (var recipientCipher : state.recipientGroupCiphers) {
            var decrypted = recipientCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void largeGroupBroadcastMedium(LargeGroupState state, Blackhole bh) {
        // Alice encrypts a medium message once
        var encryptedMessage = state.aliceGroupCipher.encrypt(MEDIUM_MESSAGE);
        bh.consume(encryptedMessage);

        // All 2047 recipients decrypt the same message
        for (var recipientCipher : state.recipientGroupCiphers) {
            var decrypted = recipientCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void largeGroupBroadcastLarge(LargeGroupState state, Blackhole bh) {
        // Alice encrypts a large message once
        var encryptedMessage = state.aliceGroupCipher.encrypt(LARGE_MESSAGE);
        bh.consume(encryptedMessage);

        // All 2047 recipients decrypt the same message
        for (var recipientCipher : state.recipientGroupCiphers) {
            var decrypted = recipientCipher.decrypt(encryptedMessage);
            bh.consume(decrypted);
        }
    }

    // ================== EDGE CASE BENCHMARKS ==================

    @State(Scope.Benchmark)
    public static class SessionOutOfOrderState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("Out of order message " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class GroupOutOfOrderState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Prepare 100 encrypted messages
            for (int i = 0; i < 100; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(("Out of order message " + i).getBytes()));
            }
        }
    }

    @State(Scope.Benchmark)
    public static class SessionMessageKeyLimitStressState {
        SignalSessionCipher bobSessionCipher;
        List<SignalCiphertextMessage> messages;

        @Setup(Level.Invocation)
        public void setupSessionCipher() {
            var setupResult = setupSessionCiphers();
            bobSessionCipher = setupResult.bobSessionCipher;
            messages = new ArrayList<>();
            for (int i = 0; i < 2000; i++) {
                var encrypted = setupResult.aliceSessionCipher.encrypt(("stress test " + i).getBytes());
                messages.add(encrypted);
            }
        }
    }

    @State(Scope.Benchmark)
    public static class GroupMessageKeyLimitStressState {
        SignalGroupCipher bobGroupCipher;
        List<byte[]> messages;

        @Setup(Level.Invocation)
        public void setupGroupCipher() {
            var setupResult = setupGroupCiphers();
            bobGroupCipher = setupResult.bobGroupCipher;
            messages = new ArrayList<>();
            // Create many messages to test message key limits
            for (int i = 0; i < 2000; i++) {
                messages.add(setupResult.aliceGroupCipher.encrypt(("stress test " + i).getBytes()));
            }
        }
    }

    @Benchmark
    public void sessionOutOfOrderDecrypt(SessionOutOfOrderState state, Blackhole bh) {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (int i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = decryptMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void groupOutOfOrderDecrypt(GroupOutOfOrderState state, Blackhole bh) {
        // Decrypt messages in reverse order (simulating out-of-order delivery)
        for (int i = state.messages.size() - 1; i >= 0; i--) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void sessionMessageKeyLimitStress(SessionMessageKeyLimitStressState state, Blackhole bh) {
        // Decrypt every 10th message to create gaps
        for (int i = 0; i < state.messages.size(); i += 10) {
            var decrypted = decryptMessage(state.bobSessionCipher, state.messages.get(i));
            bh.consume(decrypted);
        }
    }

    @Benchmark
    public void groupMessageKeyLimitStress(GroupMessageKeyLimitStressState state, Blackhole bh) {
        // Decrypt every 10th message to create gaps
        for (int i = 0; i < state.messages.size(); i += 10) {
            var decrypted = state.bobGroupCipher.decrypt(state.messages.get(i));
            bh.consume(decrypted);
        }
    }
}