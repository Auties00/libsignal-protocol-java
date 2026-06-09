package com.github.auties00.libsignal.benchmark;

import com.github.auties00.libsignal.util.HKDF;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.KDF;
import javax.crypto.Mac;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class HKDFBenchmarks {
    // Test messages of various sizes (static to avoid recreation)
    private static final byte[] SMALL_MESSAGE = "Hello, this is a typical text message".getBytes();
    private static final byte[] MEDIUM_MESSAGE = generateRandom(1024); // 1KB
    private static final byte[] LARGE_MESSAGE = generateRandom(64 * 1024); // 64KB
    private static final byte[] EXTRA_LARGE_MESSAGE = generateRandom(1024 * 1024); // 1MB

    private static final byte[] KEY = generateRandom(32);
    private static final SecretKeySpec JCA_KEY = new SecretKeySpec(KEY, "AES");

    private static final int OUTPUT_LENGTH = 64; // Indicative of expansions size used by the library

    private static byte[] generateRandom(int size) {
        var message = new byte[size];
        new Random(42).nextBytes(message); // Deterministic for consistent benchmarks
        return message;
    }

    @Benchmark
    public void newJavaLibSmallMessage(Blackhole blackhole) throws GeneralSecurityException {
        var mac = Mac.getInstance("HmacSHA256");
        blackhole.consume(HKDF.deriveSecrets(3, mac, KEY, SMALL_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void newJavaLibMediumMessage(Blackhole blackhole) throws GeneralSecurityException {
        var mac = Mac.getInstance("HmacSHA256");
        blackhole.consume(HKDF.deriveSecrets(3, mac, KEY, MEDIUM_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void newJavaLibLargeMessage(Blackhole blackhole) throws GeneralSecurityException {
        var mac = Mac.getInstance("HmacSHA256");
        blackhole.consume(HKDF.deriveSecrets(3, mac, KEY, LARGE_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void newJavaLibExtraLargeMessage(Blackhole blackhole) throws GeneralSecurityException {
        var mac = Mac.getInstance("HmacSHA256");
        blackhole.consume(HKDF.deriveSecrets(3, mac, KEY, EXTRA_LARGE_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void rustBindingsLibSmallMessage(Blackhole blackhole) {
        blackhole.consume(org.signal.libsignal.protocol.kdf.HKDF.deriveSecrets(KEY, SMALL_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void rustBindingsLibMediumMessage(Blackhole blackhole) {
        blackhole.consume(org.signal.libsignal.protocol.kdf.HKDF.deriveSecrets(KEY, MEDIUM_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void rustBindingsLibLargeMessage(Blackhole blackhole) {
        blackhole.consume(org.signal.libsignal.protocol.kdf.HKDF.deriveSecrets(KEY, LARGE_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void rustBindingsLibExtraLargeMessage(Blackhole blackhole) {
        blackhole.consume(org.signal.libsignal.protocol.kdf.HKDF.deriveSecrets(KEY, EXTRA_LARGE_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void oldJavaLibSmallMessage(Blackhole blackhole) {
        var hkdf = archived.org.whispersystems.libsignal.kdf.HKDF.createFor(3);
        blackhole.consume(hkdf.deriveSecrets(KEY, SMALL_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void oldJavaLibMediumMessage(Blackhole blackhole) {
        var hkdf = archived.org.whispersystems.libsignal.kdf.HKDF.createFor(3);
        blackhole.consume(hkdf.deriveSecrets(KEY, MEDIUM_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void oldJavaLibLargeMessage(Blackhole blackhole) {
        var hkdf = archived.org.whispersystems.libsignal.kdf.HKDF.createFor(3);
        blackhole.consume(hkdf.deriveSecrets(KEY, LARGE_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void oldJavaLibExtraLargeMessage(Blackhole blackhole) {
        var hkdf = archived.org.whispersystems.libsignal.kdf.HKDF.createFor(3);
        blackhole.consume(hkdf.deriveSecrets(KEY, EXTRA_LARGE_MESSAGE, OUTPUT_LENGTH));
    }

    @Benchmark
    public void jcaSmallMessage(Blackhole blackhole) throws GeneralSecurityException {
        var kdf = KDF.getInstance("HKDF-SHA256");
        var spec = HKDFParameterSpec.ofExtract()
                .thenExpand(SMALL_MESSAGE, OUTPUT_LENGTH);
        blackhole.consume(kdf.deriveData(spec));
    }

    @Benchmark
    public void jcaMediumMessage(Blackhole blackhole) throws GeneralSecurityException {
        var kdf = KDF.getInstance("HKDF-SHA256");
        var spec = HKDFParameterSpec.ofExtract()
                .thenExpand(MEDIUM_MESSAGE, OUTPUT_LENGTH);
        blackhole.consume(kdf.deriveData(spec));
    }

    @Benchmark
    public void jcaLargeMessage(Blackhole blackhole) throws GeneralSecurityException {
        var kdf = KDF.getInstance("HKDF-SHA256");
        var spec = HKDFParameterSpec.ofExtract()
                .thenExpand(LARGE_MESSAGE, OUTPUT_LENGTH);
        blackhole.consume(kdf.deriveData(spec));
    }

    @Benchmark
    public void jcaExtraLargeMessage(Blackhole blackhole) throws GeneralSecurityException {
        var kdf = KDF.getInstance("HKDF-SHA256");
        var spec = HKDFParameterSpec.ofExtract()
                .thenExpand(EXTRA_LARGE_MESSAGE, OUTPUT_LENGTH);
        blackhole.consume(kdf.deriveData(spec));
    }
}
