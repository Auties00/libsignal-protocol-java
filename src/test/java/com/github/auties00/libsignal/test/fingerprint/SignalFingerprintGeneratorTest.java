package com.github.auties00.libsignal.test.fingerprint;

import com.github.auties00.libsignal.fingerprint.SignalCombinedFingerprint;
import com.github.auties00.libsignal.fingerprint.SignalCombinedFingerprintSpec;
import com.github.auties00.libsignal.fingerprint.SignalFingerprintGenerator;
import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SignalFingerprintGeneratorTest {
    private static final byte[] ALICE_IDENTITY = {(byte) 0x05, (byte) 0x06, (byte) 0x86, (byte) 0x3b, (byte) 0xc6, (byte) 0x6d, (byte) 0x02, (byte) 0xb4, (byte) 0x0d, (byte) 0x27, (byte) 0xb8, (byte) 0xd4, (byte) 0x9c, (byte) 0xa7, (byte) 0xc0, (byte) 0x9e, (byte) 0x92, (byte) 0x39, (byte) 0x23, (byte) 0x6f, (byte) 0x9d, (byte) 0x7d, (byte) 0x25, (byte) 0xd6, (byte) 0xfc, (byte) 0xca, (byte) 0x5c, (byte) 0xe1, (byte) 0x3c, (byte) 0x70, (byte) 0x64, (byte) 0xd8, (byte) 0x68};
    private static final byte[] BOB_IDENTITY = {(byte) 0x05, (byte) 0xf7, (byte) 0x81, (byte) 0xb6, (byte) 0xfb, (byte) 0x32, (byte) 0xfe, (byte) 0xd9, (byte) 0xba, (byte) 0x1c, (byte) 0xf2, (byte) 0xde, (byte) 0x97, (byte) 0x8d, (byte) 0x4d, (byte) 0x5d, (byte) 0xa2, (byte) 0x8d, (byte) 0xc3, (byte) 0x40, (byte) 0x46, (byte) 0xae, (byte) 0x81, (byte) 0x44, (byte) 0x02, (byte) 0xb5, (byte) 0xc0, (byte) 0xdb, (byte) 0xd9, (byte) 0x6f, (byte) 0xda, (byte) 0x90, (byte) 0x7b};

    private static final int VERSION_1 = 1;
    private static final String DISPLAYABLE_FINGERPRINT_V1 = "300354477692869396892869876765458257569162576843440918079131";
    private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V1 = new byte[]{(byte) 0x08, (byte) 0x01, (byte) 0x12, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0x1e, (byte) 0x30, (byte) 0x1a, (byte) 0x03, (byte) 0x53, (byte) 0xdc, (byte) 0xe3, (byte) 0xdb, (byte) 0xe7, (byte) 0x68, (byte) 0x4c, (byte) 0xb8, (byte) 0x33, (byte) 0x6e, (byte) 0x85, (byte) 0x13, (byte) 0x6c, (byte) 0xdc, (byte) 0x0e, (byte) 0xe9, (byte) 0x62, (byte) 0x19, (byte) 0x49, (byte) 0x4a, (byte) 0xda, (byte) 0x30, (byte) 0x5d, (byte) 0x62, (byte) 0xa7, (byte) 0xbd, (byte) 0x61, (byte) 0xdf, (byte) 0x1a, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0xd6, (byte) 0x2c, (byte) 0xbf, (byte) 0x73, (byte) 0xa1, (byte) 0x15, (byte) 0x92, (byte) 0x01, (byte) 0x5b, (byte) 0x6b, (byte) 0x9f, (byte) 0x16, (byte) 0x82, (byte) 0xac, (byte) 0x30, (byte) 0x6f, (byte) 0xea, (byte) 0x3a, (byte) 0xaf, (byte) 0x38, (byte) 0x85, (byte) 0xb8, (byte) 0x4d, (byte) 0x12, (byte) 0xbc, (byte) 0xa6, (byte) 0x31, (byte) 0xe9, (byte) 0xd4, (byte) 0xfb, (byte) 0x3a, (byte) 0x4d};
    private static final byte[] BOB_SCANNABLE_FINGERPRINT_V1 = new byte[]{(byte) 0x08, (byte) 0x01, (byte) 0x12, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0xd6, (byte) 0x2c, (byte) 0xbf, (byte) 0x73, (byte) 0xa1, (byte) 0x15, (byte) 0x92, (byte) 0x01, (byte) 0x5b, (byte) 0x6b, (byte) 0x9f, (byte) 0x16, (byte) 0x82, (byte) 0xac, (byte) 0x30, (byte) 0x6f, (byte) 0xea, (byte) 0x3a, (byte) 0xaf, (byte) 0x38, (byte) 0x85, (byte) 0xb8, (byte) 0x4d, (byte) 0x12, (byte) 0xbc, (byte) 0xa6, (byte) 0x31, (byte) 0xe9, (byte) 0xd4, (byte) 0xfb, (byte) 0x3a, (byte) 0x4d, (byte) 0x1a, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0x1e, (byte) 0x30, (byte) 0x1a, (byte) 0x03, (byte) 0x53, (byte) 0xdc, (byte) 0xe3, (byte) 0xdb, (byte) 0xe7, (byte) 0x68, (byte) 0x4c, (byte) 0xb8, (byte) 0x33, (byte) 0x6e, (byte) 0x85, (byte) 0x13, (byte) 0x6c, (byte) 0xdc, (byte) 0x0e, (byte) 0xe9, (byte) 0x62, (byte) 0x19, (byte) 0x49, (byte) 0x4a, (byte) 0xda, (byte) 0x30, (byte) 0x5d, (byte) 0x62, (byte) 0xa7, (byte) 0xbd, (byte) 0x61, (byte) 0xdf};

    private static final int VERSION_2 = 2;
    private static final String DISPLAYABLE_FINGERPRINT_V2 = DISPLAYABLE_FINGERPRINT_V1;
    private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V2 = new byte[]{(byte) 0x08, (byte) 0x02, (byte) 0x12, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0x1e, (byte) 0x30, (byte) 0x1a, (byte) 0x03, (byte) 0x53, (byte) 0xdc, (byte) 0xe3, (byte) 0xdb, (byte) 0xe7, (byte) 0x68, (byte) 0x4c, (byte) 0xb8, (byte) 0x33, (byte) 0x6e, (byte) 0x85, (byte) 0x13, (byte) 0x6c, (byte) 0xdc, (byte) 0x0e, (byte) 0xe9, (byte) 0x62, (byte) 0x19, (byte) 0x49, (byte) 0x4a, (byte) 0xda, (byte) 0x30, (byte) 0x5d, (byte) 0x62, (byte) 0xa7, (byte) 0xbd, (byte) 0x61, (byte) 0xdf, (byte) 0x1a, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0xd6, (byte) 0x2c, (byte) 0xbf, (byte) 0x73, (byte) 0xa1, (byte) 0x15, (byte) 0x92, (byte) 0x01, (byte) 0x5b, (byte) 0x6b, (byte) 0x9f, (byte) 0x16, (byte) 0x82, (byte) 0xac, (byte) 0x30, (byte) 0x6f, (byte) 0xea, (byte) 0x3a, (byte) 0xaf, (byte) 0x38, (byte) 0x85, (byte) 0xb8, (byte) 0x4d, (byte) 0x12, (byte) 0xbc, (byte) 0xa6, (byte) 0x31, (byte) 0xe9, (byte) 0xd4, (byte) 0xfb, (byte) 0x3a, (byte) 0x4d};
    private static final byte[] BOB_SCANNABLE_FINGERPRINT_V2 = new byte[]{(byte) 0x08, (byte) 0x02, (byte) 0x12, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0xd6, (byte) 0x2c, (byte) 0xbf, (byte) 0x73, (byte) 0xa1, (byte) 0x15, (byte) 0x92, (byte) 0x01, (byte) 0x5b, (byte) 0x6b, (byte) 0x9f, (byte) 0x16, (byte) 0x82, (byte) 0xac, (byte) 0x30, (byte) 0x6f, (byte) 0xea, (byte) 0x3a, (byte) 0xaf, (byte) 0x38, (byte) 0x85, (byte) 0xb8, (byte) 0x4d, (byte) 0x12, (byte) 0xbc, (byte) 0xa6, (byte) 0x31, (byte) 0xe9, (byte) 0xd4, (byte) 0xfb, (byte) 0x3a, (byte) 0x4d, (byte) 0x1a, (byte) 0x22, (byte) 0x0a, (byte) 0x20, (byte) 0x1e, (byte) 0x30, (byte) 0x1a, (byte) 0x03, (byte) 0x53, (byte) 0xdc, (byte) 0xe3, (byte) 0xdb, (byte) 0xe7, (byte) 0x68, (byte) 0x4c, (byte) 0xb8, (byte) 0x33, (byte) 0x6e, (byte) 0x85, (byte) 0x13, (byte) 0x6c, (byte) 0xdc, (byte) 0x0e, (byte) 0xe9, (byte) 0x62, (byte) 0x19, (byte) 0x49, (byte) 0x4a, (byte) 0xda, (byte) 0x30, (byte) 0x5d, (byte) 0x62, (byte) 0xa7, (byte) 0xbd, (byte) 0x61, (byte) 0xdf};

    @Test
    public void testVectorsVersion1() {
        var aliceIdentityKey = SignalIdentityPublicKey.ofDirect(ALICE_IDENTITY);
        var bobIdentityKey = SignalIdentityPublicKey.ofDirect(BOB_IDENTITY);
        byte[] aliceStableId = "+14152222222".getBytes();
        byte[] bobStableId = "+14153333333".getBytes();

        var generator = new SignalFingerprintGenerator(5200);

        var aliceFingerprint = generator.generate(VERSION_1,
                aliceStableId, aliceIdentityKey,
                bobStableId, bobIdentityKey);

        var bobFingerprint = generator.generate(VERSION_1,
                bobStableId, bobIdentityKey,
                aliceStableId, aliceIdentityKey);

        assertEquals(DISPLAYABLE_FINGERPRINT_V1, aliceFingerprint.toDisplayText());
        assertEquals(DISPLAYABLE_FINGERPRINT_V1, bobFingerprint.toDisplayText());

        assertEquals(SignalCombinedFingerprintSpec.decode(ALICE_SCANNABLE_FINGERPRINT_V1), aliceFingerprint);
        assertEquals(SignalCombinedFingerprintSpec.decode(BOB_SCANNABLE_FINGERPRINT_V1), bobFingerprint);
    }

    @Test
    public void testVectorsVersion2() {
        var aliceIdentityKey = SignalIdentityPublicKey.ofDirect(ALICE_IDENTITY);
        var bobIdentityKey = SignalIdentityPublicKey.ofDirect(BOB_IDENTITY);
        byte[] aliceStableId = "+14152222222".getBytes();
        byte[] bobStableId = "+14153333333".getBytes();


        var generator = new SignalFingerprintGenerator(5200);

        var aliceFingerprint = generator.generate(VERSION_2,
                aliceStableId, aliceIdentityKey,
                bobStableId, bobIdentityKey);

        var bobFingerprint = generator.generate(VERSION_2,
                bobStableId, bobIdentityKey,
                aliceStableId, aliceIdentityKey);

        assertEquals(DISPLAYABLE_FINGERPRINT_V2, aliceFingerprint.toDisplayText());
        assertEquals(DISPLAYABLE_FINGERPRINT_V2, bobFingerprint.toDisplayText());

        assertEquals(SignalCombinedFingerprintSpec.decode(ALICE_SCANNABLE_FINGERPRINT_V2), aliceFingerprint);
        assertEquals(SignalCombinedFingerprintSpec.decode(BOB_SCANNABLE_FINGERPRINT_V2), bobFingerprint);
    }

    @Test
    public void testMatchingFingerprints() {
        var aliceKeyPair = SignalIdentityKeyPair.random();
        var bobKeyPair = SignalIdentityKeyPair.random();

        var aliceIdentityKey = aliceKeyPair.publicKey();
        var bobIdentityKey = bobKeyPair.publicKey();

        var generator = new SignalFingerprintGenerator(1024);
        var aliceFingerprint = generator.generate(VERSION_1,
                "+14152222222".getBytes(), aliceIdentityKey,
                "+14153333333".getBytes(), bobIdentityKey);

        var bobFingerprint = generator.generate(VERSION_1,
                "+14153333333".getBytes(), bobIdentityKey,
                "+14152222222".getBytes(), aliceIdentityKey);

        assertEquals(aliceFingerprint.toDisplayText(), bobFingerprint.toDisplayText());

        assertEquals(aliceFingerprint.localFingerprint(), bobFingerprint.remoteFingerprint());

        assertEquals(60, aliceFingerprint.toDisplayText().length());
    }

    @Test
    public void testMismatchingFingerprints() {
        var aliceKeyPair = SignalIdentityKeyPair.random();
        var bobKeyPair = SignalIdentityKeyPair.random();
        var mitmKeyPair = SignalIdentityKeyPair.random();

        var aliceIdentityKey = aliceKeyPair.publicKey();
        var bobIdentityKey = bobKeyPair.publicKey();
        var mitmIdentityKey = mitmKeyPair.publicKey();

        var generator = new SignalFingerprintGenerator(1024);
        var aliceFingerprint = generator.generate(VERSION_1,
                "+14152222222".getBytes(), aliceIdentityKey,
                "+14153333333".getBytes(), mitmIdentityKey);

        var bobFingerprint = generator.generate(VERSION_1,
                "+14153333333".getBytes(), bobIdentityKey,
                "+14152222222".getBytes(), aliceIdentityKey);

        assertNotEquals(aliceFingerprint.toDisplayText(), bobFingerprint.toDisplayText());

        assertNotEquals(aliceFingerprint, bobFingerprint);
        assertNotEquals(bobFingerprint, aliceFingerprint);
    }

    @Test
    public void testMismatchingIdentifiers() {
        var aliceKeyPair = SignalIdentityKeyPair.random();
        var bobKeyPair = SignalIdentityKeyPair.random();

        var aliceIdentityKey = aliceKeyPair.publicKey();
        var bobIdentityKey = bobKeyPair.publicKey();

        SignalFingerprintGenerator generator = new SignalFingerprintGenerator(1024);
        var aliceFingerprint = generator.generate(VERSION_1,
                "+141512222222".getBytes(), aliceIdentityKey,
                "+14153333333".getBytes(), bobIdentityKey);

        var bobFingerprint = generator.generate(VERSION_1,
                "+14153333333".getBytes(), bobIdentityKey,
                "+14152222222".getBytes(), aliceIdentityKey);

        assertNotEquals(aliceFingerprint.toDisplayText(), bobFingerprint.toDisplayText());

        assertNotEquals(aliceFingerprint, bobFingerprint);
        assertNotEquals(bobFingerprint, aliceFingerprint);
    }

    @Test
    public void testDifferentVersionsMakeSameFingerPrintsButDifferentScannable() {
        var aliceIdentityKey = SignalIdentityPublicKey.ofDirect(ALICE_IDENTITY);
        var bobIdentityKey = SignalIdentityPublicKey.ofDirect(BOB_IDENTITY);
        byte[] aliceStableId = "+14152222222".getBytes();
        byte[] bobStableId = "+14153333333".getBytes();

        SignalFingerprintGenerator generator = new SignalFingerprintGenerator(5200);

        var aliceFingerprintV1 = generator.generate(VERSION_1,
                aliceStableId, aliceIdentityKey,
                bobStableId, bobIdentityKey);

        var aliceFingerprintV2 = generator.generate(VERSION_2,
                aliceStableId, aliceIdentityKey,
                bobStableId, bobIdentityKey);

        assertEquals(aliceFingerprintV1.toDisplayText(), aliceFingerprintV2.toDisplayText());

        assertNotEquals(aliceFingerprintV1, aliceFingerprintV2);
    }
}
