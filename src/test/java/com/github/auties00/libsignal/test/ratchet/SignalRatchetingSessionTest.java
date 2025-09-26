package com.github.auties00.libsignal.test.ratchet;

import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPrivateKey;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.ratchet.*;
import com.github.auties00.libsignal.state.SignalSessionChain;
import com.github.auties00.libsignal.state.SignalSessionState;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SignalRatchetingSessionTest {
    @Test
    public void testRatchetingSessionAsBob() {
        var bobPublic = new byte[]{(byte) 0x05, (byte) 0x2c, (byte) 0xb4, (byte) 0x97,
                (byte) 0x76, (byte) 0xb8, (byte) 0x77, (byte) 0x02,
                (byte) 0x05, (byte) 0x74, (byte) 0x5a, (byte) 0x3a,
                (byte) 0x6e, (byte) 0x24, (byte) 0xf5, (byte) 0x79,
                (byte) 0xcd, (byte) 0xb4, (byte) 0xba, (byte) 0x7a,
                (byte) 0x89, (byte) 0x04, (byte) 0x10, (byte) 0x05,
                (byte) 0x92, (byte) 0x8e, (byte) 0xbb, (byte) 0xad,
                (byte) 0xc9, (byte) 0xc0, (byte) 0x5a, (byte) 0xd4,
                (byte) 0x58};

        var bobPrivate = new byte[]{(byte) 0xa1, (byte) 0xca, (byte) 0xb4, (byte) 0x8f,
                (byte) 0x7c, (byte) 0x89, (byte) 0x3f, (byte) 0xaf,
                (byte) 0xa9, (byte) 0x88, (byte) 0x0a, (byte) 0x28,
                (byte) 0xc3, (byte) 0xb4, (byte) 0x99, (byte) 0x9d,
                (byte) 0x28, (byte) 0xd6, (byte) 0x32, (byte) 0x95,
                (byte) 0x62, (byte) 0xd2, (byte) 0x7a, (byte) 0x4e,
                (byte) 0xa4, (byte) 0xe2, (byte) 0x2e, (byte) 0x9f,
                (byte) 0xf1, (byte) 0xbd, (byte) 0xd6, (byte) 0x5a};

        var bobIdentityPublic = new byte[]{(byte) 0x05, (byte) 0xf1, (byte) 0xf4, (byte) 0x38,
                (byte) 0x74, (byte) 0xf6, (byte) 0x96, (byte) 0x69,
                (byte) 0x56, (byte) 0xc2, (byte) 0xdd, (byte) 0x47,
                (byte) 0x3f, (byte) 0x8f, (byte) 0xa1, (byte) 0x5a,
                (byte) 0xde, (byte) 0xb7, (byte) 0x1d, (byte) 0x1c,
                (byte) 0xb9, (byte) 0x91, (byte) 0xb2, (byte) 0x34,
                (byte) 0x16, (byte) 0x92, (byte) 0x32, (byte) 0x4c,
                (byte) 0xef, (byte) 0xb1, (byte) 0xc5, (byte) 0xe6,
                (byte) 0x26};

        var bobIdentityPrivate = new byte[]{(byte) 0x48, (byte) 0x75, (byte) 0xcc, (byte) 0x69,
                (byte) 0xdd, (byte) 0xf8, (byte) 0xea, (byte) 0x07,
                (byte) 0x19, (byte) 0xec, (byte) 0x94, (byte) 0x7d,
                (byte) 0x61, (byte) 0x08, (byte) 0x11, (byte) 0x35,
                (byte) 0x86, (byte) 0x8d, (byte) 0x5f, (byte) 0xd8,
                (byte) 0x01, (byte) 0xf0, (byte) 0x2c, (byte) 0x02,
                (byte) 0x25, (byte) 0xe5, (byte) 0x16, (byte) 0xdf,
                (byte) 0x21, (byte) 0x56, (byte) 0x60, (byte) 0x5e};

        var aliceBasePublic = new byte[]{(byte) 0x05, (byte) 0x47, (byte) 0x2d, (byte) 0x1f,
                (byte) 0xb1, (byte) 0xa9, (byte) 0x86, (byte) 0x2c,
                (byte) 0x3a, (byte) 0xf6, (byte) 0xbe, (byte) 0xac,
                (byte) 0xa8, (byte) 0x92, (byte) 0x02, (byte) 0x77,
                (byte) 0xe2, (byte) 0xb2, (byte) 0x6f, (byte) 0x4a,
                (byte) 0x79, (byte) 0x21, (byte) 0x3e, (byte) 0xc7,
                (byte) 0xc9, (byte) 0x06, (byte) 0xae, (byte) 0xb3,
                (byte) 0x5e, (byte) 0x03, (byte) 0xcf, (byte) 0x89,
                (byte) 0x50};

        var aliceEphemeralPublic = new byte[]{(byte) 0x05, (byte) 0x6c, (byte) 0x3e, (byte) 0x0d,
                (byte) 0x1f, (byte) 0x52, (byte) 0x02, (byte) 0x83,
                (byte) 0xef, (byte) 0xcc, (byte) 0x55, (byte) 0xfc,
                (byte) 0xa5, (byte) 0xe6, (byte) 0x70, (byte) 0x75,
                (byte) 0xb9, (byte) 0x04, (byte) 0x00, (byte) 0x7f,
                (byte) 0x18, (byte) 0x81, (byte) 0xd1, (byte) 0x51,
                (byte) 0xaf, (byte) 0x76, (byte) 0xdf, (byte) 0x18,
                (byte) 0xc5, (byte) 0x1d, (byte) 0x29, (byte) 0xd3,
                (byte) 0x4b};

        var aliceIdentityPublic = new byte[]{(byte) 0x05, (byte) 0xb4, (byte) 0xa8, (byte) 0x45,
                (byte) 0x56, (byte) 0x60, (byte) 0xad, (byte) 0xa6,
                (byte) 0x5b, (byte) 0x40, (byte) 0x10, (byte) 0x07,
                (byte) 0xf6, (byte) 0x15, (byte) 0xe6, (byte) 0x54,
                (byte) 0x04, (byte) 0x17, (byte) 0x46, (byte) 0x43,
                (byte) 0x2e, (byte) 0x33, (byte) 0x39, (byte) 0xc6,
                (byte) 0x87, (byte) 0x51, (byte) 0x49, (byte) 0xbc,
                (byte) 0xee, (byte) 0xfc, (byte) 0xb4, (byte) 0x2b,
                (byte) 0x4a};

        var bobSignedPreKeyPublic = new byte[]{(byte) 0x05, (byte) 0xac, (byte) 0x24, (byte) 0x8a, (byte) 0x8f,
                (byte) 0x26, (byte) 0x3b, (byte) 0xe6, (byte) 0x86, (byte) 0x35,
                (byte) 0x76, (byte) 0xeb, (byte) 0x03, (byte) 0x62, (byte) 0xe2,
                (byte) 0x8c, (byte) 0x82, (byte) 0x8f, (byte) 0x01, (byte) 0x07,
                (byte) 0xa3, (byte) 0x37, (byte) 0x9d, (byte) 0x34, (byte) 0xba,
                (byte) 0xb1, (byte) 0x58, (byte) 0x6b, (byte) 0xf8, (byte) 0xc7,
                (byte) 0x70, (byte) 0xcd, (byte) 0x67};

        var bobSignedPreKeyPrivate = new byte[]{(byte) 0x58, (byte) 0x39, (byte) 0x00, (byte) 0x13, (byte) 0x1f,
                (byte) 0xb7, (byte) 0x27, (byte) 0x99, (byte) 0x8b, (byte) 0x78,
                (byte) 0x03, (byte) 0xfe, (byte) 0x6a, (byte) 0xc2, (byte) 0x2c,
                (byte) 0xc5, (byte) 0x91, (byte) 0xf3, (byte) 0x42, (byte) 0xe4,
                (byte) 0xe4, (byte) 0x2a, (byte) 0x8c, (byte) 0x8d, (byte) 0x5d,
                (byte) 0x78, (byte) 0x19, (byte) 0x42, (byte) 0x09, (byte) 0xb8,
                (byte) 0xd2, (byte) 0x53};

        var senderChain = new byte[]{(byte) 0x97, (byte) 0x97, (byte) 0xca, (byte) 0xca, (byte) 0x53,
                (byte) 0xc9, (byte) 0x89, (byte) 0xbb, (byte) 0xe2, (byte) 0x29,
                (byte) 0xa4, (byte) 0x0c, (byte) 0xa7, (byte) 0x72, (byte) 0x70,
                (byte) 0x10, (byte) 0xeb, (byte) 0x26, (byte) 0x04, (byte) 0xfc,
                (byte) 0x14, (byte) 0x94, (byte) 0x5d, (byte) 0x77, (byte) 0x95,
                (byte) 0x8a, (byte) 0x0a, (byte) 0xed, (byte) 0xa0, (byte) 0x88,
                (byte) 0xb4, (byte) 0x4d};

        var bobIdentityKeyPublic = SignalIdentityPublicKey.ofDirect(bobIdentityPublic);
        var bobIdentityKeyPrivate = SignalIdentityPrivateKey.ofDirect(bobIdentityPrivate);
        var bobIdentityKey = new SignalIdentityKeyPair(bobIdentityKeyPublic, bobIdentityKeyPrivate);
        var bobEphemeralPublicKey = SignalIdentityPublicKey.ofDirect(bobPublic);
        var bobEphemeralPrivateKey = SignalIdentityPrivateKey.ofDirect(bobPrivate);
        var bobEphemeralKey = new SignalIdentityKeyPair(bobEphemeralPublicKey, bobEphemeralPrivateKey);
        var bobSignedKeyPublic = SignalIdentityPublicKey.ofDirect(bobSignedPreKeyPublic);
        var bobSignedKeyPrivate = SignalIdentityPrivateKey.ofDirect(bobSignedPreKeyPrivate);
        var bobSignedPreKey = new SignalIdentityKeyPair(bobIdentityKeyPublic, bobSignedKeyPrivate);
        var aliceBasePublicKey = SignalIdentityPublicKey.ofDirect(aliceBasePublic);
        var aliceEphemeralPublicKey = SignalIdentityPublicKey.ofDirect(aliceEphemeralPublic);
        var aliceIdentityPublicKey = SignalIdentityPublicKey.ofDirect(aliceIdentityPublic);

        var parameters = new SignalBobParametersBuilder()
                .ourIdentityKey(bobIdentityKey)
                .ourSignedPreKey(bobSignedPreKey)
                .ourRatchetKey(bobEphemeralKey)
                .ourOneTimePreKey(null)
                .theirIdentityKey(aliceIdentityPublicKey)
                .theirBaseKey(aliceBasePublicKey)
                .build();

        var session = new SignalSessionState();

        SignalRatchetingSession.initializeSession(session, parameters);

        assertEquals(session.localIdentityPublic(), bobIdentityKey.publicKey());
        assertEquals(session.remoteIdentityPublic(), aliceIdentityPublicKey);
        var expectedSenderChainKey = session.senderChain()
                .map(SignalSessionChain::chainKey)
                .map(SignalChainKey::key)
                .orElse(null);
        assertArrayEquals(expectedSenderChainKey, senderChain);
    }

    @Test
    public void testRatchetingSessionAsAlice() {
        var bobPublic = new byte[]{(byte) 0x05, (byte) 0x2c, (byte) 0xb4, (byte) 0x97, (byte) 0x76,
                (byte) 0xb8, (byte) 0x77, (byte) 0x02, (byte) 0x05, (byte) 0x74,
                (byte) 0x5a, (byte) 0x3a, (byte) 0x6e, (byte) 0x24, (byte) 0xf5,
                (byte) 0x79, (byte) 0xcd, (byte) 0xb4, (byte) 0xba, (byte) 0x7a,
                (byte) 0x89, (byte) 0x04, (byte) 0x10, (byte) 0x05, (byte) 0x92,
                (byte) 0x8e, (byte) 0xbb, (byte) 0xad, (byte) 0xc9, (byte) 0xc0,
                (byte) 0x5a, (byte) 0xd4, (byte) 0x58};

        var bobIdentityPublic = new byte[]{(byte) 0x05, (byte) 0xf1, (byte) 0xf4, (byte) 0x38, (byte) 0x74,
                (byte) 0xf6, (byte) 0x96, (byte) 0x69, (byte) 0x56, (byte) 0xc2,
                (byte) 0xdd, (byte) 0x47, (byte) 0x3f, (byte) 0x8f, (byte) 0xa1,
                (byte) 0x5a, (byte) 0xde, (byte) 0xb7, (byte) 0x1d, (byte) 0x1c,
                (byte) 0xb9, (byte) 0x91, (byte) 0xb2, (byte) 0x34, (byte) 0x16,
                (byte) 0x92, (byte) 0x32, (byte) 0x4c, (byte) 0xef, (byte) 0xb1,
                (byte) 0xc5, (byte) 0xe6, (byte) 0x26};

        var bobSignedPreKeyPublic = new byte[]{(byte) 0x05, (byte) 0xac, (byte) 0x24, (byte) 0x8a, (byte) 0x8f,
                (byte) 0x26, (byte) 0x3b, (byte) 0xe6, (byte) 0x86, (byte) 0x35,
                (byte) 0x76, (byte) 0xeb, (byte) 0x03, (byte) 0x62, (byte) 0xe2,
                (byte) 0x8c, (byte) 0x82, (byte) 0x8f, (byte) 0x01, (byte) 0x07,
                (byte) 0xa3, (byte) 0x37, (byte) 0x9d, (byte) 0x34, (byte) 0xba,
                (byte) 0xb1, (byte) 0x58, (byte) 0x6b, (byte) 0xf8, (byte) 0xc7,
                (byte) 0x70, (byte) 0xcd, (byte) 0x67};

        var aliceBasePublic = new byte[]{(byte) 0x05, (byte) 0x47, (byte) 0x2d, (byte) 0x1f, (byte) 0xb1,
                (byte) 0xa9, (byte) 0x86, (byte) 0x2c, (byte) 0x3a, (byte) 0xf6,
                (byte) 0xbe, (byte) 0xac, (byte) 0xa8, (byte) 0x92, (byte) 0x02,
                (byte) 0x77, (byte) 0xe2, (byte) 0xb2, (byte) 0x6f, (byte) 0x4a,
                (byte) 0x79, (byte) 0x21, (byte) 0x3e, (byte) 0xc7, (byte) 0xc9,
                (byte) 0x06, (byte) 0xae, (byte) 0xb3, (byte) 0x5e, (byte) 0x03,
                (byte) 0xcf, (byte) 0x89, (byte) 0x50};

        var aliceBasePrivate = new byte[]{(byte) 0x11, (byte) 0xae, (byte) 0x7c, (byte) 0x64, (byte) 0xd1,
                (byte) 0xe6, (byte) 0x1c, (byte) 0xd5, (byte) 0x96, (byte) 0xb7,
                (byte) 0x6a, (byte) 0x0d, (byte) 0xb5, (byte) 0x01, (byte) 0x26,
                (byte) 0x73, (byte) 0x39, (byte) 0x1c, (byte) 0xae, (byte) 0x66,
                (byte) 0xed, (byte) 0xbf, (byte) 0xcf, (byte) 0x07, (byte) 0x3b,
                (byte) 0x4d, (byte) 0xa8, (byte) 0x05, (byte) 0x16, (byte) 0xa4,
                (byte) 0x74, (byte) 0x49};

        var aliceEphemeralPublic = new byte[]{(byte) 0x05, (byte) 0x6c, (byte) 0x3e, (byte) 0x0d, (byte) 0x1f,
                (byte) 0x52, (byte) 0x02, (byte) 0x83, (byte) 0xef, (byte) 0xcc,
                (byte) 0x55, (byte) 0xfc, (byte) 0xa5, (byte) 0xe6, (byte) 0x70,
                (byte) 0x75, (byte) 0xb9, (byte) 0x04, (byte) 0x00, (byte) 0x7f,
                (byte) 0x18, (byte) 0x81, (byte) 0xd1, (byte) 0x51, (byte) 0xaf,
                (byte) 0x76, (byte) 0xdf, (byte) 0x18, (byte) 0xc5, (byte) 0x1d,
                (byte) 0x29, (byte) 0xd3, (byte) 0x4b};

        var aliceEphemeralPrivate = new byte[]{(byte) 0xd1, (byte) 0xba, (byte) 0x38, (byte) 0xce, (byte) 0xa9,
                (byte) 0x17, (byte) 0x43, (byte) 0xd3, (byte) 0x39, (byte) 0x39,
                (byte) 0xc3, (byte) 0x3c, (byte) 0x84, (byte) 0x98, (byte) 0x65,
                (byte) 0x09, (byte) 0x28, (byte) 0x01, (byte) 0x61, (byte) 0xb8,
                (byte) 0xb6, (byte) 0x0f, (byte) 0xc7, (byte) 0x87, (byte) 0x0c,
                (byte) 0x59, (byte) 0x9c, (byte) 0x1d, (byte) 0x46, (byte) 0x20,
                (byte) 0x12, (byte) 0x48};

        var aliceIdentityPublic = new byte[]{(byte) 0x05, (byte) 0xb4, (byte) 0xa8, (byte) 0x45, (byte) 0x56,
                (byte) 0x60, (byte) 0xad, (byte) 0xa6, (byte) 0x5b, (byte) 0x40,
                (byte) 0x10, (byte) 0x07, (byte) 0xf6, (byte) 0x15, (byte) 0xe6,
                (byte) 0x54, (byte) 0x04, (byte) 0x17, (byte) 0x46, (byte) 0x43,
                (byte) 0x2e, (byte) 0x33, (byte) 0x39, (byte) 0xc6, (byte) 0x87,
                (byte) 0x51, (byte) 0x49, (byte) 0xbc, (byte) 0xee, (byte) 0xfc,
                (byte) 0xb4, (byte) 0x2b, (byte) 0x4a};

        var aliceIdentityPrivate = new byte[]{(byte) 0x90, (byte) 0x40, (byte) 0xf0, (byte) 0xd4, (byte) 0xe0,
                (byte) 0x9c, (byte) 0xf3, (byte) 0x8f, (byte) 0x6d, (byte) 0xc7,
                (byte) 0xc1, (byte) 0x37, (byte) 0x79, (byte) 0xc9, (byte) 0x08,
                (byte) 0xc0, (byte) 0x15, (byte) 0xa1, (byte) 0xda, (byte) 0x4f,
                (byte) 0xa7, (byte) 0x87, (byte) 0x37, (byte) 0xa0, (byte) 0x80,
                (byte) 0xeb, (byte) 0x0a, (byte) 0x6f, (byte) 0x4f, (byte) 0x5f,
                (byte) 0x8f, (byte) 0x58};

        var receiverChain = new byte[]{(byte) 0x97, (byte) 0x97, (byte) 0xca, (byte) 0xca, (byte) 0x53,
                (byte) 0xc9, (byte) 0x89, (byte) 0xbb, (byte) 0xe2, (byte) 0x29,
                (byte) 0xa4, (byte) 0x0c, (byte) 0xa7, (byte) 0x72, (byte) 0x70,
                (byte) 0x10, (byte) 0xeb, (byte) 0x26, (byte) 0x04, (byte) 0xfc,
                (byte) 0x14, (byte) 0x94, (byte) 0x5d, (byte) 0x77, (byte) 0x95,
                (byte) 0x8a, (byte) 0x0a, (byte) 0xed, (byte) 0xa0, (byte) 0x88,
                (byte) 0xb4, (byte) 0x4d};

        var     bobIdentityKey           = SignalIdentityPublicKey.ofDirect(bobIdentityPublic);
        var     bobEphemeralPublicKey    = SignalIdentityPublicKey.ofDirect(bobPublic);
        var     bobSignedPreKey          = SignalIdentityPublicKey.ofDirect(bobSignedPreKeyPublic);
        var     aliceBasePublicKey       = SignalIdentityPublicKey.ofDirect(aliceBasePublic);
        var    aliceBasePrivateKey      = SignalIdentityPrivateKey.ofDirect(aliceBasePrivate);
        var       aliceBaseKey             = new SignalIdentityKeyPair(aliceBasePublicKey, aliceBasePrivateKey);
        var     aliceEphemeralPublicKey  = SignalIdentityPublicKey.ofDirect(aliceEphemeralPublic);
        var    aliceEphemeralPrivateKey = SignalIdentityPrivateKey.ofDirect(aliceEphemeralPrivate);
        var       aliceEphemeralKey        = new SignalIdentityKeyPair(aliceEphemeralPublicKey, aliceEphemeralPrivateKey);
        var     aliceIdentityPublicKey   = SignalIdentityPublicKey.ofDirect(aliceIdentityPublic);
        var    aliceIdentityPrivateKey  = SignalIdentityPrivateKey.ofDirect(aliceIdentityPrivate);
        var aliceIdentityKey         = new SignalIdentityKeyPair(aliceIdentityPublicKey, aliceIdentityPrivateKey);

        var session = new SignalSessionState();

        var parameters = new SignalAliceParametersBuilder()
                .ourBaseKey(aliceBaseKey)
                .ourIdentityKey(aliceIdentityKey)
                .theirIdentityKey(bobIdentityKey)
                .theirSignedPreKey(bobSignedPreKey)
                .theirRatchetKey(bobEphemeralPublicKey)
                .theirOneTimePreKey((SignalIdentityPublicKey) null)
                .build();

        SignalRatchetingSession.initializeSession(session, parameters);

        assertEquals(session.localIdentityPublic(), aliceIdentityKey.publicKey());
        assertEquals(session.remoteIdentityPublic(), bobIdentityKey);
        var expectedReceiverChainKey = session.findReceiverChain(bobEphemeralPublicKey)
                .map(SignalSessionChain::chainKey)
                .map(SignalChainKey::key)
                .orElse(null);
        assertArrayEquals(expectedReceiverChainKey, receiverChain);
    }
}
