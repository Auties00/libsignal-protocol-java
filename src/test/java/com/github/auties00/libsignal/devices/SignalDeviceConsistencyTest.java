package com.github.auties00.libsignal.devices;

import com.github.auties00.libsignal.key.SignalIdentityKeyPair;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import com.github.auties00.libsignal.protocol.SignalDeviceConsistencyMessage;
import com.github.auties00.libsignal.protocol.SignalDeviceConsistencyMessageBuilder;
import com.github.auties00.libsignal.protocol.SignalDeviceConsistencyMessageSpec;
import org.junit.jupiter.api.Test;

import java.security.SignatureException;
import java.util.Collections;
import java.util.LinkedList;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SignalDeviceConsistencyTest {
    @Test
    public void testDeviceConsistency() throws SignatureException {
        var deviceOne = SignalIdentityKeyPair.random();
        var deviceTwo = SignalIdentityKeyPair.random();
        var deviceThree = SignalIdentityKeyPair.random();

        var keyList = new LinkedList<SignalIdentityPublicKey>();
        keyList.add(deviceOne.publicKey());
        keyList.add(deviceTwo.publicKey());
        keyList.add(deviceThree.publicKey());

        Collections.shuffle(keyList);
        var deviceOneCommitment = new SignalDeviceConsistencyCommitment(1, keyList);

        Collections.shuffle(keyList);
        var deviceTwoCommitment = new SignalDeviceConsistencyCommitment(1, keyList);

        Collections.shuffle(keyList);
        var deviceThreeCommitment = new SignalDeviceConsistencyCommitment(1, keyList);

        assertArrayEquals(deviceOneCommitment.toSerialized(), deviceTwoCommitment.toSerialized());
        assertArrayEquals(deviceTwoCommitment.toSerialized(), deviceThreeCommitment.toSerialized());

        var deviceOneMessage = new SignalDeviceConsistencyMessageBuilder()
                .commitment(deviceOneCommitment)
                .identityKeyPair(deviceOne)
                .build();
        var deviceTwoMessage = new SignalDeviceConsistencyMessageBuilder()
                .commitment(deviceTwoCommitment)
                .identityKeyPair(deviceTwo)
                .build();
        var deviceThreeMessage = new SignalDeviceConsistencyMessageBuilder()
                .commitment(deviceThreeCommitment)
                .identityKeyPair(deviceThree)
                .build();

        var receivedDeviceOneMessage = SignalDeviceConsistencyMessage.ofSerialized(SignalDeviceConsistencyMessageSpec.encode(deviceOneMessage), deviceOneCommitment, deviceOne);
        var receivedDeviceTwoMessage = SignalDeviceConsistencyMessage.ofSerialized(SignalDeviceConsistencyMessageSpec.encode(deviceTwoMessage), deviceTwoCommitment, deviceTwo);
        var receivedDeviceThreeMessage = SignalDeviceConsistencyMessage.ofSerialized(SignalDeviceConsistencyMessageSpec.encode(deviceThreeMessage), deviceThreeCommitment, deviceThree);

        assertArrayEquals(deviceOneMessage.signature().vrfOutput(), receivedDeviceOneMessage.signature().vrfOutput());
        assertArrayEquals(deviceTwoMessage.signature().vrfOutput(), receivedDeviceTwoMessage.signature().vrfOutput());
        assertArrayEquals(deviceThreeMessage.signature().vrfOutput(), receivedDeviceThreeMessage.signature().vrfOutput());

        var codeOne = generateCode(deviceOneCommitment, deviceOneMessage, receivedDeviceTwoMessage, receivedDeviceThreeMessage);
        var codeTwo = generateCode(deviceTwoCommitment, deviceTwoMessage, receivedDeviceThreeMessage, receivedDeviceOneMessage);
        var codeThree = generateCode(deviceThreeCommitment, deviceThreeMessage, receivedDeviceTwoMessage, receivedDeviceOneMessage);

        assertEquals(codeOne, codeTwo);
        assertEquals(codeTwo, codeThree);
    }

    private String generateCode(SignalDeviceConsistencyCommitment commitment, SignalDeviceConsistencyMessage... messages) {
        var signatures = new LinkedList<SignalDeviceConsistencySignature>();
        for (var message : messages) {
            signatures.add(message.signature());
        }
        return SignalDeviceConsistencyCodeGenerator.generate(commitment, signatures);
    }
}
