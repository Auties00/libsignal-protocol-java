package com.github.auties00.libsignal.protocol;

import com.github.auties00.libsignal.exception.SignalDecryptException;
import com.github.auties00.libsignal.exception.SignalMalformedMessageException;
import com.github.auties00.libsignal.key.SignalIdentityPublicKey;
import it.auties.protobuf.annotation.ProtobufBuilder;
import it.auties.protobuf.annotation.ProtobufMessage;
import it.auties.protobuf.annotation.ProtobufProperty;
import it.auties.protobuf.model.ProtobufType;
import it.auties.protobuf.stream.ProtobufInputStream;
import it.auties.protobuf.stream.ProtobufOutputStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

@ProtobufMessage(generateBuilder = false)
public final class SignalMessage extends SignalCiphertextMessage {
    private static final Integer MAC_LENGTH = 8;
    private static final String MAC_ALGORITHM = "HmacSHA256";

    private Integer version;

    @ProtobufProperty(index = 1, type = ProtobufType.BYTES)
    final SignalIdentityPublicKey senderRatchetKey;

    @ProtobufProperty(index = 2, type = ProtobufType.UINT32)
    final Integer counter;

    @ProtobufProperty(index = 3, type = ProtobufType.UINT32)
    final Integer previousCounter;

    @ProtobufProperty(index = 4, type = ProtobufType.BYTES)
    final byte[] ciphertext;

    private byte[] mac;

    SignalMessage(SignalIdentityPublicKey senderRatchetKey, Integer counter, Integer previousCounter, byte[] ciphertext) {
        // Don't set the version, it will be set by ofSerialized
        this.senderRatchetKey = senderRatchetKey;
        this.counter = counter;
        this.previousCounter = previousCounter;
        this.ciphertext = ciphertext;
        // Don't set the mac, it will be set by ofSerialized
    }

    @ProtobufBuilder(className = "SignalMessageBuilder")
    SignalMessage(Mac hmacSha256, Integer version, SignalIdentityPublicKey senderRatchetKey, Integer counter, Integer previousCounter, byte[] ciphertext,
                         SignalIdentityPublicKey localIdentityKey, SignalIdentityPublicKey remoteIdentityKey, SecretKeySpec macKey) {
        this.version = version;
        this.senderRatchetKey = senderRatchetKey;
        this.counter = counter;
        this.previousCounter = previousCounter;
        this.ciphertext = ciphertext;
        this.mac = getMac(hmacSha256, macKey, localIdentityKey, remoteIdentityKey);
    }

    public static SignalMessage ofSerialized(byte[] serialized) {
        try {
            var mac = Arrays.copyOfRange(serialized, serialized.length - MAC_LENGTH, serialized.length);
            var result = SignalMessageSpec.decode(ProtobufInputStream.fromBytes(serialized, 1, serialized.length - 1 - MAC_LENGTH));
            if (result.senderRatchetKey == null || result.counter == null || result.ciphertext == null) {
                throw new SignalMalformedMessageException("Incomplete message");
            }
            result.version = Byte.toUnsignedInt(serialized[0]) >> 4;
            result.mac = mac;
            result.serialized = serialized;
            return result;
        } catch (SignalMalformedMessageException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new SignalMalformedMessageException(exception);
        }
    }

    @Override
    public int type() {
        return WHISPER_TYPE;
    }

    @Override
    public int version() {
        if (version == null) {
            throw new InternalError();
        }

        return version;
    }

    @Override
    byte[] serialize() {
        var messageLength = SignalMessageSpec.sizeOf(this);
        var serialized = new byte[1 + messageLength + MAC_LENGTH];
        if (version == null) {
            throw new InternalError();
        }
        serialized[0] = (byte) (version << 4 | CURRENT_VERSION);
        SignalMessageSpec.encode(this, ProtobufOutputStream.toBytes(serialized, 1));
        if (mac == null || mac.length != MAC_LENGTH) {
            throw new InternalError();
        }
        System.arraycopy(mac, 0, serialized, 1 + messageLength, MAC_LENGTH);
        return serialized;
    }

    public void verifyMac(Mac hmacSha256, SignalIdentityPublicKey senderIdentityPublicKey, SignalIdentityPublicKey receiverIdentityPublicKey, SecretKeySpec macKey) {
        if(hmacSha256 == null || !MAC_ALGORITHM.equals(hmacSha256.getAlgorithm())) {
            throw new IllegalArgumentException("Invalid hmacSha256 instance");
        }

        if (mac == null || mac.length != MAC_LENGTH) {
            throw new InternalError();
        }

        var theirMac = mac;
        var ourMac = getMac(hmacSha256, macKey, senderIdentityPublicKey, receiverIdentityPublicKey);
        if (!MessageDigest.isEqual(theirMac, ourMac)) {
            throw new SignalDecryptException("Bad Mac!");
        }
    }

    private byte[] getMac(Mac hmacSha256, SecretKeySpec macKey, SignalIdentityPublicKey localIdentityKey, SignalIdentityPublicKey remoteIdentityKey) {
        try {
            var messageLength = SignalMessageSpec.sizeOf(this);
            var macInput = new byte[SignalIdentityPublicKey.lengthWithType() + SignalIdentityPublicKey.lengthWithType() + 1 + messageLength];
            var offset = localIdentityKey.writeEncodedPointWithType(macInput, 0);
            offset = remoteIdentityKey.writeEncodedPointWithType(macInput, offset);
            macInput[offset++] = (byte) (version << 4 | CURRENT_VERSION);
            SignalMessageSpec.encode(this, ProtobufOutputStream.toBytes(macInput, offset));

            hmacSha256.init(macKey);
            var mac = hmacSha256.doFinal(macInput);

            return Arrays.copyOf(mac, MAC_LENGTH);
        } catch (GeneralSecurityException exception) {
            throw new InternalError("Mac error", exception);
        }
    }

    public SignalIdentityPublicKey senderRatchetKey() {
        return senderRatchetKey;
    }

    public Integer counter() {
        return counter;
    }

    public Integer previousCounter() {
        return previousCounter;
    }

    public byte[] ciphertext() {
        return ciphertext;
    }

    public byte[] signature() {
        return mac;
    }
}
