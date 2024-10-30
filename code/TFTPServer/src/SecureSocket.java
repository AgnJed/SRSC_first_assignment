package TFTPServer.src;

import Multicast.Configuration;
import Multicast.FileAccess;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SecureSocket {
    // Configuration parameters
    protected Configuration config;
    protected SecretKeySpec encryptionKey;
    protected SecretKeySpec integrityKey;
    protected Cipher cipher;
    protected int sequenceNumber = 0;

    // Constants for header sizes
    protected static final int VERSION_SIZE = 2; // 16 bits
    protected static final int RELEASE_SIZE = 1; // 8 bits
    protected static final int PAYLOAD_LEN_SIZE = 2; // 16 bits
    protected static final int HEADER_SIZE = VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE;
    protected static final int SEQ_NR_SIZE = 2; // 16 bits

    protected static final String FILE_PATH = "config.txt";

    public SecureSocket() throws Exception{
        this.config = new FileAccess().readConfigFile(FILE_PATH);
        initializeKeysAndCipher();
    }

    protected void initializeKeysAndCipher() throws Exception {
        encryptionKey = createAndValidateKey(config.getSymmetricKey(),
                config.getConfidentialityAlgorithm().split("/")[0],
                config.getSymmetricKeySize());
        cipher = Cipher.getInstance(config.getConfidentialityAlgorithm());
        if (config.getIntegrityMode() == Configuration.IntegrityMode.HMAC) {
            integrityKey = createAndValidateKey(config.getHmacKey(), config.getHmac(), config.getHmacKeySize());
        }
    }

    protected SecretKeySpec createAndValidateKey(byte[] key, String algorithm, int expectedKeySize) {
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        if (secretKey.getEncoded().length * 8 != expectedKeySize) {
            throw new IllegalArgumentException("Invalid key size for " + algorithm + ". Expected: " + expectedKeySize + " bits.");
        }
        return secretKey;
    }

    protected boolean requiresIV(String algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            return (cipher.getBlockSize() > 0 && cipher.getIV() != null) || config.isGCMMode();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return false;
        }
    }

    protected AlgorithmParameterSpec generateIV() {
        byte[] ivBytes = new byte[config.getIvSize()];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);

        if (config.isGCMMode()) {
            GCMParameterSpec spec = new GCMParameterSpec(128, ivBytes);
            config.setIv(spec.getIV());
            return spec;
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            config.setIv(ivBytes);
            return ivSpec;
        }
    }

    protected byte[] computeIntegrity(byte[] data) throws Exception {
        if (config.getIntegrityMode() == Configuration.IntegrityMode.HMAC) {
            Mac mac = Mac.getInstance(config.getHmac());
            mac.init(integrityKey);
            return mac.doFinal(data);
        } else if (config.getIntegrityMode() == Configuration.IntegrityMode.H) {
            MessageDigest digest = MessageDigest.getInstance(config.getHash());
            return digest.digest(data);
        } else {
            throw new IllegalArgumentException("Unsupported IntegrityMode: " + config.getIntegrityMode());
        }
    }

    protected ByteBuffer constructPacketBuffer(byte[] encryptedMessage, byte[] iv) {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE + iv.length + encryptedMessage.length);

        // Headers
        buffer.putShort((short) 0xFF); // Version
        buffer.put((byte) (0xF - 1));  // Release
        buffer.putShort((short) (iv.length + encryptedMessage.length)); // Payload length

        // Content
        buffer.put(iv);
        buffer.put(encryptedMessage);

        return buffer;
    }

    protected Message parseReceivedPacket(byte[] packetBuffer, int payloadLength) throws Exception {
        // Extract the sequence number as a byte array
        byte[] seqNr = Arrays.copyOfRange(packetBuffer, 0, SEQ_NR_SIZE);

        int integritySize = (config.getIntegrityMode() == Configuration.IntegrityMode.H)
                ? MessageDigest.getInstance(config.getHash()).getDigestLength()
                : Mac.getInstance(config.getHmac()).getMacLength();
        int dataLength = payloadLength - SEQ_NR_SIZE - integritySize;

        byte[] data = new byte[dataLength];
        byte[] receivedIntegrity = new byte[integritySize];

        System.arraycopy(packetBuffer, SEQ_NR_SIZE, data, 0, dataLength);
        System.arraycopy(packetBuffer, SEQ_NR_SIZE + dataLength, receivedIntegrity, 0, integritySize);

        return new Message(seqNr, data, receivedIntegrity);
    }

    protected void processSend(DatagramPacket packet) throws IOException {
        try {
            if (requiresIV(config.getConfidentialityAlgorithm())) {
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, generateIV());
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            }

            byte[] seqNr = new byte[SEQ_NR_SIZE];
            seqNr[0] = (byte) ((sequenceNumber >> 8) & 0xFF);
            seqNr[1] = (byte) (sequenceNumber & 0xFF);
            sequenceNumber++;

            byte[] data = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());
            byte[] integrity = computeIntegrity(data);

            Message msg = new Message(seqNr, data, integrity);
            System.out.println("Sending message seq nr: " + Arrays.toString(msg.sequenceNumber()));
            System.out.println("Sending message data: " + Arrays.toString(msg.data()));
            System.out.println("Sending message integrity: " + Arrays.toString(msg.integrity()));

            byte[] encryptedMessage = cipher.doFinal(msg.getAll());
            ByteBuffer packetBuffer = constructPacketBuffer(encryptedMessage, config.getIv());
            System.out.println("Sending message: " + Arrays.toString(packetBuffer.array()));

            // Update the packet with encrypted data
            packet.setData(packetBuffer.array());
            packet.setLength(packetBuffer.array().length);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Error in processSend", e);
        }
    }

    protected void processReceive(DatagramPacket packet) throws IOException {
        try {
            byte[] data = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());

            int payloadLength = ByteBuffer.wrap(data, VERSION_SIZE + RELEASE_SIZE, PAYLOAD_LEN_SIZE).getShort();
            byte[] receivedMessage = Arrays.copyOfRange(data, HEADER_SIZE, HEADER_SIZE + payloadLength);
            byte[] messageWOIv = receivedMessage;

            AlgorithmParameterSpec ivSpec;
            if (requiresIV(config.getConfidentialityAlgorithm())) {
                ivSpec = config.isGCMMode()
                        ? new GCMParameterSpec(128, Arrays.copyOfRange(receivedMessage, 0, config.getIvSize()))
                        : new IvParameterSpec(Arrays.copyOfRange(receivedMessage, 0, config.getIvSize()));
                messageWOIv = Arrays.copyOfRange(receivedMessage, config.getIvSize(), receivedMessage.length);
                cipher.init(Cipher.DECRYPT_MODE, encryptionKey, ivSpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
            }

            byte[] decryptedData = cipher.doFinal(messageWOIv);

            Message receivedData = parseReceivedPacket(decryptedData, decryptedData.length);
            System.out.println("Received message seq nr: " + Arrays.toString(receivedData.sequenceNumber()));
            System.out.println("Received message data: " + Arrays.toString(receivedData.data()));
            System.out.println("Received message integrity: " + Arrays.toString(receivedData.integrity()));

            byte[] computedIntegrity = computeIntegrity(receivedData.data());
            if (!Arrays.equals(receivedData.integrity(), computedIntegrity)) {
                throw new SecurityException("Integrity check failed.");
            }

            // Copy the extracted data into the packet's data buffer
            System.arraycopy(receivedData.data(), 0, packet.getData(), packet.getOffset(), receivedData.data().length);
            packet.setLength(receivedData.data().length);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Error in processReceive", e);
        }
    }

    // Inner class to represent a message
    protected record Message(byte[] sequenceNumber, byte[] data, byte[] integrity) {

        public byte[] getAll() {
            byte[] all = new byte[sequenceNumber.length + data.length + integrity.length];
            System.arraycopy(sequenceNumber, 0, all, 0, sequenceNumber.length);
            System.arraycopy(data, 0, all, sequenceNumber.length, data.length);
            System.arraycopy(integrity, 0, all, sequenceNumber.length + data.length, integrity.length);
            return all;
        }
    }
}

