package java.service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.IO.FileAccess;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.service.exceptions.IntegrityException;
import java.util.Arrays;

public class SecureDatagramSocket {

    private static final String CONFIG_FILE_NAME = "secret.txt";
    private final static int VERSION_HEADER_SIZE = 16;
    private final static int RELEASE_HEADER_SIZE = 8;
    private final static int PAYLOAD_LENGTH_HEADER_SIZE = 16;
    private final static int SEQUENCE_NUMBER_SIZE = 16;
    private final FileAccess config;
    private final DatagramSocket socket;
    private SecretKey encryptionKey;
    private SecretKey integrityKey;
    private Cipher cipher;

    // for sending data, we shall generate all crypo data with the provided algorithm
    // R/W
    // for receiving data we shall use the provided algorithm and keys to decrypt the data
    // R

    // Question how to initialize the secure socket aka constructor?
    // constructor overload?
    // single constructor with a mode parameter?

    // constructor that abstracts the creation of the socket
    public SecureDatagramSocket(InetAddress address, int port, Mode messageMode) throws Exception {
        socket = new DatagramSocket(port, address);

        // should the constructor call file access?
        config = new FileAccess();
        config.readConfigFile(CONFIG_FILE_NAME);
    }

    public void send(String message, IntegrityMode integrityMode) throws Exception {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // Encrypt message
        encryptionKey = createAndValidateKey(config.getSymmetricKey(), config.getConfidentialityAlgorithm(), config.getSymmetricKeySize());
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] encryptedMessage = cipher.doFinal(messageBytes);

        byte[] integrity = {};

        switch (integrityMode) {
            case HMAC: {
                // Generate HMAC for integrity
                integrityKey = createAndValidateKey(config.getMacKey(), config.getMac(), config.getMacKeySize());
                integrity = generateHMAC(encryptedMessage);
                break;
            }
            case H: {
                MessageDigest secureHash = MessageDigest.getInstance(config.getH());
                integrity = secureHash.digest(message.getBytes());
                break;
            }
        }

        // Combine encrypted message and integrity check
        byte[] secureMessage = new byte[encryptedMessage.length + integrity.length];
        System.arraycopy(encryptedMessage, 0, secureMessage, 0, encryptedMessage.length);
        System.arraycopy(integrity, 0, secureMessage, encryptedMessage.length, integrity.length);

        DatagramPacket packet = new DatagramPacket(secureMessage, secureMessage.length, socket.getInetAddress(), socket.getPort());
        socket.send(packet);
    }

    public String receive() throws Exception {
        byte[] headerBuffer = new byte[PAYLOAD_LENGTH_HEADER_SIZE + RELEASE_HEADER_SIZE + VERSION_HEADER_SIZE];
        DatagramPacket headerPacket = new DatagramPacket(headerBuffer, headerBuffer.length);
        socket.receive(headerPacket);

        int payloadLength = Integer.parseInt(new String(Arrays.copyOfRange(headerBuffer, VERSION_HEADER_SIZE + RELEASE_HEADER_SIZE, PAYLOAD_LENGTH_HEADER_SIZE), StandardCharsets.UTF_8));
        byte[] contentBuffer = new byte[payloadLength];
        DatagramPacket contentPacket = new DatagramPacket(contentBuffer, contentBuffer.length);
        socket.receive(contentPacket);
        byte[] receivedData = Arrays.copyOfRange(contentPacket.getData(), 0, contentPacket.getLength());
        byte[] messageData = receivedData;
        // read integrity check
        switch (config.getIntegrityMode()) {
            case HMAC: {
                Mac mac = Mac.getInstance(config.getMac());
                SecretKeySpec integrityKey = new SecretKeySpec(config.getMacKey(), config.getMac());
                mac.init(integrityKey);

                // Split received data into encrypted message and HMAC
                messageData = Arrays.copyOfRange(receivedData, 0, receivedData.length - mac.getMacLength());
                byte[] receivedHMAC = Arrays.copyOfRange(receivedData, receivedData.length - mac.getMacLength(), receivedData.length);

                // Verify integrity
                byte[] calculatedHMAC = generateHMAC(messageData);
                if (!Arrays.equals(receivedHMAC, calculatedHMAC)) {
                    throw new IntegrityException("HMAC does not match, message integrity compromised");
                }
                break;
            }
            case H: {
                MessageDigest secureHash = MessageDigest.getInstance(config.getH());
                byte[] receivedHash = Arrays.copyOfRange(receivedData, receivedData.length - secureHash.getDigestLength(), receivedData.length);
                messageData = Arrays.copyOfRange(receivedData, 0, receivedData.length - secureHash.getDigestLength());

                byte[] calculatedHash = secureHash.digest(messageData);
                if (!Arrays.equals(receivedHash, calculatedHash)) {
                    throw new IntegrityException("Hash does not match, message integrity compromised");
                }

                break;
            }
        }

        // Decrypt message
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        byte[] decryptedMessage = cipher.doFinal(messageData);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    private byte[] generateHMAC(byte[] data) throws Exception {
        Mac mac = Mac.getInstance(config.getMac());
        mac.init(integrityKey);
        return mac.doFinal(data);
    }

    // check if compatible with H and HMAC and Cipher
    private SecretKeySpec createAndValidateKey(byte[] key, String algorithm, int keySize) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        if (secretKey.getEncoded().length != keySize) {
            throw new Exception("Key size does not match the configuration");
        }
        return secretKey;
    }
}