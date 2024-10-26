package java.service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.IO.FileAccess;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.service.exceptions.OutOfOrderPacketException;
import java.util.Arrays;

public class SecureDatagramSocket implements DSTPSocket {

    private static final int VERSION_SIZE = 2; // 16 bits
    private static final int RELEASE_SIZE = 1; // 8 bits
    private static final int PAYLOAD_LEN_SIZE = 2; // 16 bits
    private static final int SEQ_NR_SIZE = 2; // 16 bits

    private DatagramSocket socket;
    private FileAccess config;
    private SecretKey encryptionKey;
    private SecretKey integrityKey;
    private Cipher cipher;
    private int sequenceNumber = 0;

    @Override
    public void initialize(InetAddress address, int port) throws IOException {
        socket = new DatagramSocket(port, address);
    }

    @Override
    public void send(String message, InetAddress address, int port) throws Exception {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] encryptedMessage = cipher.doFinal(messageBytes);

        byte[] integrity = computeIntegrity(encryptedMessage, config.getIntegrityMode());

        ByteBuffer packetBuffer = constructPacketBuffer(encryptedMessage, integrity);

        DatagramPacket packet = new DatagramPacket(packetBuffer.array(), packetBuffer.position(), address, port);
        socket.send(packet);

        sequenceNumber++;
    }

    @Override
    public String receive() throws Exception {
        byte[] buffer = new byte[1024]; // Adjust buffer size as needed
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);

        ByteBuffer packetBuffer = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());

        byte[] receivedData = parseReceivedPacket(packetBuffer, config.getIntegrityMode());

        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        byte[] decryptedMessage = cipher.doFinal(receivedData);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    @Override
    public void configure(String configPath) throws Exception {
        config = new FileAccess();
        config.readConfigFile(configPath);
        initializeKeysAndCipher();
    }

    @Override
    public void close() throws IOException {
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }

    @Override
    public int getCurrentSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Initializes the encryption and integrity keys and the cipher based on the configuration.
     * @throws Exception If an error occurs while initializing the keys or cipher.
     */
    private void initializeKeysAndCipher() throws Exception {
        encryptionKey = createAndValidateKey(config.getSymmetricKey(), config.getConfidentialityAlgorithm(),
                config.getSymmetricKeySize());
        cipher = Cipher.getInstance(config.getConfidentialityAlgorithm());
        integrityKey = createAndValidateKey(config.getMacKey(), config.getMac(), config.getMacKeySize());
    }

    /**
     * Constructs a DSTP packet buffer with the given encrypted message and integrity.
     * @param encryptedMessage The encrypted message to include in the packet.
     * @param integrity The integrity value to include in the packet.
     * @return A ByteBuffer containing the DSTP packet.
     */
    private ByteBuffer constructPacketBuffer(byte[] encryptedMessage, byte[] integrity) {
        ByteBuffer buffer = ByteBuffer.allocate(VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE + SEQ_NR_SIZE +
                encryptedMessage.length + integrity.length);

        buffer.putShort((short) 0);
        buffer.put((byte) 0);
        buffer.putShort((short) (SEQ_NR_SIZE + encryptedMessage.length + integrity.length));
        buffer.putShort((short) sequenceNumber);

        buffer.put(encryptedMessage);
        buffer.put(integrity);

        return buffer;
    }

    /**
     * Parses the received DSTP packet buffer and validates the integrity of the received message.
     * @param packetBuffer The buffer containing the received DSTP packet.
     * @param mode The integrity mode to use for validation.
     * @return The decrypted message from the packet.
     * @throws Exception If an error occurs while parsing or validating the packet.
     */
    private byte[] parseReceivedPacket(ByteBuffer packetBuffer, IntegrityMode mode) throws Exception {
        short payloadLength = packetBuffer.getShort();
        short seqNr = packetBuffer.getShort();

        if (seqNr < sequenceNumber) {
            throw new OutOfOrderPacketException("Computed sequence number: " + sequenceNumber + ", received: " + seqNr);
        }
        sequenceNumber = seqNr;

        int encryptedMessageLength = payloadLength - SEQ_NR_SIZE - (mode == IntegrityMode.H ? 32 : Mac.getInstance(config.getMac()).getMacLength());
        byte[] encryptedMessage = new byte[encryptedMessageLength];
        packetBuffer.get(encryptedMessage);

        byte[] receivedIntegrity = new byte[mode == IntegrityMode.H ? 32 : Mac.getInstance(config.getMac()).getMacLength()];
        packetBuffer.get(receivedIntegrity);

        byte[] calculatedIntegrity = computeIntegrity(encryptedMessage, mode);
        if (!Arrays.equals(receivedIntegrity, calculatedIntegrity)) {
            throw new OutOfOrderPacketException("Integrity check failed.");
        }

        return encryptedMessage;
    }

    /**
     * Computes the integrity value for the given data using the specified mode.
     * @param data The data to compute the integrity for.
     * @param mode The integrity mode to use.
     * @return The integrity value.
     * @throws Exception If an error occurs while computing the integrity, or if the mode is not supported.
     */
    private byte[] computeIntegrity(byte[] data, IntegrityMode mode) throws Exception {
        switch (mode) {
            case HMAC:
                Mac mac = Mac.getInstance(config.getMac());
                mac.init(integrityKey);
                return mac.doFinal(data);
            case H:
                MessageDigest digest = MessageDigest.getInstance(config.getH());
                return digest.digest(data);
            default:
                throw new IllegalArgumentException("Unsupported IntegrityMode: " + mode);
        }
    }

    /**
     * Creates a SecretKeySpec from the given key and validates its size.
     * @param key The key to create the SecretKeySpec from.
     * @param algorithm The algorithm to use for the key.
     * @param expectedKeySize The expected size of the key in bits.
     * @return The created SecretKeySpec.
     * @throws Exception If the key size is invalid.
     */
    private SecretKeySpec createAndValidateKey(byte[] key, String algorithm, int expectedKeySize) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        if (secretKey.getEncoded().length * 8 != expectedKeySize) { // Check in bits
            throw new IllegalArgumentException("Invalid key size for " + algorithm + ". Expected: " + expectedKeySize + " bits.");
        }
        return secretKey;
    }
}
