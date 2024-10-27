package java.service;

import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.IO.FileAccess;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.service.exceptions.IntegrityException;
import java.service.exceptions.OutOfOrderPacketException;
import java.util.Arrays;

public class SecureDatagramSocket implements DSTPSocket, AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(SecureDatagramSocket.class);

    private static final int VERSION_SIZE = 2; // 16 bits
    private static final int RELEASE_SIZE = 1; // 8 bits
    private static final int PAYLOAD_LEN_SIZE = 2; // 16 bits
    private static final int SEQ_NR_SIZE = 2; // 16 bits

    private final DatagramSocket socket;
    private final Configuration config;
    private SecretKey encryptionKey;
    private SecretKey integrityKey;
    private Cipher cipher;
    private int sequenceNumber = 0;

    private final static String configPath = "config.txt";

    public SecureDatagramSocket(InetAddress address, int port) throws Exception {
        config = new FileAccess().readConfigFile(configPath);
        initializeKeysAndCipher();
        socket = new DatagramSocket(port, address);
    }

    @Override
    public void send(String message, InetAddress address, int port) throws Exception {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        if (requiresIV(config.getConfidentialityAlgorithm())) {
            IvParameterSpec iv = generateIV(config.getConfidentialityAlgorithm());
            config.setIv(iv.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
        } else
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);

        byte[] encryptedMessage = cipher.doFinal(messageBytes);

        byte[] integrity = computeIntegrity(encryptedMessage, config.getIntegrityMode());

        ByteBuffer packetBuffer = constructPacketBuffer(encryptedMessage, integrity);

        DatagramPacket packet = new DatagramPacket(packetBuffer.array(), packetBuffer.array().length, address, port);
        socket.send(packet);

        sequenceNumber++;
    }

    @Override
    public String receive() throws Exception {
        byte[] headerBuffer = new byte[VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE];
        DatagramPacket headerPacket = new DatagramPacket(headerBuffer, headerBuffer.length);
        socket.receive(headerPacket);

        int payloadLength = Integer.parseInt(Arrays.toString(Arrays.copyOfRange(headerBuffer, VERSION_SIZE + RELEASE_SIZE, VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE)));
        byte[] dataBuffer = new byte[payloadLength];
        DatagramPacket packet = new DatagramPacket(dataBuffer, dataBuffer.length);
        socket.receive(packet);

        ByteBuffer packetBuffer = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());

        byte[] receivedData = parseReceivedPacket(packetBuffer, config.getIntegrityMode());

        if (requiresIV(config.getConfidentialityAlgorithm())) {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(config.getIv()));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        }

        byte[] decryptedMessage = cipher.doFinal(receivedData);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    @Override
    public void close() {
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
     *
     * @throws Exception If an error occurs while initializing the keys or cipher.
     */
    private void initializeKeysAndCipher() throws Exception {
        encryptionKey = createAndValidateKey(config.getSymmetricKey(), config.getConfidentialityAlgorithm(), config.getSymmetricKeySize());
        cipher = Cipher.getInstance(config.getConfidentialityAlgorithm());
        integrityKey = createAndValidateKey(config.getHmacKey(), config.getHmac(), config.getHmacKeySize());
    }

    /**
     * Constructs a DSTP packet buffer with the given encrypted message and integrity.
     *
     * @param encryptedMessage The encrypted message to include in the packet.
     * @param integrity        The integrity value to include in the packet.
     * @return A ByteBuffer containing the DSTP packet.
     */
    private ByteBuffer constructPacketBuffer(byte[] encryptedMessage, byte[] integrity) {
        ByteBuffer buffer = ByteBuffer.allocate(VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE + SEQ_NR_SIZE +
                encryptedMessage.length + integrity.length);

        //HEADERS
        buffer.putShort((short) 0); // Version
        buffer.put((byte) 0); // Release
        buffer.putShort((short) (SEQ_NR_SIZE + encryptedMessage.length + integrity.length));

        // Content
        buffer.putShort((short) sequenceNumber);
        buffer.put(encryptedMessage);
        buffer.put(integrity);

        return buffer;
    }

    /**
     * Parses the received DSTP packet buffer and validates the integrity of the received message.
     *
     * @param packetBuffer The buffer containing the received DSTP packet.
     * @param mode         The integrity mode to use for validation.
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
        int integritySize = mode == IntegrityMode.H ? 32 : Mac.getInstance(config.getHmac()).getMacLength();
        int encryptedMessageLength = payloadLength - SEQ_NR_SIZE - integritySize;
        byte[] encryptedMessage = new byte[encryptedMessageLength];
        packetBuffer.get(0, encryptedMessage, SEQ_NR_SIZE, encryptedMessageLength);

        byte[] receivedIntegrity = new byte[integritySize];
        packetBuffer.get(0, receivedIntegrity, SEQ_NR_SIZE + encryptedMessageLength, integritySize);

        byte[] calculatedIntegrity = computeIntegrity(encryptedMessage, mode);
        if (!Arrays.equals(receivedIntegrity, calculatedIntegrity)) {
            throw new IntegrityException("Integrity check does not match.");
        }

        return encryptedMessage;
    }

    /**
     * Computes the integrity value for the given data using the specified mode.
     *
     * @param data The data to compute the integrity for.
     * @param mode The integrity mode to use.
     * @return The integrity value.
     * @throws Exception If an error occurs while computing the integrity, or if the mode is not supported.
     */
    private byte[] computeIntegrity(byte[] data, IntegrityMode mode) throws Exception {
        switch (mode) {
            case HMAC:
                Mac mac = Mac.getInstance(config.getHmac());
                mac.init(integrityKey);
                return mac.doFinal(data);
            case H:
                MessageDigest digest = MessageDigest.getInstance(config.getHash());
                return digest.digest(data);
            default:
                throw new IllegalArgumentException("Unsupported IntegrityMode: " + mode);
        }
    }

    /**
     * Creates a SecretKeySpec from the given key and validates its size.
     *
     * @param key             The key to create the SecretKeySpec from.
     * @param algorithm       The algorithm to use for the key.
     * @param expectedKeySize The expected size of the key in bits.
     * @return The created SecretKeySpec.
     */
    private SecretKeySpec createAndValidateKey(byte[] key, String algorithm, int expectedKeySize) {
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        if (secretKey.getEncoded().length * 8 != expectedKeySize) {
            throw new IllegalArgumentException("Invalid key size for " + algorithm + ". Expected: " + expectedKeySize + " bits.");
        }
        return secretKey;
    }

    /**
     * Checks if the specified algorithm requires an Initialization Vector (IV).
     *
     * @param algorithm The algorithm string (e.g., "AES/CBC/PKCS5Padding")
     * @return True if the algorithm requires an IV, false otherwise.
     */
    public static boolean requiresIV(String algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            return cipher.getBlockSize() > 0 && cipher.getIV() != null;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error(() -> "Invalid algorithm: " + algorithm);
            return false;
        }
    }

    /**
     * Generates an Initialization Vector (IV) for the specified algorithm.
     *
     * @param algorithm The algorithm string (e.g., "AES/CBC/PKCS5Padding")
     * @return IvParameterSpec containing the generated IV
     * @throws NoSuchAlgorithmException if the algorithm is not valid
     * @throws NoSuchPaddingException   if the padding is not valid
     */
    public static IvParameterSpec generateIV(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        int blockSize = cipher.getBlockSize();

        byte[] ivBytes = new byte[blockSize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);

        return new IvParameterSpec(ivBytes);
    }
}
