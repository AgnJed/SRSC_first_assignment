import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SecureDatagramSocket implements DSTPSocket, AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(SecureDatagramSocket.class);

    private static final int VERSION_SIZE = 2; // 16 bits
    private static final int RELEASE_SIZE = 1; // 8 bits
    private static final int PAYLOAD_LEN_SIZE = 2; // 16 bits
    private static final int HEADER_SIZE = VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE;
    private static final int SEQ_NR_SIZE = 2; // 16 bits

    private final DatagramSocket socket;
    private final Configuration config;
    private SecretKeySpec encryptionKey;
    private SecretKeySpec integrityKey;
    private Cipher cipher;
    private int sequenceNumber = 0;

    private final static String configPath = "./code/config.txt";

    public SecureDatagramSocket(InetAddress address, int port, boolean isMulticast) throws Exception {
        config = new FileAccess().readConfigFile(configPath);
        initializeKeysAndCipher();
        socket = isMulticast ? new MulticastSocket(port) : new DatagramSocket(port, address);
    }

    public SecureDatagramSocket(InetAddress address, int port) throws Exception {
        this(address, port, false);
    }

    public void joinGroup(InetAddress group) throws IOException {
        if (socket instanceof MulticastSocket)
            ((MulticastSocket) socket).joinGroup(group);
    }

    @Override
    public void send(DatagramPacket packet) throws Exception {
        if (requiresIV(config.getConfidentialityAlgorithm())) {
            AlgorithmParameterSpec iv = generateIV(config.getConfidentialityAlgorithm());
            config.setIv(iv);
            // save the new config with the new IV if its first message
            if (sequenceNumber == 0) {
                new FileAccess().writeConfigFile(configPath, config);
            }
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);

        } else {
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        }

        Message msg = new Message(
                ByteBuffer.allocate(SEQ_NR_SIZE).putShort((short) sequenceNumber++).array(),
                sequenceNumber == 0 ? packet.getData() : appendIV(config.getIv(), packet.getData()),
                computeIntegrity(sequenceNumber == 0 ? packet.getData() : appendIV(config.getIv(), packet.getData()), config.getIntegrityMode())
        );
        byte[] encryptedMessage = cipher.doFinal(msg.getAll());

        ByteBuffer packetBuffer = constructPacketBuffer(encryptedMessage);

        packet.setData(packetBuffer.array());
        packet.setLength(packetBuffer.array().length);
        socket.send(packet);
    }

    @Override
    public void receive(DatagramPacket packet) throws Exception {
        socket.receive(packet);
        byte[] data = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), 0, data, 0, packet.getLength());

        int payloadLength = ByteBuffer.wrap(data, VERSION_SIZE + RELEASE_SIZE, PAYLOAD_LEN_SIZE).getShort();
        byte[] receivedMessage = Arrays.copyOfRange(data, HEADER_SIZE, HEADER_SIZE + payloadLength);

        if (requiresIV(config.getConfidentialityAlgorithm())) {
            if (config.isGCMMode()) {
                cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(config.getIvSize(), config.getIv()));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(config.getIv()));
            }
        } else {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        }

        byte[] decrypt = cipher.doFinal(receivedMessage);

        Message receivedData = parseReceivedPacket(decrypt, decrypt.length, config.getIntegrityMode(), config.getIvSize() > 0);

        byte[] computedIntegrity = computeIntegrity(receivedData.getData(), config.getIntegrityMode());
        if (!Arrays.equals(receivedData.getIntegrity(), computedIntegrity)) {
            logger.error(() -> "Integrity check failed. Received: " + Arrays.toString(receivedData.getIntegrity()) + ", computed: " + Arrays.toString(computedIntegrity));
            throw new IntegrityException("Integrity check failed.");
        }

        // Copy the extracted data into the packet's original buffer, maintaining buffer size
        System.arraycopy(receivedData.getData(), 0, packet.getData(), 0, receivedData.getData().length);
        packet.setLength(receivedData.getData().length);
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
        encryptionKey = createAndValidateKey(config.getSymmetricKey(), config.getConfidentialityAlgorithm().split("/")[0], config.getSymmetricKeySize());
        cipher = Cipher.getInstance(config.getConfidentialityAlgorithm());
        if (config.getIntegrityMode() == IntegrityMode.HMAC)
            integrityKey = createAndValidateKey(config.getHmacKey(), config.getHmac(), config.getHmacKeySize());
    }

    /**
     * Constructs a DSTP packet buffer with the given encrypted message and integrity.
     *
     * @param encryptedMessage The encrypted message to include in the packet.
     * @return A ByteBuffer containing the DSTP packet.
     */
    private ByteBuffer constructPacketBuffer(byte[] encryptedMessage) {
        ByteBuffer buffer = ByteBuffer.allocate(VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE + SEQ_NR_SIZE +
                encryptedMessage.length);

        //HEADERS

        buffer.putShort((short) 0xFF); // Version
        buffer.put((byte) (0xF - 1)); // Release
        buffer.putShort((short) (encryptedMessage.length)); // Payload length

        // Content
        buffer.put(encryptedMessage);

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
    private Message parseReceivedPacket(byte[] packetBuffer, int payloadLength, IntegrityMode mode, boolean hasIv) throws Exception {
        short seqNr = ByteBuffer.wrap(packetBuffer, 0, SEQ_NR_SIZE).getShort();
        if (seqNr < sequenceNumber) {
            logger.error(() -> "Received out-of-order packet. Expected: " + sequenceNumber + ", received: " + seqNr);
            throw new OutOfOrderPacketException("Computed sequence number: " + sequenceNumber + ", received: " + seqNr);
        }
        sequenceNumber = seqNr;
        int integritySize = mode == IntegrityMode.H ? 32 : Mac.getInstance(config.getHmac()).getMacLength();
        int encryptedMessageLength = payloadLength - SEQ_NR_SIZE - integritySize - (hasIv ? config.getIvSize() : 0);
        byte[] encryptedMessage = new byte[encryptedMessageLength];
        byte[] receivedIntegrity = new byte[integritySize];
        System.arraycopy(packetBuffer, SEQ_NR_SIZE, encryptedMessage, 0, encryptedMessageLength);
        System.arraycopy(packetBuffer, SEQ_NR_SIZE + encryptedMessageLength, receivedIntegrity, 0, integritySize);

        return new Message(new byte[seqNr], encryptedMessage, receivedIntegrity);
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
                logger.error(() -> "Unsupported IntegrityMode: " + mode);
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
            logger.error(() -> "Invalid key size for " + algorithm + ". Expected: " + expectedKeySize + " bits.");
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
    public boolean requiresIV(String algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            return (cipher.getBlockSize() > 0 && cipher.getIV() != null) || config.isGCMMode();
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
    public AlgorithmParameterSpec generateIV(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        int blockSize = cipher.getBlockSize();

        byte[] ivBytes = new byte[blockSize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);

        if (config.isGCMMode()) {
            return new GCMParameterSpec(128, ivBytes); // IS HARD CODED 128 DONT EFFING LIKE IT
        } else {
            return new IvParameterSpec(ivBytes);
        }
    }

    public byte[] appendIV(byte[] iv, byte[] data) {
        byte[] result = new byte[iv.length + data.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(data, 0, result, iv.length, data.length);
        return result;
    }
}
