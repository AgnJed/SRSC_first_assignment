import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
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
        ((MulticastSocket) socket).joinGroup(group);
    }

    @Override
    public void send(DatagramPacket packet) throws Exception {
        if (requiresIV(config.getConfidentialityAlgorithm())) {
            IvParameterSpec iv = generateIV(config.getConfidentialityAlgorithm());
            config.setIv(iv.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        }

        Message msg = new Message(new byte[sequenceNumber], packet.getData(), computeIntegrity(packet.getData(), config.getIntegrityMode()));
        System.out.println("SEQ" + Arrays.toString(msg.getSequenceNumber()));
        System.out.println("DATA: " + Arrays.toString(msg.getData()));
        System.out.println("INTEGRITY: " + Arrays.toString(msg.getIntegrity()));
        byte[] encryptedMessage = cipher.doFinal(msg.getAll());
        ByteBuffer packetBuffer = constructPacketBuffer(encryptedMessage);

        packet.setData(packetBuffer.array());
        packet.setLength(packetBuffer.array().length);
        socket.send(packet);

        sequenceNumber++;
    }

    @Override
    public String receive(DatagramPacket packet) throws Exception {
        socket.receive(packet);
        byte[] data = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), 0, data, 0, packet.getLength());

        Message receivedData = parseReceivedPacket(data, config.getIntegrityMode());

        if (requiresIV(config.getConfidentialityAlgorithm())) {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(config.getIv()));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        }

        byte[] decrypt = cipher.doFinal(receivedData.getAll());

        byte[] decryptedMessage = Arrays.copyOfRange(decrypt, SEQ_NR_SIZE, decrypt.length - receivedData.getIntegrity().length);
        byte[] receivedIntegrity = Arrays.copyOfRange(decrypt, SEQ_NR_SIZE + decryptedMessage.length, decrypt.length);
        System.out.println("DATA: " + Arrays.toString(decryptedMessage));
        System.out.println("INTEGRITY: " + Arrays.toString(receivedIntegrity));

        byte[] computedIntegrity = computeIntegrity(decryptedMessage, config.getIntegrityMode());
        System.out.println(Arrays.toString(computedIntegrity));
        if (!Arrays.equals(receivedIntegrity, computedIntegrity)) {
            logger.error(() -> "Integrity check failed. Received: " + Arrays.toString(receivedIntegrity) + ", computed: " + Arrays.toString(computedIntegrity));
            throw new IntegrityException("Integrity check failed.");
        }

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
        encryptionKey = createAndValidateKey(config.getSymmetricKey(), config.getConfidentialityAlgorithm().split("/")[0] , config.getSymmetricKeySize());
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
        buffer.putShort((short) 0); // Version
        buffer.put((byte) 0); // Release
        buffer.putShort((short) (SEQ_NR_SIZE + encryptedMessage.length)); // Payload length

        // Content
        buffer.putShort((short) sequenceNumber);
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
    private Message parseReceivedPacket(byte[] packetBuffer, IntegrityMode mode) throws Exception {
        short seqNr = ByteBuffer.wrap(packetBuffer, HEADER_SIZE, SEQ_NR_SIZE).getShort();
        short payloadLength = ByteBuffer.wrap(packetBuffer, VERSION_SIZE + RELEASE_SIZE, PAYLOAD_LEN_SIZE).getShort();

//        if (seqNr < sequenceNumber) {
//            logger.error(() -> "Received out-of-order packet. Expected: " + sequenceNumber + ", received: " + seqNr);
//            throw new OutOfOrderPacketException("Computed sequence number: " + sequenceNumber + ", received: " + seqNr);
//        }
//        sequenceNumber = seqNr;
        int integritySize = mode == IntegrityMode.H ? 32 : Mac.getInstance(config.getHmac()).getMacLength();
        int encryptedMessageLength = payloadLength - SEQ_NR_SIZE - integritySize;
        byte[] encryptedMessage = new byte[encryptedMessageLength];
        byte[] receivedIntegrity = new byte[integritySize];
        System.arraycopy(packetBuffer, HEADER_SIZE + SEQ_NR_SIZE, encryptedMessage, 0, encryptedMessageLength);
        System.arraycopy(packetBuffer, HEADER_SIZE + SEQ_NR_SIZE + encryptedMessageLength, receivedIntegrity, 0, integritySize);

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
