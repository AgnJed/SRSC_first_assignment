package TFTPServer.src;

//import org.junit.platform.commons.logging.Logger;
//import org.junit.platform.commons.logging.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SecureDatagramSocket implements DSTPSocket {

//    private static final Logger logger = LoggerFactory.getLogger(SecureDatagramSocket.class);

    private static final int VERSION_SIZE = 2; // 16 bits
    private static final int RELEASE_SIZE = 1; // 8 bits
    private static final int PAYLOAD_LEN_SIZE = 2; // 16 bits
    private static final int HEADER_SIZE = VERSION_SIZE + RELEASE_SIZE + PAYLOAD_LEN_SIZE;
    private static final int SEQ_NR_SIZE = 2; // 16 bits

    private final static String configPath = "./code/config.txt";

    private final DatagramSocket socket;
    private final Configuration config;
    private SecretKeySpec encryptionKey;
    private SecretKeySpec integrityKey;
    private Cipher cipher;
    private int sequenceNumber = 0;

    public SecureDatagramSocket() throws Exception {
        socket = new DatagramSocket();
        config = new FileAccess().readConfigFile(configPath);
        initializeKeysAndCipher();
    }

    public SecureDatagramSocket(int port) throws Exception {
        socket = new MulticastSocket(port);
        config = new FileAccess().readConfigFile(configPath);
        initializeKeysAndCipher();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        socket.setSoTimeout(timeout);
    }

    @Override
    public void joinGroup(InetAddress group) throws IOException {
        ((MulticastSocket) socket).joinGroup(group);
    }

    @Override
    public void leaveGroup(InetAddress group) throws IOException {
        ((MulticastSocket) socket).leaveGroup(group);
    }

    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }

    @Override
    public void send(DatagramPacket packet) throws IOException, IntegrityException {
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
            byte[] integrity = computeIntegrity(packet.getData(), config.getIntegrityMode());
            byte[] data = packet.getData();

            Message msg = new Message(
                    seqNr,
                    data,
                    integrity
            );

//            System.out.println("Sequence number: " + Arrays.toString(msg.sequenceNumber()));
//            System.out.println("Data: " + Arrays.toString(msg.data()));
//            System.out.println("Integrity: " + Arrays.toString(msg.integrity()));
            byte[] encryptedMessage = cipher.doFinal(msg.getAll());
//            System.out.println("Encrypted message: " + Arrays.toString(encryptedMessage));
            ByteBuffer packetBuffer = constructPacketBuffer(encryptedMessage, config.getIv());
//            System.out.println("Packet buffer: " + Arrays.toString(packetBuffer.array()));
            packet.setData(packetBuffer.array());
            packet.setLength(packetBuffer.array().length);
            socket.send(packet);

        } catch (Throwable e) {
//            logger.error(() -> "Error sending packet: " + e.getMessage());
            if (e instanceof IOException)
                throw (IOException) e;
            else if (e instanceof IntegrityException)
                throw (IntegrityException) e;
        }
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException, IntegrityException {
        try {
            socket.receive(packet);
            byte[] data = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), 0, data, 0, packet.getLength());

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

            byte[] decrypt = cipher.doFinal(messageWOIv);

            Message receivedData = parseReceivedPacket(decrypt, decrypt.length, config.getIntegrityMode());
//            System.out.println("Sequence number: " + Arrays.toString(receivedData.sequenceNumber()));
//            System.out.println("Received data: " + Arrays.toString(receivedData.data()));
//            System.out.println("Received integrity: " + Arrays.toString(receivedData.integrity()));

            byte[] computedIntegrity = computeIntegrity(receivedData.data(), config.getIntegrityMode());
            if (!Arrays.equals(receivedData.integrity(), computedIntegrity)) {
//                logger.error(() -> "Integrity check failed. Received: " + Arrays.toString(receivedData.integrity()) + ", computed: " + Arrays.toString(computedIntegrity));
                throw new IntegrityException("Integrity check failed.");
            }

            // Copy the extracted data into the packet's original buffer, maintaining buffer size
            System.arraycopy(receivedData.data(), 0, packet.getData(), 0, receivedData.data().length);
            packet.setLength(receivedData.data().length);
        } catch (Throwable e) {
//            logger.error(() -> "Error receiving packet: " + e.getMessage());
            if (e instanceof IOException)
                throw (IOException) e;
            else if (e instanceof IntegrityException)
                throw (IntegrityException) e;
        }
    }

    /**
     * Closes the DSTP socket, releasing any resources held by the socket.
     */
    @Override
    public void close() {
        socket.close();
    }

    /**
     * Gets the current sequence number of the last sent packet.
     * Useful for tracking and managing packet ordering.
     *
     * @return the current sequence number.
     */
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
        if (config.getIntegrityMode() == Configuration.IntegrityMode.HMAC)
            integrityKey = createAndValidateKey(config.getHmacKey(), config.getHmac(), config.getHmacKeySize());
    }

    /**
     * Constructs a DSTP packet buffer with the given encrypted message and integrity.
     *
     * @param encryptedMessage The encrypted message to include in the packet.
     * @return A ByteBuffer containing the DSTP packet.
     */
    private ByteBuffer constructPacketBuffer(byte[] encryptedMessage, byte[] iv) {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE + iv.length + encryptedMessage.length);

        //HEADERS
        buffer.putShort((short) 0xFF); // Version
        buffer.put((byte) (0xF - 1)); // Release
        buffer.putShort((short) (iv.length + encryptedMessage.length)); // Payload length

        // Content
        buffer.put(iv);
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
    private Message parseReceivedPacket(byte[] packetBuffer, int payloadLength, Configuration.IntegrityMode mode) throws Exception {
        short seqNr = ByteBuffer.wrap(packetBuffer, 0, SEQ_NR_SIZE).getShort();
        if (seqNr < sequenceNumber) {
//            logger.error(() -> "Received out-of-order packet. Expected: " + sequenceNumber + ", received: " + seqNr);
            throw new OutOfOrderPacketException("Computed sequence number: " + sequenceNumber + ", received: " + seqNr);
        }
        sequenceNumber = seqNr;
        int integritySize = mode == Configuration.IntegrityMode.H ? 32 : Mac.getInstance(config.getHmac()).getMacLength();
        int encryptedMessageLength = payloadLength - SEQ_NR_SIZE - integritySize;
        byte[] encryptedMessage = new byte[encryptedMessageLength];
        byte[] receivedIntegrity = new byte[integritySize];

        System.arraycopy(packetBuffer, SEQ_NR_SIZE , encryptedMessage, 0, encryptedMessageLength);
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
    private byte[] computeIntegrity(byte[] data, Configuration.IntegrityMode mode) throws Exception {
        switch (mode) {
            case HMAC:
                Mac mac = Mac.getInstance(config.getHmac());
                mac.init(integrityKey);
                return mac.doFinal(data);
            case H:
                MessageDigest digest = MessageDigest.getInstance(config.getHash());
                return digest.digest(data);
            default:
//                logger.error(() -> "Unsupported IntegrityMode: " + mode);
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
//            logger.error(() -> "Invalid key size for " + algorithm + ". Expected: " + expectedKeySize + " bits.");
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
//            logger.error(() -> "Invalid algorithm: " + algorithm);
            return false;
        }
    }

    /**
     * Generates an Initialization Vector (IV) for the specified algorithm.
     *
     * @return IvParameterSpec containing the generated IV
     */
    public AlgorithmParameterSpec generateIV() {
        byte[] ivBytes = new byte[config.getIvSize()];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);

        if (config.isGCMMode()) {
            GCMParameterSpec spec = new GCMParameterSpec(128, ivBytes); // IS HARD CODED 128 DONT EFFING LIKE IT
            config.setIv(spec.getIV());
            return spec;
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            config.setIv(ivBytes);
            return ivSpec;
        }
    }

    public record Message(byte[] sequenceNumber, byte[] data, byte[] integrity) {

        public byte[] getAll() {
            byte[] all = new byte[sequenceNumber.length + data.length + integrity.length];
            System.arraycopy(sequenceNumber, 0, all, 0, sequenceNumber.length);
            System.arraycopy(data, 0, all, sequenceNumber.length, data.length);
            System.arraycopy(integrity, 0, all, sequenceNumber.length + data.length, integrity.length);
            return all;
        }
    }

}
