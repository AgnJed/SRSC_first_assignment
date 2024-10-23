package service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SecureDatagramSocket {

    private DatagramSocket socket;
    private SecretKey encryptionKey;
    private SecretKey integrityKey;
    private Cipher cipher;

    public SecureDatagramSocket(int port) throws Exception {
        socket = new DatagramSocket(port);

        // Initialize encryption key and cipher
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        encryptionKey = keyGen.generateKey();
        cipher = Cipher.getInstance("AES");

        // Initialize integrity key for HMAC
        KeyGenerator keyGenHMAC = KeyGenerator.getInstance("HmacSHA256");
        keyGenHMAC.init(256);
        integrityKey = keyGenHMAC.generateKey();
    }

    public void send(String message, InetAddress address, int port) throws Exception {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // Encrypt message
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] encryptedMessage = cipher.doFinal(messageBytes);

        // Generate HMAC for integrity
        byte[] hmac = generateHMAC(encryptedMessage);

        // Combine encrypted message and HMAC
        byte[] secureMessage = new byte[encryptedMessage.length + hmac.length];
        System.arraycopy(encryptedMessage, 0, secureMessage, 0, encryptedMessage.length);
        System.arraycopy(hmac, 0, secureMessage, encryptedMessage.length, hmac.length);

        DatagramPacket packet = new DatagramPacket(secureMessage, secureMessage.length, address, port);
        socket.send(packet);
    }

    public String receive() throws Exception {
        byte[] buffer = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);

        byte[] receivedData = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());

        // Split received data into encrypted message and HMAC
        byte[] encryptedMessage = Arrays.copyOfRange(receivedData, 0, receivedData.length - 32);
        byte[] receivedHMAC = Arrays.copyOfRange(receivedData, receivedData.length - 32, receivedData.length);

        // Verify integrity
        byte[] calculatedHMAC = generateHMAC(encryptedMessage);
        if (!Arrays.equals(receivedHMAC, calculatedHMAC)) {
            throw new SecurityException("HMAC does not match, message integrity compromised");
        }

        // Decrypt message
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    private byte[] generateHMAC(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(integrityKey);
        return mac.doFinal(data);
    }
}