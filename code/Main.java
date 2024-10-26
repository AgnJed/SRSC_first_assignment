import javax.crypto.NoSuchPaddingException;
import java.IO.FileAccess;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.service.SecureDatagramSocket;

public class Main {
    private final FileAccess fileAccess = new FileAccess();

    public static void main(String[] args) {
        System.out.println("Hello, world!");
    }

    /**
     * TODO: Implement this method and change signature
     * Decrypts the given message using the given key...
     */
    public static String decrypt(String message, String key) {

        return message + key;
    }

    static DatagramSocket createSocket(String address, int port) throws SocketException, UnknownHostException {
        DatagramSocket socket = new DatagramSocket();
        socket.connect(InetAddress.getByName(address), port);
        return socket;
    }

    static SecureDatagramSocket createSecureSocket(String address, int port) throws Exception {

        return new java.service.SecureDatagramSocket(port);
    }

    static void readConfigFile(String path) {
        // Read config file and set up the socket
    }

    static void writeConfigFile(String path) {
        // Write config file with the socket information
    }

    /**
     * TODO: Implement this method and change signature
     * Encrypts the given message using the given key...
     */
    public String encrypt(String message) throws NoSuchPaddingException, NoSuchAlgorithmException {

        return message;
    }
}
