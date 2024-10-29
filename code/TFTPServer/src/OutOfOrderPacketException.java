package TFTPServer.src;

/**
 * Exception thrown when a packet is out of order
 */
public class OutOfOrderPacketException extends Exception {
    public OutOfOrderPacketException(String message) {
        super(message);
    }
}
