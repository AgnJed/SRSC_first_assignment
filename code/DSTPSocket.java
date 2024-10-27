import java.io.IOException;
import java.net.InetAddress;

public interface DSTPSocket {
    /**
     * Sends a message securely using the DSTP protocol.
     *
     * @param message the message to send.
     * @param address the target address to send the message to.
     * @param port the target port number.
     * @throws IOException if an I/O error occurs while sending the message.
     * @throws Exception if a cryptographic or protocol error occurs.
     */
    void send(byte[] message, InetAddress address, int port) throws IOException, Exception;

    /**
     * Receives a message securely using the DSTP protocol.
     *
     * @return the decrypted message received.
     * @throws IOException if an I/O error occurs while receiving the message.
     * @throws Exception if a cryptographic or protocol error occurs.
     */
    String receive() throws IOException, Exception;

    /**
     * Closes the DSTP socket, releasing any resources held by the socket.
     *
     * @throws IOException if an I/O error occurs while closing the socket.
     */
    void close() throws IOException;

    /**
     * Gets the current sequence number of the last sent packet.
     * Useful for tracking and managing packet ordering.
     *
     * @return the current sequence number.
     */
    int getCurrentSequenceNumber();
}

