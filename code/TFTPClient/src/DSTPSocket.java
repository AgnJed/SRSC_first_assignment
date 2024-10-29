package TFTPClient.src;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;

public interface DSTPSocket {
    /**
     * Sends a message securely using the DSTP protocol.
     *
     * @param packet the packet to send.
     * @throws IOException if an I/O error occurs while sending the message.
     * @throws Exception   if a cryptographic or protocol error occurs.
     */
    void send(DatagramPacket packet) throws IOException, Exception;

    /**
     * Receives a message securely using the DSTP protocol.
     *
     * @param packet the packet to receive the message into.
     * @throws IOException if an I/O error occurs while receiving the message.
     * @throws Exception   if a cryptographic or protocol error occurs.
     */
    void receive(DatagramPacket packet) throws IOException, Exception;

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

    void joinGroup(InetAddress group) throws IOException;

    void leaveGroup(InetAddress group) throws IOException;

    int getLocalPort();

    void setSoTimeout(int i) throws SocketException;
}

