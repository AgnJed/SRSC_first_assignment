package java.service;

import java.io.IOException;
import java.net.InetAddress;

public interface DSTPSocket {

    /**
     * Initializes the DSTP socket with a given address and port.
     *
     * @param address the address to bind the socket to.
     * @param port the port number to bind the socket to.
     * @throws IOException if an I/O error occurs while creating the socket.
     */
    void initialize(InetAddress address, int port) throws IOException;

    /**
     * Sends a message securely using the DSTP protocol.
     *
     * @param message the message to send.
     * @param address the target address to send the message to.
     * @param port the target port number.
     * @throws IOException if an I/O error occurs while sending the message.
     * @throws Exception if a cryptographic or protocol error occurs.
     */
    void send(String message, InetAddress address, int port) throws IOException, Exception;

    /**
     * Receives a message securely using the DSTP protocol.
     *
     * @return the decrypted message received.
     * @throws IOException if an I/O error occurs while receiving the message.
     * @throws Exception if a cryptographic or protocol error occurs.
     */
    String receive() throws IOException, Exception;

    /**
     * Sets the configuration for the DSTP socket based on parameters loaded from a configuration file.
     *
     * @param configPath the path to the configuration file.
     * @throws IOException if an I/O error occurs while loading the configuration.
     * @throws Exception if there is an error in the configuration setup.
     */
    void configure(String configPath) throws IOException, Exception;

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

