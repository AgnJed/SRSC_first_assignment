package Multicast;

import java.io.IOException;
import java.net.*;

public class SecureUnicastSocket extends DatagramSocket {
    private SecureSocket secureSocket;

    public SecureUnicastSocket() throws SocketException {
        super();
        initializeBaseDSTP();
    }

    public SecureUnicastSocket(int port) throws SocketException {
        super(port);
        initializeBaseDSTP();
    }

    public SecureUnicastSocket(SocketAddress bindaddr) throws SocketException {
        super(bindaddr);
        initializeBaseDSTP();
    }

    private void initializeBaseDSTP() throws SocketException {
        try {
            secureSocket = new SecureSocket();
        } catch (Exception e) {
            throw new SocketException("Failed to initialize SecureUnicastSocket: " + e.getMessage());
        }
    }

    @Override
    public void send(DatagramPacket p) throws IOException {
        secureSocket.processSend(p);
        super.send(p);
    }

    @Override
    public void receive(DatagramPacket p) throws IOException {
        super.receive(p);
        secureSocket.processReceive(p);
    }
}
