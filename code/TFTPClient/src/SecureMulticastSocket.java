package TFTPClient.src;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.SocketAddress;

public class SecureMulticastSocket extends MulticastSocket {
    private SecureSocket secureSocket;

    public SecureMulticastSocket() throws IOException {
        super();
        initializeBaseDSTP();
    }

    public SecureMulticastSocket(int port) throws IOException {
        super(port);
        initializeBaseDSTP();
    }

    public SecureMulticastSocket(SocketAddress bindaddr) throws IOException {
        super(bindaddr);
        initializeBaseDSTP();
    }

    private void initializeBaseDSTP() throws IOException {
        try {
            secureSocket = new SecureSocket();
        } catch (Exception e) {
            throw new IOException("Failed to initialize SecureMulticastSocket: " + e.getMessage());
        }
    }

    @Override
    public void joinGroup(InetAddress group) throws IOException {
        super.joinGroup(group);
    }

    @Override
    public void leaveGroup(InetAddress group) throws IOException {
        super.leaveGroup(group);
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
