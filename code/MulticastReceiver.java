import java.net.DatagramPacket;
import java.net.InetAddress;

public class MulticastReceiver {

    public static void main(String[] args) throws Exception {
//        if (args.length != 2) {
//            System.err.println("usage: java MulticastReceiver grupo_multicast porto");
//            System.exit(0);
//        }

        int port = 7000;
        InetAddress group = InetAddress.getByName("224.0.0.0");

        if (!group.isMulticastAddress()) {
            System.err.println("Multicast address required...");
            System.exit(0);
        }

        SecureDatagramSocket rs = new SecureDatagramSocket(port);
        rs.joinGroup(group);
        DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
        String recvmsg;

        do {

            p.setLength(65536); // resize with max size
            rs.receive(p);
            recvmsg = new String(p.getData(), 0, p.getLength());

            System.out.println("Msg recebida: " + recvmsg);
        } while (!recvmsg.equals("fim!"));

        // rs.leave if you want leave from the multicast group ...
        rs.close();

    }
}
