import java.net.InetAddress;

public class MulticastReceiver {

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: java MulticastReceiver grupo_multicast porto");
            System.exit(0);
        }

        int port = Integer.parseInt(args[1]);
        InetAddress group = InetAddress.getByName(args[0]);

        if (!group.isMulticastAddress()) {
            System.err.println("Multicast address required...");
            System.exit(0);
        }

        SecureDatagramSocket rs = new SecureDatagramSocket(group, port);
//
//    rs.joinGroup(group);

        String recvmsg;

        do {
            recvmsg = rs.receive();

            System.out.println("Msg recebida: " + recvmsg);
        } while (!recvmsg.equals("fim!"));

        // rs.leave if you want leave from the multicast group ...
        rs.close();

    }
}
