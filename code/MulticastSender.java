import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.util.Date;

public class MulticastSender {

    public static void main(String[] args) throws Exception {
//        if (args.length != 3) {
//            System.err.println("usage: java MulticastSender  grupo_multicast porto time-interval");
//            System.exit(0);
//        }

        int more = 20; // change if needed, send 20 time a MCAST message
        int port = 7000;
        InetAddress group = InetAddress.getByName("127.0.0.1");
        int timeInterval = 2;
        String msg;
//
//        if (!group.isMulticastAddress()) {
//            System.err.println("Multicast address required...");
//            System.exit(0);
//        }

        DSTPSocket ms = new SecureDatagramSocket(group, port);
        do {
            String msgsecret = "topcsecret message, sent on: ";
            String msgdate = new Date().toString();
            msg = msgsecret + msgdate;
            ms.send(msg.getBytes(), group, port);

            try {
                Thread.sleep(1000L * timeInterval);
            } catch (InterruptedException ignored) {
            }

        } while (--more > 0);
        msg = "fim!";
        ms.send(msg.getBytes(), group, port);
        ms.close();

    }
}

