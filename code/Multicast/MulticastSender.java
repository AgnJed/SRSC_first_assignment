package Multicast;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Date;

public class MulticastSender {

    public static void main(String[] args) throws Exception {
//        if (args.length != 3) {
//            System.err.println("usage: java MulticastSender  grupo_multicast porto time-interval");
//            System.exit(0);
//        }

        int more = 1; // change if needed, send 20 time a MCAST message
        int port = 7000;
        InetAddress group = InetAddress.getByName("224.0.0.0");
        int timeInterval = 2;
        String msg;

        if (!group.isMulticastAddress()) {
            System.err.println("Multicast address required...");
            System.exit(0);
        }

        SecureMulticastSocket ms = new SecureMulticastSocket(port);
        do {
            String msgsecret = "top secret message, sent on: ";
            String msgdate = new Date().toString();
            msg = msgsecret + msgdate;
            ms.send(new DatagramPacket(msg.getBytes(), msg.length(), group, port));

            try {
                Thread.sleep(1000L * timeInterval);
            } catch (InterruptedException ignored) {
            }

        } while (--more > 0);
        msg = "fim!";
        ms.send(new DatagramPacket(msg.getBytes(), msg.length(), group, port));
        ms.close();

    }
}

