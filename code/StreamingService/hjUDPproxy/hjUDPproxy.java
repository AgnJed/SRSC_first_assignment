package StreamingService.hjUDPproxy;/* hjUDPproxy, for use in 2024
 */

import TFTPServer.src.SecureMulticastSocket;
import TFTPServer.src.SecureUnicastSocket;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
//if (args.length != 2)
//        {
//        System.out.println("Use: hjUDPproxy <endpoint1> <endpoint2>");
//        System.out.println("<endpoint1>: endpoint for receiving stream");
//        System.out.println("<endpoint2>: endpoint of media player");
//
//	System.out.println("Ex: hjUDPproxy 224.2.2.2:9000 127.0.0.1:8888");
//	System.out.println("Ex: hjUDPproxy 127.0.0.1:10000 127.0.0.1:8888");
//	System.exit(0);
//	}
	
	String remote="224.2.2.2:9000"; // receive mediastream from this rmote endpoint
	String destinations="127.0.0.1:8888"; //resend mediastream to this destination endpoint
	    

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

        // Manage this according to your required setup, namely
	// if you want to use unicast or multicast channels

        // If listen a remote unicast server try the remote config
        // uncomment the following line
	
	 SecureMulticastSocket inSocket = new SecureMulticastSocket(inSocketAddress);

	// If listen a remote multicast server using IP Multicasting
        // addressing (remember IP Multicast Range) and port 
	// uncomment the following two lines

	//	MulticastSocket ms = new MulticastSocket(9999);
	//        ms.joinGroup(InetAddress.getByName("239.9.9.9"));

	int countframes=0;
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];
        while (true) {

            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
	    // If listen a remote unicast server
	    // uncomment the following line

	    inSocket.receive(inPacket);  // if remote is unicast

	    // If listen a remote multcast server
	    // uncomment the following line

            //ms.receive(inPacket);          // if remote is multicast

	    // Just for debug... 
            //countframes++;
            //System.out.println(":"+countframes);           // debug	    
            //System.out.print(":");           // debug
            for (SocketAddress outSocketAddress : outSocketAddressSet) 
		{
                outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
