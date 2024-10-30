package StreamingService.hjStreamServer;/*
* hjStreamServer.java 
* Streaming server: emitter of video streams (movies)
* Can send in unicast or multicast IP for client listeners
* that can play in real time the transmitted movies
*/

import TFTPServer.src.SecureMulticastSocket;
import TFTPServer.src.SecureUnicastSocket;

import java.io.*;
import java.net.*;

class hjStreamServer {

	static public void main( String []args ) throws Exception {
//	        if (args.length != 3)
//	        {
//	         System.out.println("Use: hjStramSrver <movie> <ip-multicast-address> <port>");
//	         System.out.println("Ex: hjStreamSrver  <movie> 224.2.2.2 9000");
//	         System.out.println(" or: hjStreamSrver  <movie> <ip-unicast-address> <port>");
//	         System.out.println("Ex: hjStreamSrver  <movie> 127.0.0.1 10000");
//
//
//	         System.exit(-1);
//	         }
      
		int size;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream("\\\\wsl.localhost\\Ubuntu-22.04\\home\\sideghost\\NOVA\\SRSC\\SRSC_first_assignment\\code\\StreamingService\\hjStreamServer\\movies\\monsters.dat") );
		byte[] buff = new byte[65000];
		SecureMulticastSocket s = new SecureMulticastSocket();
		InetSocketAddress addr =
		    new InetSocketAddress("224.2.2.2", 9000);
		DatagramPacket p=new DatagramPacket(buff,buff.length,addr);
		long t0 = System.nanoTime(); // tempo de referencia
		long q0 = 0;

		while ( g.available() > 0 ) {
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			s.send( p );
			//System.out.print( "." );
		}

		System.out.println("\nEND ! packets with frames sent: "+count);
	}

}
