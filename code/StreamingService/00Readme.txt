See the code, compile and try.
You must pass proprly IP addresses (unicast or multicast) in order
to test the operation of the Streaming Server and Proxy.

You must use also a Media Player App (ex., VLC or MPC).
Other Apps able to pay MPEG based streaming could also be used.

Architecture


hjStreamServer >>>>>>>>>>>> hjProxy >>>>>>>>>>>> Media Player App
               udp channel           udp channel

hjStreamServer arguments:
-------------------------
Pass the movie to stream and the IP (Unicast or Multicast) Addess and Port
for which the Server will send the streamed movies.
Movies for this Streaming Service are encoded in a special streaming format
for the sequence of frames, where each frame is encoded in MPEG4.
Th server supports sending sterams in multicast or unicast.
Available movies (files) for testing are in the directory "movies"

Ex: for Multicast streaming:

Syntax (command line)
hjStreamServer <movie> <ip-multicast-address> <udp port>
hjStreamServer monsters.dat 224.2.2.2 9000

Ex: for Unicast streaming:

hjStreamSrver  <movie> <ip-unicast-address> <udp port>
Ex: hjStreamSrver  <movie> 127.0.0.1 10000"

hjUDPProxy arguments:
----------------------

Must input the rquired arguments for the Proxy that wil receive
disseminated movie streams (from the Streaming server) and
delivers the streams to be played by a media player App.

Depending on the arguents used for the StreamServer, the
Proxy must be launched with the corrspondent arguments.

hjUDPproxy <endpoint1> <endpoint2>
<endpoint1>: endpoint for receiving stream
<endpoint2>: endpoint  media player delivery
Format for endpoints is: <ip address>:<udp port>

Ex: 
hjUDPproxy 224.2.2.2:9000  127.0.0.1:8888
(for the proxy to receive  multicasted streams 

To play the movies you can obain from the StreamServer (directly) or
through the proxy (indirectly).

You must know how to configure UDP endpoints for receiving
network streaming, when using IP unicasting or IP multicasting.


