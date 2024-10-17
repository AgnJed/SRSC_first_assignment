## Tasks
> Trying to follow an agile work metodology, we will try to devide the work in taks and assign them to one and other using story points or other metric to access work dificulty and time consumed.

### Task 1 - Basic software design with diagrams

By analising the requirements of the work assigment the sofware design will be as follows: 

- Console read: for console comands and handling
- cryptoconfig.txt: for read cypher configs // TODO Access if this will be the used way to use the app instead of console
- API interface: if enogth time create a interface and then implement it as the solution. aka abstraction

- Questions: Application will work as a knownd intreceptor? What annalogy can be applied to the to be developed application

- Does the console read configuration from the file cryptoconfig.txt?

### Task 2 - Create a secure communication layer over UDP using the Datagram Sockets

- key initialization: load encryption and MAC keys from the class that is supposed to read files from cryptoconfig.txt

- send() method: encrypt the message, add a MAC to the encypted message, add a sequence number to the packet to handle order control, send the UDP packet

- receive() method: receive the packet, check the sequence number, verify the MAC, decrypt the message and return it to the user