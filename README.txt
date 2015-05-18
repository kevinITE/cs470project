STUDENT INFO
==============
Yiğit Özen. ID: 21000685
Emre Doğru. ID: 21002482

GitHub URL: https://github.com/ozen/cs470project


HOW TO RUN
============

Compiled class files can be found in out directory.
Development was conducted in Linux environment. Oracle JDK 1.8 and IntelliJ IDEA 14 IDE was used.
Java bytecodes should be run in other environments. But, JDK implementations other than Oracle JDK may cause problems because of the implementation of X509CertificateGenerator.

Make sure java classpath includes all necessary jar and class files. Following commands work in our development environment. You should make any necessary modification in the paths.


Running Certificate Authority:
-------------------------------
java -classpath /usr/lib/jvm/java-8-oracle/jre/lib:/home/yigit/IdeaProjects/cs470project/out/production/cs470project Chat.CertificateAuthority

Running Chat Server:
-------------------------------
java -classpath /usr/lib/jvm/java-8-oracle/jre/lib:/home/yigit/IdeaProjects/cs470project/out/production/cs470project Chat.ChatServer

Running Chat Client:
-------------------------------
java -classpath /usr/lib/jvm/java-8-oracle/jre/lib:/home/yigit/IdeaProjects/cs470project/out/production/cs470project Chat.ChatClient


KEYSTORES
==========

Following key pairs and certificates are created and stored before running the application:
CA has a self-signed certificate. Client and Server have long-term RSA key pairs and corresponding certificates signed using the CA's certificate. Client's keystore has client's key pair, certificate and CA's certificate. Server's keystore has server's key pair, certificate and CA's certificate.

Chat Client and Certificate Authority asks for the path and password of their keystores in their start up GUIs. Chat Server does not have a GUI; the path and password of its keystore can be set using the variables in the beginning of ChatServer source code.

All paths are relative to the Chat package. The keystores we created during the development are in Chat/keystores directory and all passwords (keystores and keys) are set to "123456". Default values of all path and password settings are set for these keystores. Therefore, the application should run without any problems if you do not change the keystores.


CLASSES
==========

We heavily modified the following classes:  

CertificateAuthorityThread
ChatClient
ChatClientThread
ChatServer
ChatServerThread
X509CertificateGenerator

We created following new classes:

PackageRegister
PackageServerExchange
PackageClientExchange
PackageMessage


All communication between CA, server and client are done by using Java object streams and Java serialization. Package<...> classes are for encapsulated objects to be sent over the object streams based on our application protocol.



APPLICATION PROTOCOL
=========================


Registration:
--------------

We don't have a predefined user database. Instead, users can get registered by communicating to the CA. Client sends the username which the user wants to register and the public key of the user's RSA key pair to CA. CA checks if the username was registered. If it was registered, it reject the request. If it was not registered, CA signs a new certificate for the requested public key and return it to client; and it stores the username-certificate pair to remember the username was registered.


Server-Client Key Exchange:
-----------------------------

Our protocol performs Diffie-Hellman (DH) key exchange with RSA encryption and mutual authentication. Server authenticates client and client authenticates server using CA-signed certificates and digital signatures. Therefore, user login process is completed during the key exchange with authenticating the client's certificate.

1. Client connects to the server.

2. Server generates its DH key pair.

3. Server sends PackageServerExchange to client. This package includes:
a) Server's certificate
b) DH parameters and server's DH public key (p, g, g^a mod p) signed with server's RSA private key.

4. Client receives PackageServerExchange. Client verifies the server's certificate is signed by CA. Client also verifies server's DH public key it received has the correct signature using server's RSA public key.

5. Client generates its DH key pair using p and g received from the server.

6. Client sends PackageClientExchange to server. This package includes:
a) Client's certificate
b) PackageServerExchange which client has received, signed by the client's RSA private key.
c) Clients's DH public key (g^b mod p) encrypted with server's RSA public key.


7. Server receives PackageClientExchange. Server verifies the client's certificate is signed by CA. Server also verifies signed PackageServerExchange it received has the correct signature using client's RSA public key. Server decrypts server's DH public key with its RSA private key.

8. Server calculates shared key using its DH private key and client's DH public key. Client calculates shared key using its DH private key and server's DH public key. Finally, key exchange is completed. 

Digital signatures use SHA256 hashing with RSA keys.
Encryption uses RSA algorithm in ECB mode with PKCS1 padding.


Joining to a Room:
----------------------

Room keys are 128-bit AES keys that are generated for a room when the first user joins the room.

Using the shared key decided during the key exchange, an encrypted connection is established between server and client with AES algorithm in CBC mode with PKCS5 padding. 

Client sends the room name the user wants to join to client using the encrypted connection.
Server joins the client to the requested room and sends the room's shared key to client using the encrypted connection.


Messaging:
----------------

Client continuously sends messages to and receives messages from server. It encrypts/decrypts messages using the room key acquired when joining the room. A MAC is attached to each message which is SHA256 hash encrypted with the room key of the message. 
Server sends encrypted message and MAC it receives from a client to all clients in the same room.
