//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package Chat;

// Java General
import java.security.cert.Certificate;
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.security.auth.x500.*;
//import sun.security.x509.*;

public class ChatServer {

    private Hashtable _clients;
//      private Hashtable _clientsRoomA;
//      private Hashtable _clientsRoomB;
    private int _clientID = 0;
    private int _port;
    private String _hostName = null;
    // Some hints: security related fields.
    private String SERVER_KEYSTORE = "C:\\Users\\Emre\\.keystore";
    private char[] SERVER_KEYSTORE_PASSWORD = "123456".toCharArray();
    private char[] SERVER_KEY_PASSWORD = "123456".toCharArray();
    private ServerSocket _serverSocket = null;
    private SecureRandom secureRandom;
    private KeyStore serverKeyStore;
//    private KeyManagerFactory keyManagerFactory;
//    private TrustManagerFactory trustManagerFactory;
  
    public ChatServer(int port) {

        try {

            _clients = new Hashtable();
            _serverSocket = null;
            _clientID = -1;
            _port = port;
            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

            FileInputStream inputStream = new FileInputStream(new File(this.SERVER_KEYSTORE));
            serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            serverKeyStore.load(inputStream, this.SERVER_KEYSTORE_PASSWORD);

        } catch (UnknownHostException e) {

            _hostName = "0.0.0.0";

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String args[]) {

        try {

            /*if (args.length != 1) {

                //  Might need more arguments if extending for extra credit
                System.out.println("Usage: java ChatServer portNum");
                return;

            } else {*/

                int port = 7777; //Integer.parseInt(args[0]);
                ChatServer server = new ChatServer(port);
                server.run();
            //}

        } catch (NumberFormatException e) {

            System.out.println("Useage: java ChatServer host portNum");
            e.printStackTrace();
            return;

        } catch (Exception e) {

            System.out.println("ChatServer error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /***
     *
     * Your methods for setting up secure connection
     *
     */
    public void run() {

        try {

            _serverSocket = new ServerSocket(_port);
            System.out.println("ChatServer is running on "
                    + _hostName + " port " + _port);

            while (true) {

                Socket socket = _serverSocket.accept();

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
                kpg.initialize(512);
                KeyPair kp = kpg.generateKeyPair();
                KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");

                DHPublicKeySpec kspec = kfactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);

                Certificate cert = serverKeyStore.getCertificate("server");
                PackageServerExchange serverExchange = new PackageServerExchange(cert, kspec, kp.getPrivate());

                if(socket!=null) {
                    ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                    oos.writeObject(serverExchange);
                }

                PackageClientExchange clientExchange = null;
                if(socket!=null) {
                    ObjectInputStream objIn = new ObjectInputStream(socket.getInputStream());
                    clientExchange = (PackageClientExchange) objIn.readObject();
                }

                SecretKey secretKey = null;
                if(clientExchange != null) {
                    KeyAgreement ka = KeyAgreement.getInstance("DH");
                    ka.init(kp.getPrivate());
                    ka.doPhase(clientExchange.getClientCertificate().getPublicKey(), true);
                    secretKey = ka.generateSecret("AES");
                }

                ClientRecord clientRecord = new ClientRecord(socket);
                _clients.put(new Integer(_clientID++), clientRecord);
                ChatServerThread thread = new ChatServerThread(this, socket);
                thread.start();
            }

            //_serverSocket.close();

        } catch (IOException e) {

            System.err.println("Could not listen on port: " + _port);
            System.exit(-1);

        } catch (Exception e) {

            e.printStackTrace();
            System.exit(1);

        }
    }

    public Hashtable getClientRecords() {

        return _clients;
    }
}
