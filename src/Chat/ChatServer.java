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

    private Map<String, HashMap<Integer, ClientRecord>> _clients;
    private Map<String, SecretKey> _roomKeys;
    private int _clientID = 0;
    private int _port;
    private String _hostName = null;
    private String SERVER_KEYSTORE = "/home/yigit/Chat/ks_server";
    private char[] SERVER_KEYSTORE_PASSWORD = "123456".toCharArray();
    private char[] SERVER_KEY_PASSWORD = "123456".toCharArray();
    private ServerSocket _serverSocket = null;
    private SecureRandom secureRandom;
    private KeyStore serverKeyStore;
    PublicKey CAPublicKey;

    public ChatServer(int port) {

        try {
            _clients = new HashMap<String, HashMap<Integer, ClientRecord>>();
            _serverSocket = null;
            _clientID = -1;
            _port = port;
            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

            FileInputStream inputStream = new FileInputStream(new File(this.SERVER_KEYSTORE));
            serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            serverKeyStore.load(inputStream, this.SERVER_KEYSTORE_PASSWORD);
            CAPublicKey = serverKeyStore.getCertificate("ca").getPublicKey();

        } catch (UnknownHostException e) {

            _hostName = "0.0.0.0";

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String args[]) {

        try {

            int port = 7779;
            ChatServer server = new ChatServer(port);
            server.run();

        } catch (NumberFormatException e) {
            System.out.println("Usage: java ChatServer host portNum");
            e.printStackTrace();

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

            KeyGenerator roomKeyGenerator = KeyGenerator.getInstance("AES");
            roomKeyGenerator.init(128);

            while (true) {

                Socket socket = _serverSocket.accept();

                try {
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                    // generate DH key part
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
                    kpg.initialize(512);
                    KeyPair kp = kpg.generateKeyPair();
                    KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");
                    DHPublicKeySpec DHServerPublicKeySpec = (DHPublicKeySpec) kfactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
                    PublicKey DHServerPublicKey = kp.getPublic();

                    // create key exchange message
                    Certificate serverCert = serverKeyStore.getCertificate("server");
                    PrivateKey RSAPrivateKey = (PrivateKey) serverKeyStore.getKey("server", SERVER_KEY_PASSWORD);
                    PackageServerExchange serverExchange = new PackageServerExchange(serverCert, DHServerPublicKeySpec, DHServerPublicKey, RSAPrivateKey);

                    // send server key exchange
                    out.writeObject(serverExchange);

                    // receive client key exchange
                    PackageClientExchange clientExchange = (PackageClientExchange) in.readObject();

                    // verify
                    if(clientExchange == null || !clientExchange.verify()) {
                        System.out.println("Key exchange failed");
                        break;
                    }
                    clientExchange.getClientCertificate().verify(CAPublicKey);

                    PublicKey DHClientPublicKey = clientExchange.getDHClientPart(RSAPrivateKey, DHServerPublicKeySpec.getP(), DHServerPublicKeySpec.getG());

                    System.out.println("Calculating shared secret");

                    // calculate shared secret
                    KeyAgreement ka = KeyAgreement.getInstance("DH");
                    ka.init(kp.getPrivate());
                    ka.doPhase(DHClientPublicKey, true);
                    SecretKey secretKey = ka.generateSecret("AES");

//                    System.out.println("Key exchange completed: " + Arrays.toString(DHClientPublicKey.getEncoded()));
//                    System.out.println("Key exchange completed: " + Arrays.toString(DHServerPublicKey.getEncoded()));
                    System.out.println("Key exchange completed: " + Arrays.toString(secretKey.getEncoded()));

                    // initialize symmetric ciphers
                    Cipher enCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    Cipher deCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    enCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    deCipher.init(Cipher.DECRYPT_MODE, secretKey);

                    // receive join room request
                    SealedObject joinRoomRequest = (SealedObject) in.readObject();
                    String room = (String) joinRoomRequest.getObject(deCipher);

                    ClientRecord clientRecord = new ClientRecord(socket, secretKey);
                    HashMap<Integer, ClientRecord> roomClients = _clients.get(room);
                    SecretKey roomKey;
                    if(roomClients == null) {
                        HashMap<Integer, ClientRecord> newMap = new HashMap<Integer, ClientRecord>();
                        newMap.put(_clientID++, clientRecord);
                        _clients.put(room, newMap);
                        roomKey = roomKeyGenerator.generateKey();
                        _roomKeys.put(room, roomKey);
                    }
                    else {
                        roomClients.put(_clientID++, clientRecord);
                        roomKey = _roomKeys.get(room);
                    }

                    // send join room reply
                    out.writeObject(new SealedObject(roomKey, enCipher));

                    ChatServerThread thread = new ChatServerThread(this, socket, room);
                    thread.start();
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Client connection failed");
                }
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

    public Map<Integer, ClientRecord> getRoomClientRecords(String room) {
        return _clients.get(room);
    }
}
