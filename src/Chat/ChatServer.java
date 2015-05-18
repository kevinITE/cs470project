//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package Chat;

// Java General
import java.util.*;

// socket
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;
import javax.crypto.*;
import java.security.cert.Certificate;

public class ChatServer {

    private int _port;
    private String _hostName = null;
    private ServerSocket _serverSocket = null;
    int clientID = 0;
    Map<String, HashMap<Integer, ClientRecord>> clients;
    Map<String, SecretKey> roomKeys;
    String SERVER_KEYSTORE = "keystores/ks_server";
    char[] SERVER_KEYSTORE_PASSWORD = "123456".toCharArray();
    char[] SERVER_KEY_PASSWORD = "123456".toCharArray();
    KeyStore keyStore;
    PublicKey CAPublicKey;
    KeyGenerator roomKeyGenerator;
    Certificate certificate;
    PrivateKey RSAPrivateKey;

    public ChatServer(int port) {
        try {
            clients = new HashMap<String, HashMap<Integer, ClientRecord>>();
            roomKeys = new HashMap<String, SecretKey>();
            _serverSocket = null;
            clientID = -1;
            _port = port;
            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

            // load server keystore
            FileInputStream inputStream = new FileInputStream(new File(getClass().getResource(SERVER_KEYSTORE).getPath()));
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inputStream, this.SERVER_KEYSTORE_PASSWORD);
            CAPublicKey = keyStore.getCertificate("ca").getPublicKey();

            roomKeyGenerator = KeyGenerator.getInstance("AES");
            roomKeyGenerator.init(128);

            certificate = keyStore.getCertificate("server");
            RSAPrivateKey = (PrivateKey) keyStore.getKey("server", SERVER_KEY_PASSWORD);

        } catch (UnknownHostException e) {
            _hostName = "0.0.0.0";

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String args[]) {

        try {
            int port = 7777;
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

    public void run() {
        try {
            _serverSocket = new ServerSocket(_port);
            System.out.println("ChatServer is running on "
                    + _hostName + " port " + _port);

            while (true) {
                Socket socket = _serverSocket.accept();
                ChatServerThread thread = new ChatServerThread(this, socket);
                thread.start();
            }

        } catch (IOException e) {
            System.err.println("Could not listen on port: " + _port);
            System.exit(-1);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

}
