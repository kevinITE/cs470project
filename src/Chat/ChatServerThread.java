package Chat;

import java.util.*;
import java.net.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ChatServerThread extends Thread {

    private Socket socket= null;
    private ChatServer server = null;
    private Map<Integer, ClientRecord> _records = null;

    public ChatServerThread(ChatServer server, Socket socket) {
        super("ChatServerThread");
        this.server = server;
        this.socket = socket;
    }

    public void run() {
        ObjectInputStream in;

        try {
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            // generate DH key part
            KeyPairGenerator DHKeyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
            DHKeyPairGenerator.initialize(512);
            KeyPair DHKeyPair = DHKeyPairGenerator.generateKeyPair();
            KeyFactory DHKeyFactory = KeyFactory.getInstance("DiffieHellman");
            DHPublicKeySpec DHServerPublicKeySpec = DHKeyFactory.getKeySpec(DHKeyPair.getPublic(), DHPublicKeySpec.class);
            PublicKey DHServerPublicKey = DHKeyPair.getPublic();

            // send server key exchange message
            PackageServerExchange serverExchange = new PackageServerExchange(server.certificate, DHServerPublicKeySpec, DHServerPublicKey, server.RSAPrivateKey);
            out.writeObject(serverExchange);

            // receive client key exchange message
            PackageClientExchange clientExchange = (PackageClientExchange) in.readObject();

            // verify client key exchange
            if(clientExchange == null || !clientExchange.verify()) {
                System.out.println("Key exchange failed.");
                socket.close();
                return;
            }
            clientExchange.getClientCertificate().verify(server.CAPublicKey);

            PublicKey DHClientPublicKey = clientExchange.getDHClientPart(server.RSAPrivateKey);

            System.out.println("Client key exchange message verified. Calculating shared secret.");

            // calculate shared secret
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(DHKeyPair.getPrivate());
            ka.doPhase(DHClientPublicKey, true);
            SecretKey sharedKey = ka.generateSecret("AES");

            System.out.println("Key exchange completed: " + Arrays.toString(sharedKey.getEncoded()));

            // initialize symmetric ciphers
            Cipher enCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Cipher deCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            enCipher.init(Cipher.ENCRYPT_MODE, sharedKey);
            deCipher.init(Cipher.DECRYPT_MODE, sharedKey);

            // receive join room request
            SealedObject joinRoomRequest = (SealedObject) in.readObject();
            String room = (String) joinRoomRequest.getObject(deCipher);

            ClientRecord clientRecord = new ClientRecord(socket, sharedKey);
            HashMap<Integer, ClientRecord> roomClients = server.clients.get(room);
            SecretKey roomKey;
            if(roomClients == null) {
                HashMap<Integer, ClientRecord> newMap = new HashMap<Integer, ClientRecord>();
                newMap.put(server.clientID++, clientRecord);
                server.clients.put(room, newMap);
                roomKey = server.roomKeyGenerator.generateKey();
                server.roomKeys.put(room, roomKey);
            }
            else {
                roomClients.put(server.clientID++, clientRecord);
                roomKey = server.roomKeys.get(room);
            }

            // send join room reply
            out.writeObject(new SealedObject(roomKey, enCipher));


        } catch (Exception e) {
            System.out.println("Client connection failed");
            e.printStackTrace();
            return;
        }

        try {
            Object receivedMsg;

            while ((receivedMsg = in.readObject()) != null) {

                for(ClientRecord c : _records.values()) {
                    Socket socket = c.getClientSocket();
                    ObjectOutputStream peerOut = new ObjectOutputStream(socket.getOutputStream());
                    peerOut.writeObject(receivedMsg);
                }

            }

            socket.shutdownInput();
            socket.shutdownOutput();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
