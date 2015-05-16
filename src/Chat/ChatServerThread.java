//
// ChatServerThread.java
// created 02/18/03 by Ting Zhang
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package Chat;

// Java
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;


// Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class ChatServerThread extends Thread {


    private Socket _socket = null;
    private ChatServer _server = null;
    private Hashtable _records = null;

    public ChatServerThread(ChatServer server, Socket socket) {

        super("ChatServerThread");
        _server = server;
        _socket = socket;
        _records = server.getClientRecords();
    }

    public void run() {

        try {

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                    _socket.getInputStream()));

            String receivedMsg;

            while ((receivedMsg = in.readLine()) != null) {

                Enumeration theClients = _records.elements();

                while (theClients.hasMoreElements()) {

                    ClientRecord c = (ClientRecord) theClients.nextElement();


                    Socket socket = c.getClientSocket();

                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    out.println(receivedMsg);

                }
            }

            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (IOException e) {

            e.printStackTrace();
        }

    }
}
