/**
 *  Created 2/16/2003 by Ting Zhang 
 *  Part of implementation of the ChatClient to receive
 *  all the messages posted to the chat room.
 */
package Chat;

// socket
import java.net.*;
import java.io.*;

//  Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class ChatClientThread extends Thread {

    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;

    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        _client = client;
        _socket = client.getSocket();
        _outputArea = client.getOutputArea();
    }

    public void run() {

        try {

            PackageChatMessage pkg;

            while ((pkg = (PackageChatMessage) _client.in.readObject()) != null) {
                String msg = pkg.getMessage(_client.roomKey);
                consumeMessage(msg + " \n");
            }

            _socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }

    public void consumeMessage(String msg) {

        if (msg != null) {
            _outputArea.append(msg);
        }

    }
}
