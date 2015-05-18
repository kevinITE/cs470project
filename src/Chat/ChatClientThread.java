package Chat;

import java.net.*;
import javax.swing.JTextArea;


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
        PackageChatMessage pkg;
        String msg;

        while (!_client.exit) {
            try {
                pkg = (PackageChatMessage) _client.in.readObject();
                if((msg = pkg.verifyAndGetMessage(_client.roomKey)) != null) {
                    consumeMessage(msg + " \n");
                }
            } catch (Exception e) {
            }
        }
    }

    public void consumeMessage(String msg) {
        if (msg != null) {
            _outputArea.append(msg);
        }
    }
}
