//  ClientRecord.java
package Chat;


import java.io.ObjectOutputStream;
import java.net.*;
import javax.crypto.*;

public class ClientRecord {

    private Socket _socket = null;
    private SecretKey _secretKey = null;
    private ObjectOutputStream outputStream = null;

    public ClientRecord(Socket socket, SecretKey secretKey, ObjectOutputStream outputStream) {
        _socket = socket;
        _secretKey = secretKey;
        this.outputStream = outputStream;
    }

    public Socket getClientSocket() {
        return _socket;
    }

    public SecretKey getSecretKey() {
        return _secretKey;
    }

    public ObjectOutputStream getOutputStream() {
        return outputStream;
    }
}
