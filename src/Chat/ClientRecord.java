//  ClientRecord.java
package Chat;


import java.net.*;
import javax.crypto.*;
public class ClientRecord {

    private Socket _socket = null;
    private SecretKey _secretKey = null;

    public ClientRecord(Socket socket, SecretKey secretKey) {
        _socket = socket;
        _secretKey = secretKey;
    }

    public Socket getClientSocket() {
        return _socket;
    }

    public SecretKey getSecretKey() {
        return _secretKey;
    }
}
