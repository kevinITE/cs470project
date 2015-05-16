package Chat;

import java.security.PublicKey;

public class CertRequest implements java.io.Serializable {
    public String username;
    public String password;
    public PublicKey publicKey;

    public CertRequest(String username, String password, PublicKey publicKey) {
        this.username = username;
        this.password = password;
        this.publicKey = publicKey;
    }
}
