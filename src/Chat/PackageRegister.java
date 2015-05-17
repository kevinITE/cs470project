package Chat;

import java.io.Serializable;
import java.security.PublicKey;

public class PackageRegister implements Serializable {
    public String username;
    public PublicKey publicKey;

    public PackageRegister(String username, PublicKey publicKey) {
        this.username = username;
        this.publicKey = publicKey;
    }
}
