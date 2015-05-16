package Chat;

import java.security.PublicKey;

public class PackageRegister implements java.io.Serializable {
    public String username;
    public PublicKey publicKey;

    public PackageRegister(String username, PublicKey publicKey) {
        this.username = username;
        this.publicKey = publicKey;
    }
}
