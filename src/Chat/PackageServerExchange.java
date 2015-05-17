package Chat;

import javax.crypto.spec.DHPublicKeySpec;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;

/**
 * Server creates an instance of this class and sends it to the client in the first step of key exchange.
 * Client uses 'verify' method to verify the signature with server's certificate (public key)
 * Client uses 'getDHServerPart' method to retrieve server's DH part to calculate shared secret.
 * Client uses 'getServerCertificate' to retrieve server's certificate.
 */
public class PackageServerExchange implements Serializable {
    /**
     * Server's certificate.
     */
    private Certificate serverCert;

    /**
     * Server's Diffie-Hellman key part, signed with server's long-term RSA private key paired with its certificate.
     */
    private SignedObject signedDHServerPart;

    public PackageServerExchange(Certificate serverCert, DHPublicKeySpec DHServerPublicKey, PrivateKey signingKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        this.serverCert = serverCert;
        Signature signingEngine = Signature.getInstance(signingKey.getAlgorithm());
        SerializableDHPublicKey unsignedDHServerPart = new SerializableDHPublicKey(DHServerPublicKey);
        this.signedDHServerPart = new SignedObject(unsignedDHServerPart, signingKey, signingEngine);

    }

    public DHPublicKeySpec getDHServerPart() throws IOException, ClassNotFoundException {
        SerializableDHPublicKey serializableKey =  (SerializableDHPublicKey) this.signedDHServerPart.getObject();
        return serializableKey.getDHPublicKeySpec();
    }

    public boolean verify() {
        try {
            PublicKey verificationKey = this.serverCert.getPublicKey();
            Signature signingEngine = Signature.getInstance(verificationKey.getAlgorithm());
            return this.signedDHServerPart.verify(verificationKey, signingEngine);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    public Certificate getServerCertificate() {
        return this.serverCert;
    }

    static class SerializableDHPublicKey implements Serializable {
        public BigInteger G;
        public BigInteger P;
        public BigInteger Y;

        public SerializableDHPublicKey(DHPublicKeySpec publicKeySpec) {
            this.G = publicKeySpec.getG();
            this.P = publicKeySpec.getP();
            this.Y = publicKeySpec.getY();
        }

        public DHPublicKeySpec getDHPublicKeySpec() {
            return new DHPublicKeySpec(this.Y, this.P, this.G);
        }
    }
}
