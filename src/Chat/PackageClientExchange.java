package Chat;

import javax.crypto.*;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import java.security.cert.Certificate;

/**
 * Client creates an instance of this class and sends it to the server in the seconds step of key exchange.
 * Server uses 'verify' method to verify the signature with client's certificate (public key)
 * Server uses 'getDHClientPart' method to retrieve client's DH part to calculate shared secret.
 * Server uses 'getClientCertificate' to retrieve client's certificate.
 */
public class PackageClientExchange implements Serializable {
    /**
     * Client's certificate
     */
    private Certificate clientCert;

    /**
     * Package retrieved from the server in the first step of key exhange, signed with
     * client's long-term RSA private key paired with its certificate.
     */
    private SignedObject signedVerification;

    /**
     * Client's Diffie-Hellman key part, encrypted with the server's RSA public key in its certificate.
     */
    private SealedObject sealedDHClientPart;


    public PackageClientExchange(Certificate clientCert, Certificate serverCert, DHPublicKeySpec DHClientPublicKey,
                                 PrivateKey signingKey, PackageServerExchange previousPackage) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException {
        this.clientCert = clientCert;

        Signature signingEngine = Signature.getInstance(signingKey.getAlgorithm());
        this.signedVerification = new SignedObject(previousPackage, signingKey, signingEngine);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverCert);
        PackageServerExchange.SerializableDHPublicKey plainDHClientPart = new PackageServerExchange.SerializableDHPublicKey(DHClientPublicKey);
        this.sealedDHClientPart = new SealedObject(plainDHClientPart, cipher);
    }

    public DHPublicKeySpec getDHClientPart(PrivateKey privateKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, ClassNotFoundException, BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        PackageServerExchange.SerializableDHPublicKey serializableDHClientPart = (PackageServerExchange.SerializableDHPublicKey) this.sealedDHClientPart.getObject(cipher);
        return serializableDHClientPart.getDHPublicKeySpec();
    }

    public boolean verify() {
        try {
            PublicKey verificationKey = this.clientCert.getPublicKey();
            Signature signingEngine = Signature.getInstance(verificationKey.getAlgorithm());
            return this.signedVerification.verify(verificationKey, signingEngine);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    public Certificate getClientCertificate() {
        return this.clientCert;
    }
}
