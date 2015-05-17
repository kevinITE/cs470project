package Chat;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

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
    private byte[] encryptedDHClientPart;


    public PackageClientExchange(Certificate clientCert, Certificate serverCert, PublicKey DHClientPublicKey,
                                 PrivateKey signingKey, PackageServerExchange previousPackage) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        this.clientCert = clientCert;

        Signature signingEngine = Signature.getInstance("SHA256withRSA");
        this.signedVerification = new SignedObject(previousPackage, signingKey, signingEngine);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverCert);
        this.encryptedDHClientPart = cipher.doFinal(DHClientPublicKey.getEncoded());
    }

    public PublicKey getDHClientPart(PrivateKey privateKey, BigInteger p, BigInteger g) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, ClassNotFoundException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        KeyFactory keyFac = KeyFactory.getInstance("DH");
        byte[] barray = cipher.doFinal(this.encryptedDHClientPart);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(barray);
        return keyFac.generatePublic(x509KeySpec);
    }

    public boolean verify() {
        try {
            PublicKey verificationKey = this.clientCert.getPublicKey();
            Signature signingEngine = Signature.getInstance("SHA256withRSA");
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
