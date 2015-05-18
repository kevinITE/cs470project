package Chat;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class PackageChatMessage implements Serializable {
    private SealedObject sealedMessage;
    private byte[] MAC;

    public PackageChatMessage(String msg, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        // encrypt message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("yigitozenemredogru".getBytes(), 0, 16));
        this.sealedMessage = new SealedObject(msg, cipher);

        // calculate MAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        this.MAC = mac.doFinal(msg.getBytes(Charset.forName("UTF-8")));
    }

    public String verifyAndGetMessage(SecretKey key) {
        try {
            // decrypt message
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec("yigitozenemredogru".getBytes(), 0, 16));
            String msg = (String) this.sealedMessage.getObject(cipher);

            // recalculate and verify MAC
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] MAC2 = mac.doFinal(msg.getBytes(Charset.forName("UTF-8")));
            if(Arrays.equals(this.MAC, MAC2)) {
                return msg;
            }
            else {
                System.out.println("MAC verification failed");
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
