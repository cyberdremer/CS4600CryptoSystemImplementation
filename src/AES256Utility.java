import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Class that will encapsulate the operations used by the AES algorithm in order to encrypt and decrypt a text file.
 */
public class AES256Utility {

    public static SecretKey generateSecretKeyWithPassword(String password, String salt, int nAesBits) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(),salt.getBytes(), 65536, nAesBits);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        /*
        * TODO Add a function that writes out the salt
        * */
        return secretKey;


    }


    /**
     * @return IvParameterSpec
     */
    public static IvParameterSpec generateIV(){
        byte[] IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        return new IvParameterSpec(IV);
        /*
         * TODO Add a function that writes out the IV
         * */
    }


    public static void encryptFile(){

    }



}
