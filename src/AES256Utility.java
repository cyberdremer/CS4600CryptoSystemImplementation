import javax.crypto.*;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
     * Generate an IV that is going to be used for AES encryption
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


    /**
     * Takes in an inputFile and decrypts the file, the outputFile is the file that gets encrypted.
     * @param algorithm The algorithm we want to use to encrypt.
     * @param key The key we are using for encryption.
     * @param IV The initialization vector.
     * @param inputFile
     * @param outputFile
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec IV, File inputFile, File outputFile) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, BadPaddingException {

        Cipher encryptionCipher = Cipher.getInstance(algorithm);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key, IV);
        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);

        byte[] buffer = new byte[64];
        int bytesRead;
        while ( (bytesRead = fis.read(buffer)) != -1){
            byte[] output = encryptionCipher.update(buffer, 0, bytesRead);
            if (output != null){
                fos.write(output);
            }
        }

        byte[] outputBytes = encryptionCipher.doFinal();
        if (outputBytes != null){
            fos.write(outputBytes);
        }

        fis.close();
        fos.close();




    }

    /**
     * Takes in an inputFile and decrypts the file, the outputFile is the file that gets encrypted.
     * @param algorithm The algorithm used for encryption.
     * @param key The key used for encryption.
     * @param IV The initialization vector used for encryption.
     * @param inputStream The input file.
     * @param outputStream The output file.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec IV, File inputStream, File outputStream) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptionCipher = Cipher.getInstance(algorithm);
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, IV);
        FileInputStream fis = new FileInputStream(inputStream);
        FileOutputStream fos = new FileOutputStream(outputStream);

        byte[] buffer = new byte[64];
        int bytesRead;
        while ( (bytesRead = fis.read(buffer)) != -1){
            byte[] output = decryptionCipher.update(buffer, 0, bytesRead);
            if (output != null){
                fos.write(output);
            }
        }

        byte[] outputBytes = decryptionCipher.doFinal();
        if (outputBytes != null){
            fos.write(outputBytes);
        }

        fis.close();
        fos.close();



    }



}
