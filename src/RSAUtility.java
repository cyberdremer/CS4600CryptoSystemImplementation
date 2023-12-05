import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAUtility {

    /** Encrypts an entire file using the RSA Algorithm.
     * @param pk The public key used for encryption.
     * @param filePath The path of the file to be encrypted.
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void encryptFile(PublicKey pk, Path filePath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] fileBytes = Files.readAllBytes(filePath);
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, pk);
        byte[] encryptedFileBytes = encryptCipher.doFinal(fileBytes);
        try(FileOutputStream fos = new FileOutputStream(filePath.toFile())){
            fos.write(encryptedFileBytes);
        }
    }

    /** Decrypts an entire file using the RSA Algorithm
     * @param pk The private key used for decryption.
     * @param filePath The path of the file to be encrypted.
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void decryptFile(PrivateKey pk, Path filePath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] encryptedFileBytes = Files.readAllBytes(filePath);
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, pk);
        byte[] decryptedFileBytes = decryptCipher.doFinal(encryptedFileBytes);
        try(FileOutputStream fos = new FileOutputStream(filePath.toFile())){
            fos.write(decryptedFileBytes);
        }

    }
}
