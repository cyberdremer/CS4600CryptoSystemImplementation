import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

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

    public static void writeOutKeys(Person person) throws FileNotFoundException {
        try(FileOutputStream fos = new FileOutputStream("public.key")){
            fos.write(person.returnPublicKey().getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try(FileOutputStream fos = new FileOutputStream("private.key")){
            fos.write(person.returnPrivateKey().getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * \Takes in user input to load in a file containing the public key for the RSA encryption scheme.
     * @param keyboardInput
     * @return PublicKey object
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */


    public static PublicKey loadInPublicKey(Scanner keyboardInput) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File keyFile;
        byte[] publicKeyBytes;
        String keyFileDirectory;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        System.out.println("Enter the file directory of the key file");
        keyFileDirectory = keyboardInput.nextLine();
        keyFile = new File(keyFileDirectory);
        if (keyFile.isFile()) {
            publicKeyBytes = Files.readAllBytes(keyFile.toPath());
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return publicKey;



        } else {
            throw new FileNotFoundException();

        }
    }

    /**
     * Takes in user input to load in a file containing the private key for the RSA encryption scheme.
     * @param keyboardInput Scanner object
     * @return PrivateKey object
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */


    public static PrivateKey loadInPrivateKey(Scanner keyboardInput) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File keyFile;
        byte[] privateKeyBytes;
        String keyFileDirectory;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        System.out.println("Enter the file directory of the key file");
        keyFileDirectory = keyboardInput.nextLine();
        keyFile = new File(keyFileDirectory);
        if (keyFile.isFile()) {
            privateKeyBytes = Files.readAllBytes(keyFile.toPath());
            EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            return privateKey;


        } else {
            throw new FileNotFoundException();

        }
    }
}
