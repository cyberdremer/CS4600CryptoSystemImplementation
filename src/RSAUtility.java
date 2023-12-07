import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class RSAUtility {

    public static void writeOutKeys(Person person, String directory, String username) throws FileNotFoundException {
        File keyFiles = new File(directory);
        String publicKeyOutPath = "";
        String privateKeyOutPath = "";
        String keyFileOutPath = "";
        publicKeyOutPath  = keyFiles.getAbsolutePath();
        privateKeyOutPath = keyFiles.getAbsolutePath();
        File publicKeyFile = new File(publicKeyOutPath + "/" + username + "public.key");
        File privateKeyFile = new File(privateKeyOutPath + "/" + username + "private.key");



        FileOutputStream publicKeyFileStream, privateKeyFileStream;
        try {
            publicKeyFileStream = new FileOutputStream(publicKeyFile);
            publicKeyFileStream.write(Base64.getEncoder().encode(person.returnPublicKey().getEncoded()));


        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            privateKeyFileStream = new FileOutputStream(privateKeyFile);
            privateKeyFileStream.write(Base64.getEncoder().encode(person.returnPrivateKey().getEncoded()));


        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }








    }

    /**
     * \Takes in user input to load in a file containing the public key for the RSA encryption scheme.
     * @param directory The directory of the file.
     * @return PublicKey object
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */


    public static PublicKey loadInPublicKey(String directory) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            directory = directory.replaceAll("\"", "");
            FileInputStream fis = new FileInputStream(directory);
            byte[] publicKeyBytes = new byte[fis.available()];
            fis.read(publicKeyBytes);

            byte[] decodedPubBytes = Base64.getDecoder().decode(publicKeyBytes);
            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(decodedPubBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
            PublicKey pk = keyFactory.generatePublic(encodedKeySpec);
            return pk;

        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Takes in user input to   load in a file containing the private key for the RSA encryption scheme.
     * @param directory The directory of the
     * @return PrivateKey object
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */


    public static PrivateKey loadInPrivateKey(String directory) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            directory = directory.replaceAll("\"", "");
            FileInputStream fis = new FileInputStream(directory);
            byte[] publicKeyBytes = new byte[fis.available()];
            fis.read(publicKeyBytes);

            byte[] decodedPubBytes = Base64.getDecoder().decode(publicKeyBytes);
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(decodedPubBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
            PrivateKey pk = keyFactory.generatePrivate(encodedKeySpec);
            return pk;

        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
