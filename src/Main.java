import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Scanner keyboardInput = new Scanner(System.in);
        int userChoice;
        System.out.println("What operation would you like to do?" +
                "\nLoad in a key-pair? (1)" +
                "\nGenerate a new key-pair (2)" +
                "\nExit the program (3)");
       boolean exit = false;
       Person currentPerson;

        userChoice = keyboardInput.nextInt();
        switch (userChoice){
            case 1:
                PublicKey publicKey = loadInPublicKey(keyboardInput);
                PrivateKey privateKey = loadInPrivateKey(keyboardInput);
                currentPerson = new Person(publicKey,privateKey);

            case 2:
                currentPerson = new Person();
                writeOutKeys(currentPerson);

            default:
                exit = true;
                break;
        }

        boolean displayOptions = true;
        do {
            System.out.println("What operation would you like to do?" +
                    "\nEncrypt a file? (1)" +
                    "\nDecrypt a file (2)" +
                    "\nExit the program (3)");
            int getChoice;
            getChoice = keyboardInput.nextInt();
            switch (getChoice){
                case 1:
                    //TODO function that uses AES 128 to encrypt a file
                case 2:
                    //TODO function that decrypts the AES key, and subsequently the FILE
                case 3:
                    //TODO Quit the program
            }


        }
        while (displayOptions);











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
        byte[] publicKeyBytes;
        String keyFileDirectory;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        System.out.println("Enter the file directory of the key file");
        keyFileDirectory = keyboardInput.nextLine();
        keyFile = new File(keyFileDirectory);
        if (keyFile.isFile()) {
            publicKeyBytes = Files.readAllBytes(keyFile.toPath());
            EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            return privateKey;


        } else {
            throw new FileNotFoundException();

        }
    }





    }

