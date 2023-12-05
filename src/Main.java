import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.Buffer;
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
                "\nLoad in an RSA key-pair? (1)" +
                "\nGenerate a new key-pair (2)" +
                "\nExit the program (3)");
       boolean exit = false;
       Person currentPerson;

        userChoice = keyboardInput.nextInt();
        switch (userChoice){
            case 1:
                PublicKey publicKey = RSAUtility.loadInPublicKey(keyboardInput);
                PrivateKey privateKey = RSAUtility.loadInPrivateKey(keyboardInput);
                currentPerson = new Person(publicKey,privateKey);

            case 2:
                currentPerson = new Person();
                RSAUtility.writeOutKeys(currentPerson);

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
                    /*
                    * TODO ask the user to import an RSA public key, then recreate the AES secret key key, then decrypt the file.
                    * */
                case 3:
                    //TODO Quit the program
            }


        }
        while (displayOptions);











    }










    }

