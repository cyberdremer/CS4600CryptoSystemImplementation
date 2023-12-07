import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Scanner keyboardInput = new Scanner(System.in);
        int userChoice;
        System.out.println("*****************************");
        System.out.println("Crypto-system Program");
        System.out.println("*****************************");
        System.out.println("What operation would you like to do?" +
                "\nLoad in an RSA key-pair? (1)" +
                "\nGenerate a new key-pair (2)" +
                "\nExit the program (3)");
       boolean exit = false;
        boolean displayOptions = true;
       Person currentPerson;
        String directory;
        userChoice = keyboardInput.nextInt();
        switch (userChoice){
            case 1:
                System.out.println("******************************************");
                System.out.println("Loading in RSA-key pair file.");
                System.out.println("******************************************");

                /*
                * Get the directory of the public key and loads it in.
                * */

                System.out.println("Enter the directory where the public key is located: ");
                directory = keyboardInput.next();
                directory = directory.replaceAll("\"", "");
                PublicKey publicKey = RSAUtility.loadInPublicKey(directory);
                /*
                * Get the directory of the private key and load it in.
                * */


                System.out.println("Enter the directory where the private key is located: ");
                directory = keyboardInput.next();
                directory = directory.replaceAll("\"", "");
                PrivateKey privateKey = RSAUtility.loadInPrivateKey(directory);
                currentPerson = new Person(publicKey,privateKey);
                System.out.println("Key pair's loaded in successfully!\n");

                break;


            case 2:
                System.out.println("******************************************");
                System.out.println("Generating RSA key-pairs ");
                System.out.println("******************************************");
                String name;
                currentPerson = new Person();
                System.out.println("Enter the directory where you want to store the key pairs: ");
                directory = keyboardInput.next();
                System.out.println("\nEnter your name: ");
                name = keyboardInput.next();
                System.out.println("Writing out key-pair to file.....");
                //Write out keys to the given directory, pre-append the name to the type of file it is.
                RSAUtility.writeOutKeys(currentPerson, directory, name);
                System.out.println("Key pair's written out successfully!\n");
                break;

            default:
                currentPerson = new Person();
                displayOptions = false;
                break;
        }


        do {
            System.out.println("What operation would you like to do?" +
                    "\nEncrypt a file? (1)" +
                    "\nDecrypt a file (2)" +
                    "\nExit the program (3)");
            int getChoice;
            getChoice = keyboardInput.nextInt();
            switch (getChoice){
                case 1:
                    System.out.println("******************************************");
                    System.out.println("Encrypting file menu");
                    System.out.println("******************************************");

                    /*TODO maybe allow the user to write in whatever they want, and allow encryption like that, it seems a lot easier to deal with...
                    * This is the case where we will encrypt a file ending in .txt
                    * */
                    String message, fileOfEncryptedText;
                    String pubKeyDirectory, fileDirectory;
                    System.out.println("Enter the directory of the other parties public key pair: ");
                    pubKeyDirectory = keyboardInput.next();
                    /*
                    * Load in the public key from the other party
                    *
                    * */
                    PublicKey otherPartyPk = RSAUtility.loadInPublicKey(pubKeyDirectory);
                    currentPerson.setOtherPersonPubKey(otherPartyPk);
                    keyboardInput.nextLine();

                    System.out.println("Enter the string you would like to encrypt and save in a file: ");
                    message = keyboardInput.nextLine();
                    System.out.println("Enter the name you desire for the file: ");

                    fileOfEncryptedText = keyboardInput.next();
                    String IVFileName = fileOfEncryptedText;
                    fileOfEncryptedText = fileOfEncryptedText + "encrypted"+ ".txt";
                    keyboardInput.nextLine();
                    IvParameterSpec encryptIV = AES256Utility.generateIV();
                    byte[] IVBytes = encryptIV.getIV();

                    System.out.println("Enter the directory of the location where you want to place the file: ");
                    String specifiedDirectory = keyboardInput.next();
                    keyboardInput.nextLine();



                    /*
                    * Generate an IV for the AES encryption scheme
                    * */


                    SecretKey AESEncryptKey =  AES256Utility.generateAESKey(256);
                    /*
                    * Perform AES encryption using the generated IV.
                    * */
                    Cipher AESCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    AESCipher.init(Cipher.ENCRYPT_MODE, AESEncryptKey, encryptIV);
                    byte[] encryptedMessage = AESCipher.doFinal(message.getBytes());

                    /*
                    * Write out the IV for future decryption. This is okay to keep in plaintext.
                    * */
                    AES256Utility.writeOutIV(IVBytes, IVFileName, specifiedDirectory);


                    /*
                    * Encrypt the AES key using the public key of the receiver.
                    * */

                    Cipher RSAEncryptCIpher = Cipher.getInstance("RSA");
                    RSAEncryptCIpher.init(Cipher.ENCRYPT_MODE, currentPerson.getOtherPersonPubKey());
                    byte[] encryptedKey = RSAEncryptCIpher.doFinal(AESEncryptKey.getEncoded());


                    /*
                    * Create a MAC for the user to verify the authenticity of the file.
                    * */

                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(AESEncryptKey);
                    byte[] macBytes = mac.doFinal(message.getBytes());
                    writeEncryptedBitsToFile(specifiedDirectory, fileOfEncryptedText, encryptedMessage, encryptedKey, macBytes);
                    System.out.println("Encrypted successful, returning to the main menu!\n");
                    break;




                case 2:
                    System.out.println("******************************************");
                    System.out.println("Decrypting file menu");
                    System.out.println("******************************************");
                    /*
                    * TODO Seriously buggy, will try and fix this week.
                    * */
                    String IVKeyPath;
                    byte[] encryptedFileMessage;
                    byte[] encryptedAESKey;
                    byte[] encryptedMac;
                    /*
                    * Read in the filepath of the IV that was used for encrypting the file, this is important.
                    * */
                    System.out.println("Enter the absolute path of the IV you would to use for decryption: ");
                    IVKeyPath = keyboardInput.next();
                    IVKeyPath = IVKeyPath.replaceAll("\"", "");
                    IvParameterSpec restoredIV = AES256Utility.readInIV(IVKeyPath);


                    System.out.println("Enter the absolute path of the file you would like to decrypt: ");
                    fileDirectory = keyboardInput.next();
                    fileDirectory = fileDirectory.replace("\"", "");

                    /*
                    * Read in the file and place bytes in each of the arrays so that we can perform operations on it.
                    * */
                    BufferedReader br = new BufferedReader(new FileReader(fileDirectory));
                    encryptedFileMessage = Base64.getDecoder().decode(br.readLine());
                    encryptedAESKey = Base64.getDecoder().decode(br.readLine());
                    encryptedMac = Base64.getDecoder().decode(br.readLine());
                    br.close();


                    

                    System.out.println("Enter the absolute path of the public key of the sender you would like to use for decryption: ");
                    String pubkeyfileDirectory = keyboardInput.next();
                    PublicKey otherPartyPublicKey = RSAUtility.loadInPublicKey(pubkeyfileDirectory);
                    currentPerson.setOtherPersonPubKey(otherPartyPublicKey);


                    /*
                    * Decrypt the AES key from the file
                    * */
                    Cipher RSADecryptCipher = Cipher.getInstance("RSA");
                    RSADecryptCipher.init(Cipher.DECRYPT_MODE, currentPerson.returnPrivateKey());
                    byte[] decodedAESKey = RSADecryptCipher.doFinal(encryptedAESKey);
                    SecretKey AESDecryptionKey = new SecretKeySpec(decodedAESKey, 0, decodedAESKey.length, "AES");

                    /*
                    *Decrypt the message
                    * */

                    Cipher AESDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    AESDecryptCipher.init(Cipher.DECRYPT_MODE, AESDecryptionKey, restoredIV);
                    byte[] decryptedBytes = AESDecryptCipher.doFinal(encryptedFileMessage);
                    /*
                    * Convert the bytes into a human readable string.
                    * */
                    String decryptedMessage =  new String(decryptedBytes);

                    /*
                    * Compute the MAC.
                    * */
                    Mac macSignature = Mac.getInstance("HmacSHA256");
                    macSignature.init(AESDecryptionKey);
                    byte[] finalMacBytes = macSignature.doFinal(decryptedMessage.getBytes());

                    //Check if the finalMacBytes is equivalent to the encryptedMac, if not, then the message was tampered with.
                    System.out.println("Mac Authentication : " + ((Arrays.equals(encryptedMac, finalMacBytes)) ? "successful!" : "failed, the message has been tampered with, do not trust!"));
                    System.out.println(decryptedMessage);
                    String newFileName = fileDirectory.substring(fileDirectory.lastIndexOf('\\') + 1, fileDirectory.length() );

                    //Write out the plaintext to a file, in the same directory that the encrypted file was in.
                    writeOutPlaintext(fileDirectory,newFileName, decryptedMessage);
                    newFileName = newFileName.replace("encrypted", "decrypted");
                    System.out.println("File written to: " + fileDirectory.substring(0, '\\') + newFileName);
                    break;
                case 3:
                    System.out.println("Exiting program, goodbye!\n");
                    displayOptions = false;
                    break;
                default:
                    break;

                }




        }
        while (displayOptions);











    }


    /**
     * Writes out a plaintext, the file location is typically that of the same location where the encrypted ciphertext is, just for convenience.
     *
     * @param directory
     * @param filename
     * @param plaintext
     */
    public static void writeOutPlaintext(String directory, String filename, String plaintext) throws FileNotFoundException {
        //Create a new file at the specified directory with the specified name.
        directory = directory.substring(0, directory.lastIndexOf('\\'));
        filename = filename.replaceAll("encrypted", "decrypted");
        String finalDirectory = directory + "\\" + filename;
        File plaintextFile = new File(finalDirectory);
        PrintWriter printWriter = new PrintWriter(plaintextFile);
        printWriter.print(plaintext);
        printWriter.close();



    }


    /**
     * Write out the encrypted bits to a specified location, this includes the message, AESKey and the MAC. Creates a file
     * in the specified directory, with the chosen filename.
     * @param directory The location where we are writing these bits to.
     * @param fileName The chosen file name for the encrypted ciphertext.
     * @param encryptedMessage The bytes of the encrypted message.
     * @param AESKey The bytes of the encrypted AES key.
     * @param MAC The bytes of the encrypted MAC.
     * @throws IOException
     */
    public static void writeEncryptedBitsToFile(String directory, String fileName, byte[] encryptedMessage, byte[] AESKey, byte[] MAC) throws IOException {

        String completeFileName = directory + "\\";
        completeFileName = completeFileName + fileName;
        File createdFile = new File(completeFileName);
        FileOutputStream fos = new FileOutputStream(createdFile);
        fos.write(Base64.getEncoder().encode(encryptedMessage));
        fos.write('\n');

        fos.write(Base64.getEncoder().encode(AESKey));
        fos.write('\n');

        fos.write(Base64.getEncoder().encode(MAC));
        fos.write('\n');
        fos.close();
    }















    }

