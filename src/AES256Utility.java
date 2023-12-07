

import javax.crypto.*;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Class that will encapsulate the operations used by the AES algorithm in order to encrypt and decrypt a text file.
 */
public class AES256Utility {

    /**
     * Generates an AES key based on the desired size.
     * @param nAesBits the number of bits desired for the AES Key.
     * @returns The generated AES key.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static SecretKey generateAESKey(int nAesBits) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(nAesBits);
        SecretKey key = kg.generateKey();
        return key;


    }


    /**
     * Generate an IV that is going to be used for AES encryption
     * @return The generated IV.
     */
    public static IvParameterSpec generateIV(){
        byte[] IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        return new IvParameterSpec(IV);
    }


    /**
     * Write out the IV to a file so that it can be used again in order to decrypt.
     * Creates a file with the "IV.txt" ending to signify it is an IV file.
     * @param IV The IvParameterSpec we would like to use to write out its bits.
     */
    public static void writeOutIV(byte[] IV, String fileName, String directory){

        try {
            String finalLocationName = directory + "\\" + fileName + "IV.txt";
            File IVFile = new File(finalLocationName);
            FileOutputStream fos = new FileOutputStream(IVFile);
            BufferedOutputStream bos = new BufferedOutputStream(fos);
            bos.write(IV);
            bos.close();

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Opens a file at the given directory and then reads in the bits needed for an IV from the file.
     * @param directory The location of the IV.
     * @return The read in IV.
     */
    public static IvParameterSpec readInIV(String directory){
        try {
            byte[] IVBytes = new byte[16];

            File IVFile = new File(directory);
            DataInputStream dis = new DataInputStream(new FileInputStream(IVFile));
            dis.readFully(IVBytes);
            if (dis != null){
                dis.close();
            }

            IvParameterSpec returnIV = new IvParameterSpec(IVBytes);
            return returnIV;


        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }





}
