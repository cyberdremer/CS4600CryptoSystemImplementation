import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;

/**
 * This class is a container for RSA public and private key-pairs.
 */
public class Person {
    private KeyPairGenerator pairGenerator;
    private KeyPair keyPair;


    //RSA Public key pair, otherPersonPubKey is used when encrypting a message.
    private PublicKey pubKey, otherPersonPubKey;


    //RSA Private key pair
    private PrivateKey privKey;

    private byte[] macBytes, encryptedMessage, encryptedAESKey;


    private SecretKey AES256Key;

    public IvParameterSpec IV;


    /** This Person constructor is used when there is no existing RSA private and public key pair for this person.
     * In that event, new keys are generated, and then written to their own separate files.
     * The keys that are generated are 2048 bit-sized keys.
     * @throws NoSuchAlgorithmException
     */
    public Person() throws NoSuchAlgorithmException {

        pairGenerator = KeyPairGenerator.getInstance("RSA");
        //Size of key for RSA will be 2048 bits
        pairGenerator.initialize(2048);
        keyPair = pairGenerator.generateKeyPair();
        this.pubKey = keyPair.getPublic();
        this.privKey = keyPair.getPrivate();



    }


    /**This Person constructor is used when there is an existing RSA private and public key pair.
     * In this case, we will read in the public key and store it into this person's private and public key pair.
     *
     * Only use when loading in keys from a file.
     * @param filePublicKey The read in public key from the file.
     *
     * @param filePrivateKey The read in private key from the file.
     *
     */
    public Person(PublicKey filePublicKey, PrivateKey filePrivateKey){
        this.pubKey = filePublicKey;
        this.privKey = filePrivateKey;

    }


    public PrivateKey returnPrivateKey(){
        return this.privKey;
    }

    public PublicKey returnPublicKey(){
        return this.pubKey;
    }




    public void setOtherPersonPubKey(PublicKey pk){
        this.otherPersonPubKey = pk;
    }

    public PublicKey getOtherPersonPubKey(){
        return otherPersonPubKey;
    }

    public byte[] getEncryptedAESKey() {
        return encryptedAESKey;
    }

    public byte[] getEncryptedMessage() {
        return encryptedMessage;
    }

    public byte[] getMacBytes() {
        return macBytes;
    }

    public void setEncryptedAESKey(byte[] encryptedAESKey) {
        this.encryptedAESKey = encryptedAESKey;
    }

    public void setEncryptedMessage(byte[] encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public void setMacBytes(byte[] macBytes) {
        this.macBytes =  macBytes;
    }
}
