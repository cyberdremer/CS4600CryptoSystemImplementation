import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;

public class Person {
    private KeyPairGenerator pairGenerator;
    private KeyPair keyPair;


    //RSA Public key pair
    private PublicKey pubKey;


    //RSA Private key pair
    private PrivateKey privKey;


    private SecretKey AES256Key;

    public IvParameterSpec IV;


    /** This Person constructor is used when there is no existing RSA private and public key pair for this person.
     * In that event, new keys are generated, and then written to their own separate files.
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
     * @param filePublicKey The read in public key from the file.
     * @param filePrivateKey The read in private key from the file.Only
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


    public void setAES256Key(){

    }


}
