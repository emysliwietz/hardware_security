package rsa;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Generate an RSA public/private keypair.
 *
 * @version $Revision: 1.1 $
 */
public class RSAKeyGen {
    /**
     * Generates an RSA public/private key pair.
     */
    public RSAKeyGen(String keyPairName) {

        try {
            /* Generate keypair. */
            System.err.println("Generating keys...");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey publickey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey privatekey = (RSAPrivateKey) keypair.getPrivate();

            /* Write public key to file. */
            writeKey(publickey, keyPairName + "_publickey");

            /* Write private key to file. */
            writeKey(privatekey, keyPairName + "_privatekey");

            System.err.println("modulus = " + publickey.getModulus());
            System.err.println("pubexpint = " + publickey.getPublicExponent());
            System.err.println("privexpint = " + privatekey.getPrivateExponent());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public RSAKeyGen() {
    }

    public static Object[] generateKeys() {
        /* Generate keypair. */
        System.err.println("Generating keys...");
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        generator.initialize(1024);
        KeyPair keypair = generator.generateKeyPair();
        RSAPublicKey publickey = (RSAPublicKey) keypair.getPublic();
        RSAPrivateKey privatekey = (RSAPrivateKey) keypair.getPrivate();
        Object[] keyPair = new Object[2];
        keyPair[0] = publickey;
        keyPair[1] = privatekey;
        return keyPair;
        //System.err.println("modulus = " + publickey.getModulus());
        //System.err.println("pubexpint = " + publickey.getPublicExponent());
        //System.err.println("privexpint = " + privatekey.getPrivateExponent());
    }

    /**
     * Writes <code>key</code> to file with name <code>filename</code> in
     * standard encoding (X.509 for RSA public key, PKCS#8 for RSA private key).
     *
     * @param key      the key to write.
     * @param filename the name of the file.
     * @throws IOException if something goes wrong.
     */
    public static void writeKey(Key key, String filename) throws IOException {
        FileOutputStream file = new FileOutputStream(filename);
        file.write(key.getEncoded());
        file.close();
    }

    /**
     * The main method just calls the constructor.
     *
     * @param arg The command line arguments.
     */
}

