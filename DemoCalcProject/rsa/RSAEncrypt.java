package rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * Encryption of a message stored in file <code>plaintext</code> with the
 * public key stored in file <code>publickey</code>. Use RSAKeyGen to generate
 * the <code>publickey</code> and <code>privatekey</code> files.
 *
 * @version $Revision: 1.1 $
 * @see RSAKeyGen
 * @see RSADecrypt
 */
public class RSAEncrypt {
    /**
     * Reads the message in file <code>filename</code> and the public key in
     * file <code>publickey</code>, encrypts the message with public key and
     * writes it to file <code>ciphertext</code>.
     *
     * @param filename the name of the file containing the plaintext.
     */
    public RSAEncrypt(String inFileName, String outFileName) {
        try {
            /* Get the secret message from file. */
            FileInputStream plainfile = new FileInputStream(inFileName);
            byte[] plaintext = new byte[plainfile.available()];
            plainfile.read(plaintext);
            plainfile.close();

            /* Get the public key from file. */
            PublicKey publickey = readPublicKey("publickey");

            /* Create a cipher for encrypting. */
            Cipher encrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            encrypt_cipher.init(Cipher.ENCRYPT_MODE, publickey);

            /* Encrypt the secret message and store in file. */
            byte[] ciphertext = encrypt_cipher.doFinal(plaintext);
            FileOutputStream cipherfile = new FileOutputStream(outFileName);
            cipherfile.write(ciphertext);
            cipherfile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public RSAEncrypt() {
    }

    /**
     * Reads the X.509 standard encoded RSA public key in <code>filename</code>.
     *
     * @param filename the name of the file with the RSA public key.
     * @return the public key in <code>filename</code>.
     * @throws Exception if something goes wrong.
     */
    public static PublicKey readPublicKey(String filename) throws Exception {
        FileInputStream file = new FileInputStream(filename);
        byte[] bytes = new byte[file.available()];
        file.read(bytes);
        file.close();
        X509EncodedKeySpec pubspec = new X509EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey pubkey = factory.generatePublic(pubspec);
        return pubkey;
    }

    /**
     * The main method just calls constructor.
     *
     * @param arg The command line arguments.
     */
    public static void main(String[] arg) {
        if (arg.length != 2) {
            System.err.println("Usage:  java RSAEncrypt <src file> <dest file>");
        } else {
            new RSAEncrypt(arg[0], arg[1]);
        }
    }

    private byte[] encrypt(PublicKey publickey, byte[] msg) {

        Cipher encrypt_cipher = null;
        try {
            encrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            encrypt_cipher.init(Cipher.ENCRYPT_MODE, publickey);

            byte[] ciphertext = encrypt_cipher.doFinal(msg);
            return ciphertext;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}

