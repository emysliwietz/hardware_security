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
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Decryption of a message which is stored in file <code>ciphertext</code>
 * with the private key stored in file <code>privatekey</code>. Use RSAKeyGen
 * to generate the <code>publickey</code> and <code>privatekey</code> files.
 *
 * @version $Revision: 1.1 $
 * @see RSAKeyGen
 * @see RSAEncrypt
 */
public class RSADecrypt {
    /**
     * Reads the encrypted message in file <code>ciphertext</code> and the
     * private key in file <code>privatekey</code>, decrypts the message with
     * private key and shows the plaintext message on standard output.
     *
     * @param filename the name of the file containing the ciphertext.
     */
    public RSADecrypt(String inFileName, String outFileName) {
        try {
            /* Get the encrypted message from file. */
            FileInputStream cipherfile = new FileInputStream(inFileName);
            byte[] ciphertext = new byte[cipherfile.available()];
            cipherfile.read(ciphertext);
            cipherfile.close();

            /* Get the private key from file. */
            PrivateKey privatekey = readPrivateKey("privatekey");

            /* Create cipher for decryption. */
            Cipher decrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            decrypt_cipher.init(Cipher.DECRYPT_MODE, privatekey);

            /* Reconstruct the plaintext message. */
            byte[] plaintext = decrypt_cipher.doFinal(ciphertext);
            FileOutputStream plainfile = new FileOutputStream(outFileName);
            plainfile.write(plaintext);
            plainfile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public RSADecrypt() {
    }

    /**
     * Reads the PKCS#8 standard encoded RSA private key in
     * <code>filename</code>.
     *
     * @param filename The name of the file with the private key.
     * @return The private key in <code>filename</code>.
     */
    public static PrivateKey readPrivateKey(String filename) throws Exception {
        FileInputStream file = new FileInputStream(filename);
        byte[] bytes = new byte[file.available()];
        file.read(bytes);
        file.close();
        PKCS8EncodedKeySpec privspec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privkey = factory.generatePrivate(privspec);
        return privkey;
    }

    /**
     * The main method just calls the constructor.
     *
     * @param arg The command line arguments.
     */
    public static void main(String[] arg) {
        if (arg.length != 2) {
            System.err.println("Usage:  java RSADecrypt <src file> <dest file>");
        } else {
            new RSADecrypt(arg[0], arg[1]);
        }
    }

    private byte[] decrypt(byte[] msg, PrivateKey privatekey) {
        Cipher decrypt_cipher = null;
        try {
            decrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            decrypt_cipher.init(Cipher.DECRYPT_MODE, privatekey);

            byte[] ciphertext = decrypt_cipher.doFinal(msg);
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

