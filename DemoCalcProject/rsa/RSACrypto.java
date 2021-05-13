package rsa;

import Interfaces.KeyWallet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class RSACrypto {

    protected PrivateKey privk;

    public byte[] decrypt(byte[] msg){
        Cipher decrypt_cipher;
        try {
            decrypt_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decrypt_cipher.init(Cipher.DECRYPT_MODE, privk);

            return decrypt_cipher.doFinal(msg);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] encrypt(byte[] msg, PublicKey publicKey) {

        Cipher encrypt_cipher;
        try {
            encrypt_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encrypt_cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return encrypt_cipher.doFinal(msg);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}
