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

    public byte[] sign(byte[] msg){
        Cipher decrypt_cipher;
        try {
            // PKCS1Padding
            decrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            decrypt_cipher.init(Cipher.DECRYPT_MODE, privk);

            return decrypt_cipher.doFinal(msg);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean verify(byte[] rawMsg, byte[] signedMsg, PublicKey pubk) {
        sig.init(pubk, Signature.MODE_VERIFY);
        return sig.verify(rawMsg, (short) 0, (short) rawMsg.length, signedMsg, (short) 0, (short) signedMsg.length);
        /*Cipher encrypt_cipher;
        try {
            // PKCS1Padding
            encrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            encrypt_cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return encrypt_cipher.doFinal(msg);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;*/
    }
}
