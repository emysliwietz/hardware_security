package rsa;

import Interfaces.ProtocolComponentLengths;
import javacard.framework.JCSystem;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.Signature;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 */
public abstract class RSACrypto implements ProtocolComponentLengths {

    private final Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
    protected PrivateKey privk;

    public byte[] sign(byte[] msg) {
        sig.init(privk, Signature.MODE_SIGN);
        byte[] sigBuf = JCSystem.makeTransientByteArray(SIGNED_HASH_LEN, JCSystem.CLEAR_ON_RESET);
        short tmps = sig.sign(msg, (short) 0, (short) msg.length, sigBuf, (short) 0);
        //System.out.println(tmps);
        return sigBuf;
        /*Cipher decrypt_cipher;
        try {
            // PKCS1Padding
            decrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            decrypt_cipher.init(Cipher.DECRYPT_MODE, privk);

            return decrypt_cipher.doFinal(msg);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;*/
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
