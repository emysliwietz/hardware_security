package rsa;

import db.Database;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.UUID;

public abstract class CryptoImplementation {
    protected byte[] ID;
    protected byte[] certificate;
    protected RSACrypto rc;
    protected SecureRandom sr = new SecureRandom();

    public short generateNonce(){
        byte[] bytes = new byte[2];
        sr.nextBytes(bytes);
        return (short)(((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF));
    }

    public boolean areSubsequentNonces(short a, short aPlus1){
        return (aPlus1 == (short) (a+1));
    }

    public boolean areSubsequentNonces(short a, short aPlusX, int x){
        return (aPlusX == (short) (a+((short) x)));
    }

    /*
        short s = Short.MAX_VALUE;
        short p = (short) (s + 1);
        System.out.println(s + 1 == p); // false
        System.out.println((short) (s + 1) == p); // true
     */

    public byte[] getCertificate() {
        return this.certificate;
    }


    public byte[] createHash(byte[] toHash){
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        digest.update(toHash);
        byte[] messageDigest = digest.digest();
        BigInteger hash = new BigInteger(1, messageDigest);
        return hash.toString(16).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] hashAndSign(byte[] message){
        return sign(createHash(message));
    }

    public byte[] sign(byte[] message){
        return rc.sign(message);
    }

    public byte[] unsign(byte[] signature, PublicKey pubSK){
        return rc.unsign(signature, pubSK);
    }

}
