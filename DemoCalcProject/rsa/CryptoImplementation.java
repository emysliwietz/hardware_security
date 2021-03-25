package rsa;

import db.Database;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.UUID;

public abstract class CryptoImplementation {
    protected byte[] ID;
    protected byte[] certificate;
    protected RSACrypto rc;

    public UUID generateNonce(){
        return UUID.randomUUID();
    }

    public byte[] getCertificate() {
        return this.certificate;
    }


    public byte[] createHash(byte[] toHash){
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-512");
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
        return rc.decrypt(message);
    }

    public byte[] unsign(byte[] signature, PublicKey pubSK){
        return rc.encrypt(signature, pubSK);
    }

}
