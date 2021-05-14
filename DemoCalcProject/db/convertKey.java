package db;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class convertKey {
    protected KeyFactory factory;

    public convertKey(){
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public PrivateKey stringToPrivate(String string){
        byte[] byte_privkey = Base64.getDecoder().decode(string);
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(byte_privkey);
        try {
            return factory.generatePrivate(privKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String privateToString(PrivateKey privkey){
        byte[] byte_privkey = privkey.getEncoded();
        String str_privkey = Base64.getEncoder().encodeToString(byte_privkey);
        return str_privkey;
    }

    public PublicKey stringToPublic(String string){
        byte[] byte_pubkey = Base64.getDecoder().decode(string);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(byte_pubkey);
        try {
            return factory.generatePublic(pubKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String publicToString(PublicKey pubkey){
        byte[] byte_pubkey = pubkey.getEncoded();
        String str_pubkey = Base64.getEncoder().encodeToString(byte_pubkey);
        return str_pubkey;
    }

}
