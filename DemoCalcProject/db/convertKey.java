package db;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

import Interfaces.Communicator;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class convertKey implements Communicator {
    protected KeyFactory factory; short offset;

    public convertKey(){
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public PrivateKey stringToPrivate(String string){
        /*byte[] byte_privkey = Base64.getDecoder().decode(string);
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(byte_privkey);
        try {
            return factory.generatePrivate(privKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }*/
        return bytesToPrivkey(fromHexString(string));
    }

    public String privateToString(PrivateKey privkey){
        /*byte[] byte_privkey = privkey.getEncoded();
        String str_privkey = Base64.getEncoder().encodeToString(byte_privkey);
        return str_privkey;*/
        return toHexString(privkToBytes(privkey));
    }

    public PublicKey stringToPublic(String string){
        /*byte[] byte_pubkey = Base64.getDecoder().decode(string);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(byte_pubkey);
        try {
            return factory.generatePublic(pubKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }*/
        return bytesToPubkey(fromHexString(string));
    }

    public String publicToString(PublicKey pubkey){
        return toHexString(pubkToBytes(pubkey));
        /*byte[] byte_pubkey = pubkey.getEncoded();
        String str_pubkey = Base64.getEncoder().encodeToString(byte_pubkey);
        return str_pubkey;*/
    }

    public String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public byte[] fromHexString(String str){
        String[] str0 = str.split(" ");
        byte[] b = new byte[str0.length];
        for(int i=0;i<str0.length;i++){
            b[i] = (byte) ((short) Short.valueOf(str0[i],16));
        }
        return b;
    }

}
