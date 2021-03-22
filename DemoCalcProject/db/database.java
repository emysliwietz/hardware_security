package db;

import rsa.*;

import java.math.BigInteger;
import java.security.MessageDigest;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import static rsa.Util.readFileAsBytes;


class Database {
    public static void main(String[] args){
        RSAKeyGen masterKey = new RSAKeyGen("master");
        //RSAKeyGen smartCardSignatureKey = new RSAKeyGen("smartCardSignature");
        //RSAKeyGen carSignatureKey = new RSAKeyGen("carSignature");
        //RSAKeyGen terminalSignatureKey = new RSAKeyGen("terminalSignature");
    }

    public void signCertificate(String inFile, String outFile){
        byte[] hash = new byte[0];
        try {
            hash = createHash(readFileAsBytes(inFile));
        } catch (IOException e) {
            e.printStackTrace();
        }
        RSADecrypt cert = new RSADecrypt(hash, outFile);
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
        System.out.println(hash.toString(16));
        return messageDigest;
    }

}
