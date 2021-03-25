package db;

import Interfaces.Communicator;
import rsa.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;


public class Database extends CryptoImplementation implements Communicator {

    public Object[] generateKeyPair(){
        /* Generate keypair. */
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        generator.initialize(1024);
        KeyPair keypair = generator.generateKeyPair();
        RSAPublicKey publickey = (RSAPublicKey)keypair.getPublic();
        RSAPrivateKey privatekey = (RSAPrivateKey)keypair.getPrivate();
        Object[] keyPair = new Object[2];
        keyPair[0] = publickey;
        keyPair[1] = privatekey;
        return keyPair;
    }

    /*public void signCertificate(String inFile, String outFile){
        byte[] hash = new byte[0];
        try {
            hash = createHash(readFileAsBytes(inFile));
        } catch (IOException e) {
            e.printStackTrace();
        }
        RSADecrypt cert = new RSADecrypt(hash, outFile);
    }*/



}
