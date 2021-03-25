package db;

import Interfaces.Communicator;
import rsa.*;

import java.security.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;


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

    public byte[] issueCertificate(PublicKey pubk, byte[] id, PrivateKey sk){
        byte[] toHash = prepareMessage(pubk, id);
        byte[] signedHash = hashAndSign(toHash);
        byte[] certificate = prepareMessage(pubk, id, signedHash);
        return certificate;
    }

    public Database(){

    }

    void generateStuff() {
        Object [] dbKeyPair = generateKeyPair();
        PublicKey dbPubSK = (PublicKey) dbKeyPair[0];
        PrivateKey dbPrivSK = (PrivateKey) dbKeyPair[1];
        Object [] scKeyPair = generateKeyPair();
        PublicKey scPubSK = (PublicKey) scKeyPair[0];
        PrivateKey scPrivSK = (PrivateKey) scKeyPair[1];
        Object [] autoKeyPair = generateKeyPair();
        PublicKey autoPubSK = (PublicKey) autoKeyPair[0];
        PrivateKey autoPrivSK = (PrivateKey) autoKeyPair[1];
        Object [] rtKeyPair = generateKeyPair();
        PublicKey rtPubSK = (PublicKey) rtKeyPair[0];
        PrivateKey rtPrivSK = (PrivateKey) rtKeyPair[1];
        byte[] scID = UUID.randomUUID().toString().getBytes();
        byte[] autoID = UUID.randomUUID().toString().getBytes();
        byte[] rtID = UUID.randomUUID().toString().getBytes();
        byte[] scCERT = issueCertificate(scPubSK, scID, dbPrivSK);
        byte[] autoCERT = issueCertificate(autoPubSK, autoID, dbPrivSK);
        byte[] rtCERT = issueCertificate(rtPubSK, rtID, dbPrivSK);
    }



}
