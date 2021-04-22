package db;

import Interfaces.Communicator;
import receptionTerminal.ReceptionTerminal;
import rsa.*;

import java.security.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;


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
        Connection c = null;

        //source for now: https://www.tutorialspoint.com/sqlite/sqlite_java.htm
        //So I know how to find the tutorial again
        try{
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:test.db"); //doesnt work yet but so we have the thing
        } catch(Exception e){
            System.err.println(e.getClass().getName() + ": " + e.getMessage() );
            System.exit(0);
        }

    }

    //Temporary filler function
    public void carAssign(ReceptionTerminal reception){
        byte[] response = new byte[0];
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssign");
            return;
        }
        Object[] responseData = processMessage(response);
        byte[] cardID = (byte[]) responseData[0]; //Get card ID so DB knows which car is assigned to which card

        //Some function so it stores the link between an autoID and a cardID

        //just a fake generate for now so it wont throw an error
        //Should be retrieved from the database
        Object [] dbKeyPair = generateKeyPair();
        PublicKey dbPubSK = (PublicKey) dbKeyPair[0];
        PrivateKey dbPrivSK = (PrivateKey) dbKeyPair[1];
        Object [] autoKeyPair = generateKeyPair();
        PublicKey autoPubSK = (PublicKey) autoKeyPair[0];
        PrivateKey autoPrivSK = (PrivateKey) autoKeyPair[1];
        byte[] autoID = UUID.randomUUID().toString().getBytes();

        byte[] message = prepareMessage(issueCertificate(autoPubSK, autoID, dbPrivSK));
        send(reception, message);
    }

 /*   void generateStuff() { //TODO: Put those variables in global object array/mini-database
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
    }*/

    void generateCard(){
        Object [] scKeyPair = generateKeyPair();
        PublicKey scPubSK = (PublicKey) scKeyPair[0];
        PrivateKey scPrivSK = (PrivateKey) scKeyPair[1];
        byte[] scID = UUID.randomUUID().toString().getBytes();
        //TODO: byte[] scCERT = issueCertificate(scPubSK, scID, dbPrivSK);

        // actually store in DB, not the private key though
        // and send the info back
    }
    void generateAuto(){
        Object [] autoKeyPair = generateKeyPair();
        PublicKey autoPubSK = (PublicKey) autoKeyPair[0];
        PrivateKey autoPrivSK = (PrivateKey) autoKeyPair[1];
        byte[] autoID = UUID.randomUUID().toString().getBytes();
        //TODO: byte[] autoCERT = issueCertificate(autoPubSK, autoID, dbPrivSK);

        // actually store in DB, not the private key though
        // and send the info back
    }

    void generateTerminal(){
        Object [] rtKeyPair = generateKeyPair();
        PublicKey rtPubSK = (PublicKey) rtKeyPair[0];
        PrivateKey rtPrivSK = (PrivateKey) rtKeyPair[1];
        byte[] rtID = UUID.randomUUID().toString().getBytes();
        //TODO: byte[] rtCERT = issueCertificate(rtPubSK, rtID, dbPrivSK);

        // actually store in DB, not the private key though
        // and send the info back

    }
}
