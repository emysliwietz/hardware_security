package db;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.CommunicatorExtended;
import Interfaces.KeyWallet;
import Smartcard.Smartcard;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import gui.SmartcardGUI;
import javacard.framework.AID;
import javafx.application.Application;
import receptionTerminal.ReceptionTerminal;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.io.File;
import java.nio.ByteBuffer;
//import java.security.*;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.KeyPair;
import java.sql.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import db.convertKey;

import javax.smartcardio.CommandAPDU;

import static utility.Util.print;

/**
@author Matti Eisenlohr
@author Egidius Mysliwietz
@author Laura Philipse
@author Alessandra van Veen
 */
public class Database extends CommunicatorExtended {

    private Connection conn;
    public PublicKey dbPubSK;
    protected PrivateKey dbPrivSK;
    protected byte[] databaseID;
    protected DatabaseCrypto dc;
    protected ByteBuffer msgBuf = ByteBuffer.allocate(512);
    convertKey conv = new convertKey();
    CardSimulator smartcard = new CardSimulator();


    public Object[] generateKeyPair(){
        /* Generate keypair. */
        /*KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        generator.initialize(1024);*/
        KeyPair kp = new KeyPair(KeyPair.ALG_RSA, (short) 512);
        kp.genKeyPair();
        RSAPublicKey publickey = (RSAPublicKey)kp.getPublic();
        RSAPrivateKey privatekey = (RSAPrivateKey)kp.getPrivate();
        Object[] keyPair = new Object[2];
        keyPair[0] = publickey;
        keyPair[1] = privatekey;
        return keyPair;
    }

    /**Returns byte array of shape: 0-127: Encoded public key; 128-132: id, 133-136: length of signed hash, 137-end: signed hash*/
    //TODO: Where is the end?
    public byte[] issueCertificate(PublicKey pubk, byte[] id, PrivateKey sk){
        byte[] toHash = concatBytes(pubkToBytes(pubk), id);
        byte[] signedHash = dc.sign(toHash);
        return concatBytes(toHash, intToByteArray(signedHash.length),signedHash);
    }

    /**get public key of database*/
    public PublicKey getDbPubSK(){
        return dbPubSK;
    }

    /**Get and set the database keys and id*/
    private void setKeys() {
        convertKey conv = new convertKey();
        String sqlGetKeys = "SELECT db.* FROM database db LIMIT 1";

        try (
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sqlGetKeys)) {
            if (rs.next() == false) { //Generate keys if they do not exist yet
                Object[] dbKeyPair = generateKeyPair();
                dbPubSK = (PublicKey) dbKeyPair[0];
                dbPrivSK = (PrivateKey) dbKeyPair[1];
                databaseID = UUID.randomUUID().toString().getBytes();

                //Store keys in database
                String sqlSetKeys = "INSERT INTO database(id, publickey, privatekey) VALUES(?,?,?)";

                try (PreparedStatement pstmt = conn.prepareStatement((sqlSetKeys))) {
                    pstmt.setString(1, new String(databaseID));
                    pstmt.setString(2, conv.publicToString(dbPubSK));
                    pstmt.setString(3, conv.privateToString(dbPrivSK));
                    pstmt.executeUpdate();
                } catch (SQLException e) {
                    System.out.println(e.getMessage());
                }

            } else { //Otherwise, grab them from the database
                dbPubSK = conv.stringToPublic(rs.getString("publickey"));
                dbPrivSK = conv.stringToPrivate(rs.getString("privatekey"));
                databaseID = rs.getString("id").getBytes();
            }
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

    public Database(){
        conn = null;

        try{
            Class.forName("org.sqlite.JDBC");
            File currentDir = new File("");
            String url = "jdbc:sqlite:" + currentDir.getAbsolutePath().replace("\\","\\\\") + "/DemoCalcProject/db/CarCompany.db";
            conn = DriverManager.getConnection(url);
        } catch(Exception e){
            System.err.println(e.getClass().getName() + ": " + e.getMessage() );
            System.exit(0);
        }

        setKeys();

        dc = new DatabaseCrypto(databaseID, null);
        byte[] dbCERT = issueCertificate(dbPubSK, databaseID, dbPrivSK); //rc = null
        dc.setCertificate(dbCERT);
    }

    public void carAssign(ReceptionTerminal reception){
        print("I'm assigning a car");
        ByteBuffer response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssign");
            return;
        }

        byte[] cardID = new byte[5];
        response.get(cardID,0,5);//Get card ID so DB knows which car is assigned to which card

        String autoID = null;

        String sqlFindCar = "SELECT a.* FROM autos a LEFT JOIN rentrelations r ON a.id = r.autoID " +
                "/*WHERE r.autoID IS NULL*/ ORDER BY random() LIMIT 1"; //Store link between auto and card

        byte[] autoCert = null;

        try (
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sqlFindCar)){

                autoID = rs.getString("id");
                autoCert = conv.fromHexString(rs.getString("certificate"));
            }
        catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        if (autoID == null){ //If no car available
            errorState("No car found");
            return;
        }

        String sqlSetRelation ="INSERT INTO rentRelations(autoID, cardID) VALUES(?,?)";

        try ( PreparedStatement pstmt = conn.prepareStatement(sqlSetRelation)){
            pstmt.setString(1, autoID);
            pstmt.setString(2, conv.toHexString(cardID));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        msgBuf.put(autoCert);
        send(reception, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        //Potentially get confirmation from terminal that they received it? or do we already ack stuff TODO
    }

    public void carUnassign(ReceptionTerminal reception){
        ByteBuffer response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carUnassign");
            return;
        }
        byte[] cardID = new byte[5];
        response.get(cardID,0,5);

        String sql = "DELETE FROM rentRelations WHERE cardID = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, new String(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String confirmation = new String(cardID) + " has been removed from Rent Relations.";
        byte[] message = prepareMessage(confirmation);
        msgBuf.put(message);
        send(reception, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        //Terminal might need to receive this message. We'll fix later. :) TODO
    }

    public void deleteCard(ReceptionTerminal reception){
        ByteBuffer response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carUnassign");
            return;
        }
        byte[] cardID = new byte[5];
        response.get(cardID,0,5);

        String sql = "DELETE FROM cards WHERE id = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, new String(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String sql2 = "DELETE FROM rentrelations WHERE id = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql2)) {

            // set the corresponding param
            pstmt.setString(1, new String(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String confirmation = new String(cardID) + " has been removed from cards.";
        byte[] message = prepareMessage(confirmation);
        msgBuf.put(message);
        send(reception, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
    }

    public void generateCard(ReceptionTerminal reception){

        // Create simulator
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();

        // Install applet
        //AID scAID = new AID(SC_APPLET_AID,(byte)0,(byte)7);
        AID scAID = AIDUtil.create(SC_APPLET_AID);
        simulator.installApplet(scAID, Smartcard.class);
        //simulator.installApplet(scAID, Smartcard.class, installBuf.array(), (short) installBuf.arrayOffset(), (byte) ibLen);
        simulator.transmitCommand(SELECT_APDU);

        Object [] scKeyPair = generateKeyPair();
        PublicKey scPubSK = (PublicKey) scKeyPair[0];
        PrivateKey scPrivSK = (PrivateKey) scKeyPair[1];
        byte[] scID = dc.generateID();
        byte[] scCERT = issueCertificate(scPubSK, scID, dbPrivSK);

        String sql ="INSERT INTO cards(id,publickey,certificate) VALUES(?,?,?)";

        try ( PreparedStatement pstmt = conn.prepareStatement(sql)){
            pstmt.setString(1, conv.toHexString(scID));
            pstmt.setString(2, conv.publicToString(scPubSK));
            pstmt.setString(3, conv.toHexString(scCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        //byte[] cardID, int certLength, byte[] cardCertificate, byte[] privateKeyEncoded
        int certLen = scCERT.length;
        int ibLen = 5+4+scCERT.length+privkToBytes(scPrivSK).length+KEY_LEN;
        ByteBuffer installBuf = ByteBuffer.allocate(ibLen);
        installBuf.put(scID);
        installBuf.putInt(scCERT.length);
        System.out.println(scCERT.length);
        System.out.println(getInt(installBuf.array(),5));
        installBuf.put(scCERT);
        installBuf.put(privkToBytes(scPrivSK));
        installBuf.put(pubkToBytes(dbPubSK));
        send(reception,installBuf);



        // and send the info back
        // Private key and certificate must be send to terminal which sends it to the card
        //return new Smartcard(scID, scCERT, scPrivSK);
        //byte[] message = prepareMessage(scPrivSK, scCERT);
        //send(terminal, message);


    }
    public Auto generateAuto(){
        Object [] autoKeyPair = generateKeyPair();
        PublicKey autoPubSK = (PublicKey) autoKeyPair[0];
        PrivateKey autoPrivSK = (PrivateKey) autoKeyPair[1];
        byte[] autoID = dc.generateID();
        byte[] autoCERT = issueCertificate(autoPubSK, autoID, dbPrivSK);

        String sql ="INSERT INTO autos(id,publickey,certificate) VALUES(?,?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)){
            pstmt.setString(1, conv.toHexString(autoID));
            pstmt.setString(2, conv.publicToString(autoPubSK));
            pstmt.setString(3, conv.toHexString(autoCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        // Private key and certificate must be send to auto
        //byte[] message = prepareMessage(autoPrivSK, autoCERT);
        return new Auto(autoID, autoCERT, autoPrivSK,dbPubSK,smartcard);
        //send(auto, message);
    }

    public ReceptionTerminal generateTerminal(){
        Object [] rtKeyPair = generateKeyPair();
        PublicKey rtPubSK = (PublicKey) rtKeyPair[0];
        PrivateKey rtPrivSK = (PrivateKey) rtKeyPair[1];
        byte[] rtID = dc.generateID();
        byte[] rtCERT = issueCertificate(rtPubSK, rtID, dbPrivSK);

        String sql ="INSERT INTO terminals(id,publickey,certificate) VALUES(?,?,?)";

        try ( PreparedStatement pstmt = conn.prepareStatement(sql)){
            pstmt.setString(1, conv.toHexString(rtID));
            pstmt.setString(2, conv.publicToString(rtPubSK));
            pstmt.setString(3, conv.toHexString(rtCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        // and send the info back
        //private key and certificate must be send to terminal
        return new ReceptionTerminal(rtID, rtCERT, this, rtPrivSK,smartcard);
        //byte[] message = prepareMessage(rtPrivSK, rtCERT);
        //send(terminal, message);

    }

    public boolean isBlocked(byte[] cardID){
        String sql = "SELECT id FROM cards db WHERE id = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)){
                pstmt.setString(1, conv.toHexString(cardID));
                ResultSet rs = pstmt.executeQuery(sql);
                if(rs.next() == false){ //If the cardID is not listed
                    return true;
                }
                else{
                    return false;
                }
            } catch (SQLException e) {
                System.out.println(e.getMessage());
            }
        return false;
    }

    public static void main(String[] args) {
        Database db = new Database();
        ReceptionTerminal rt = db.generateTerminal();
        Auto auto = db.generateAuto();
        //Smartcard sc = db.generateCard();
        SmartcardGUI gui = new SmartcardGUI();
        //gui.init(sc, auto, rt);
        //gui.launch();
        Thread t1 = new Thread(() -> Application.launch(SmartcardGUI.class, args));
        t1.start();
    }

    private class DatabaseCrypto extends CryptoImplementation {

        public DatabaseCrypto(byte[] databaseID, byte[] databaseCertificate) {
            super.ID = databaseID;
            super.certificate = databaseCertificate;
            DatabaseWallet dbWallet = new DatabaseWallet();
            dbWallet.storePrivateKey(dbPrivSK);
            super.rc = dbWallet;
        }

        private void setCertificate(byte[] cert){
            super.certificate = cert;
        }

        private class DatabaseWallet extends RSACrypto implements KeyWallet {
        //no idea what exactly should be happening in these functions

            @Override
            public void storePublicKey() {

            }

            @Override
            public void storePrivateKey(PrivateKey privateKey) {
                super.privk = privateKey;
            }

            @Override
            public PublicKey getPublicKey() {
                return null;
            }
        }
    }
}
