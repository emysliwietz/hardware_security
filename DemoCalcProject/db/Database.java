package db;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Smartcard.Smartcard;
import gui.SmartcardGUI;
import receptionTerminal.ReceptionTerminal;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.io.File;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.*;
import java.util.Base64;
import java.util.UUID;

import db.convertKey;


public class Database implements Communicator {
    private Connection conn;
    protected PublicKey dbPubSK;
    protected PrivateKey dbPrivSK;
    protected byte[] databaseID;
    protected DatabaseCrypto dc;


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
        byte[] signedHash = dc.hashAndSign(toHash);
        byte[] certificate = prepareMessage(pubk, id, signedHash);
        return certificate;
    }

    //Get and set the database keys and id
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
            String url = "jdbc:sqlite:" + currentDir.getAbsolutePath().replace("\\","\\\\") + "\\db\\CarCompany.db";
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

        String autoID = null;

        String sqlFindCar = "SELECT a.* FROM autos a LEFT JOIN rentrelations r ON a.id = r.autoID " +
                "WHERE r.autoID IS NULL ORDER BY random() LIMIT 1"; //Store link between auto and card

       byte[] autoCert = null;

        try (
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sqlFindCar)){

                autoID = rs.getString("id");
                autoCert = rs.getString("certificate").getBytes();
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
            pstmt.setString(2, new String(cardID));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }


        byte[] message = prepareMessage(autoCert);
        send(reception, message);
        //Potentially get confirmation from terminal that they received it? or do we already ack stuff
    }

    public void carUnassign(ReceptionTerminal reception){
        byte[] response = new byte[0];
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carUnassign");
            return;
        }
        Object[] responseData = processMessage(response);
        byte[] cardID = (byte[]) responseData[0];

        String sql = "DELETE FROM rentRelations WHERE cardID = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, new String(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String confirmation = cardID.toString() + " has been removed from Rent Relations.";
        byte[] message = prepareMessage(confirmation);
        send(reception, message);
        //Terminal might need to receive this message. We'll fix later. :)
    }

    public void deleteCard(ReceptionTerminal reception){
        byte[] response = new byte[0];
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carUnassign");
            return;
        }
        Object[] responseData = processMessage(response);
        byte[] cardID = (byte[]) responseData[0];

        String sql = "DELETE FROM cards WHERE cardID = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, new String(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String confirmation = cardID.toString() + " has been removed from cards.";
        byte[] message = prepareMessage(confirmation);
        send(reception, message);
    }

    Smartcard generateCard(){
        convertKey conv = new convertKey();
        Object [] scKeyPair = generateKeyPair();
        PublicKey scPubSK = (PublicKey) scKeyPair[0];
        PrivateKey scPrivSK = (PrivateKey) scKeyPair[1];
        byte[] scID = UUID.randomUUID().toString().getBytes();
        byte[] scCERT = issueCertificate(scPubSK, scID, dbPrivSK);

        String sql ="INSERT INTO cards(id,publickey,certificate) VALUES(?,?,?)";

        try ( PreparedStatement pstmt = conn.prepareStatement(sql)){
            pstmt.setString(1, new String(scID));
            pstmt.setString(2, conv.publicToString(scPubSK));
            pstmt.setString(3, new String(scCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        // and send the info back
        // Private key and certificate must be send to terminal which sends it to the card
        return new Smartcard(scID, scCERT, scPrivSK);
        //byte[] message = prepareMessage(scPrivSK, scCERT);
        //send(terminal, message);


    }
    Auto generateAuto(){
        convertKey conv = new convertKey();
        Object [] autoKeyPair = generateKeyPair();
        PublicKey autoPubSK = (PublicKey) autoKeyPair[0];
        PrivateKey autoPrivSK = (PrivateKey) autoKeyPair[1];
        byte[] autoID = UUID.randomUUID().toString().getBytes();
        byte[] autoCERT = issueCertificate(autoPubSK, autoID, dbPrivSK);

        String sql ="INSERT INTO autos(id,publickey,certificate) VALUES(?,?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)){
            pstmt.setString(1, new String(autoID));
            pstmt.setString(2, conv.publicToString(autoPubSK));
            pstmt.setString(3, new String(autoCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        // Private key and certificate must be send to auto
        //byte[] message = prepareMessage(autoPrivSK, autoCERT);
        return new Auto(autoID, autoCERT, autoPrivSK);
        //send(auto, message);
    }

    ReceptionTerminal generateTerminal(){
        convertKey conv = new convertKey();
        Object [] rtKeyPair = generateKeyPair();
        PublicKey rtPubSK = (PublicKey) rtKeyPair[0];
        PrivateKey rtPrivSK = (PrivateKey) rtKeyPair[1];
        byte[] rtID = UUID.randomUUID().toString().getBytes();
        byte[] rtCERT = issueCertificate(rtPubSK, rtID, dbPrivSK);

        String sql ="INSERT INTO terminals(id,publickey,certificate) VALUES(?,?,?)";

        try ( PreparedStatement pstmt = conn.prepareStatement(sql)){
            pstmt.setString(1, new String(rtID));
            pstmt.setString(2, conv.publicToString(rtPubSK));
            pstmt.setString(3, new String(rtCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        // and send the info back
        //private key and certificate must be send to terminal
        return new ReceptionTerminal(rtID, rtCERT, this, rtPrivSK);
        //byte[] message = prepareMessage(rtPrivSK, rtCERT);
        //send(terminal, message);

    }

    public static void main(String[] args) {
        Database db = new Database();
        ReceptionTerminal rt = db.generateTerminal();
        Auto auto = db.generateAuto();
        Smartcard sc = db.generateCard();
        SmartcardGUI gui = new SmartcardGUI(sc, auto, rt);
        gui.launch();
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
