package db;

import Interfaces.Communicator;
import receptionTerminal.ReceptionTerminal;
import rsa.*;

import java.security.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.*;
import java.util.UUID;


public class Database extends CryptoImplementation implements Communicator {
    private Connection c;
    private PublicKey dbPubSK;
    private PrivateKey dbPrivSK;


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
        c = null;

        //source for now: https://www.tutorialspoint.com/sqlite/sqlite_java.htm
        //So I know how to find the tutorial again
        try{
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:CarCompany.db"); //doesnt work yet but so we have the thing
        } catch(Exception e){
            System.err.println(e.getClass().getName() + ": " + e.getMessage() );
            System.exit(0);
        }

        Object [] dbKeyPair = generateKeyPair(); //maybe also get this from the database?
        dbPubSK = (PublicKey) dbKeyPair[0];
        dbPrivSK = (PrivateKey) dbKeyPair[1];
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
        byte[] cardID = responseData[0].getBytes(); //Get card ID so DB knows which car is assigned to which card

        //Some function so it stores the link between an autoID and a cardID

        String autoID = null;

        String sqlFindCar = "SELECT a.* FROM autos a LEFT JOIN rentrelations r ON a.id = r.autoID " +
                "WHERE r.autoID IS NULL ORDER BY random() LIMIT 1";

        ResultSet rs = null;

        try (Connection conn = this.connect();
            Statement stmt = conn.createStatement();
            rs = stmt.executeQuery(sqlFindCar)){

                autoID = rs.getString("id");
            }
        catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        if (autoID == null){ //If no car available
            errorState("No car found");
            return;
        }

        String sqlSetRelation ="INSERT INTO rentRelations(autoID, cardID) VALUES(?,?)";

        try (Connection conn = this.connect(); //Store in DB
             Preparedstatement pstmt = conn.prepareStatement(sqlSetRelation)){
            //Potential error: Byte[] to String
            pstmt.setString(1, autoID.toString());
            pstmt.setString(2, cardID.toString());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        byte[] autoCert = rs.getString("certificate").getBytes(); //does this convert work? We dont know yet
        byte[] message = prepareMessage(autoCert);
        send(reception, message);
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
        byte[] cardID = responseData[0].getBytes();

        String sql = "DELETE FROM rentRelations WHERE cardID = ?";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, cardID.toString());
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

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
        byte[] scCERT = issueCertificate(scPubSK, scID, dbPrivSK);

        String sql ="INSERT INTO cards(id,publickey,certificate) VALUES(?,?,?)";

        try (Connection conn = this.connect(); //Store in DB
                Preparedstatement pstmt = conn.prepareStatement(sql)){
            //Potential error: Byte[] to String
            pstmt.setString(1, scID.toString());
            pstmt.setString(2, scPubSK.toString());
            pstmt.setString(3, scCERT.toString());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        // and send the info back
    }
    void generateAuto(){
        Object [] autoKeyPair = generateKeyPair();
        PublicKey autoPubSK = (PublicKey) autoKeyPair[0];
        PrivateKey autoPrivSK = (PrivateKey) autoKeyPair[1];
        byte[] autoID = UUID.randomUUID().toString().getBytes();
        byte[] autoCERT = issueCertificate(autoPubSK, autoID, dbPrivSK);

        String sql ="INSERT INTO autos(id,publickey,certificate) VALUES(?,?,?)";

        try (Connection conn = this.connect(); //Store in DB
             Preparedstatement pstmt = conn.prepareStatement(sql)){
            //Potential error: Byte[] to String
            pstmt.setString(1, autoID.toString());
            pstmt.setString(2, autoPubSK.toString());
            pstmt.setString(3, autoCERT.toString());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        // and send the info back
    }

    void generateTerminal(){
        Object [] rtKeyPair = generateKeyPair();
        PublicKey rtPubSK = (PublicKey) rtKeyPair[0];
        PrivateKey rtPrivSK = (PrivateKey) rtKeyPair[1];
        byte[] rtID = UUID.randomUUID().toString().getBytes();
        byte[] rtCERT = issueCertificate(rtPubSK, rtID, dbPrivSK);

        String sql ="INSERT INTO terminals(id,publickey,certificate) VALUES(?,?,?)";

        try (Connection conn = this.connect(); //Store in DB
             Preparedstatement pstmt = conn.prepareStatement(sql)){
            //Potential error: Byte[] to String
            pstmt.setString(1, rtID.toString();
            pstmt.setString(2, rtPubSK.toString());
            pstmt.setString(3, rtCERT.toString());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        // and send the info back

    }
}
