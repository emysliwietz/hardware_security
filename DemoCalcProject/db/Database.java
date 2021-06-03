package db;

import Auto.Auto;
import Interfaces.CommunicatorExtended;
import Interfaces.KeyWallet;
import Smartcard.Smartcard;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import gui.SmartcardGUI;
import javacard.framework.AID;
import javacard.security.*;
import javafx.application.Application;
import receptionTerminal.ReceptionTerminal;
import rsa.CryptoImplementationExtended;
import rsa.RSACrypto;

import java.io.File;
import java.nio.ByteBuffer;
import java.sql.*;
import java.util.UUID;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 * @author Laura Philipse
 * @author Alessandra van Veen
 */
public class Database extends CommunicatorExtended {

    public PublicKey dbPubSK;
    protected PrivateKey dbPrivSK;
    protected byte[] databaseID;
    protected DatabaseCrypto dc;
    ConvertKey conv = new ConvertKey();
    CardSimulator smartcard = new CardSimulator();
    private Connection conn;


    public Database() {
        conn = null;

        try {
            Class.forName("org.sqlite.JDBC");
            File currentDir = new File("");
            String url = "jdbc:sqlite:" + currentDir.getAbsolutePath().replace("\\", "\\\\") + "/DemoCalcProject/db/CarCompany.db";
            conn = DriverManager.getConnection(url);
        } catch (Exception e) {
            System.err.println(e.getClass().getName() + ": " + e.getMessage());
            System.exit(0);
        }

        setKeys();
        clearAutos(); //Clear autos otherwise program may crash

        dc = new DatabaseCrypto(databaseID, null);
        byte[] dbCERT = issueCertificate(dbPubSK, databaseID, dbPrivSK); //rc = null
        dc.setCertificate(dbCERT);
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

    public Object[] generateKeyPair() {
        KeyPair kp = new KeyPair(KeyPair.ALG_RSA, (short) 512);
        kp.genKeyPair();
        RSAPublicKey publickey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privatekey = (RSAPrivateKey) kp.getPrivate();
        Object[] keyPair = new Object[2];
        keyPair[0] = publickey;
        keyPair[1] = privatekey;
        return keyPair;
    }

    /**
     * @return byte array of shape: 0-127: Encoded public key; 128-132: id, 133-136: length of signed hash, 137-end: signed hash
     */
    //TODO: Where is the end?
    public byte[] issueCertificate(PublicKey pubk, byte[] id, PrivateKey sk) {
        byte[] toHash = concatBytes(pubkToBytes(pubk), id);
        byte[] signedHash = dc.sign(toHash);
        return concatBytes(toHash, intToByteArray(signedHash.length), signedHash);
    }

    /**
     * get public key of database
     */
    public PublicKey getDbPubSK() {
        return dbPubSK;
    }

    /**
     * Get and set the database keys and id
     */
    private void setKeys() {
        ConvertKey conv = new ConvertKey();
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
                    pstmt.setString(1, conv.toHexString(databaseID));
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

    private void clearAutos() {
        String sql = "DELETE FROM autos";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * assign a car to the cardID and send the car info to the terminal
     */
    public void carAssign(ReceptionTerminal reception) {
        ByteBuffer response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssign");
            return;
        }


        byte[] cardID = new byte[ID_LEN];
        response.get(cardID, 0, ID_LEN);//Get card ID so DB knows which car is assigned to which card

        String autoID = null;

        String sqlFindCar = "SELECT a.* FROM autos a LEFT JOIN rentrelations r ON a.id = r.autoID " +
                "/*WHERE r.autoID IS NULL*/ ORDER BY random() LIMIT 1"; //Store link between auto and card

        byte[] autoCert = null;

        try (
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sqlFindCar)) {

            autoID = rs.getString("id");
            autoCert = conv.fromHexString(rs.getString("certificate"));
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        if (autoID == null) { //If no car available
            errorState("No car found");
            return;
        }

        String sqlSetRelation = "INSERT INTO rentRelations(autoID, cardID) VALUES(?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sqlSetRelation)) {
            pstmt.setString(1, autoID);
            pstmt.setString(2, conv.toHexString(cardID));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        msgBuf.clear().rewind();
        clearBuf(msgBuf);
        msgBuf.put(autoCert);
        send(reception, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        //Potentially get confirmation from terminal that they received it? or do we already ack stuff TODO
    }

    /**
     * remove car assignment from rentrelations table
     */
    public void carUnassign(ReceptionTerminal reception) {
        ByteBuffer response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carUnassign");
            return;
        }
        byte[] cardID = new byte[ID_LEN];
        response.get(cardID, 0, ID_LEN);

        String sql = "DELETE FROM rentRelations WHERE cardID = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, conv.toHexString(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String confirmation = conv.toHexString(cardID) + " has been removed from Rent Relations.";
        byte[] message = prepareMessage(confirmation);
        msgBuf.put(message);
        send(reception, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        //Terminal might need to receive this message. We'll fix later. :) TODO
    }

    /**
     * delete card from database
     */
    public void deleteCard(ReceptionTerminal reception) {
        ByteBuffer response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carUnassign");
            return;
        }
        byte[] cardID = new byte[ID_LEN];
        response.get(cardID, 0, ID_LEN);

        String sql = "DELETE FROM cards WHERE id = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, conv.toHexString(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String sql2 = "DELETE FROM rentrelations WHERE id = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql2)) {

            // set the corresponding param
            pstmt.setString(1, conv.toHexString(cardID));
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        String confirmation = conv.toHexString(cardID) + " has been removed from cards.";
        byte[] message = prepareMessage(confirmation);
        msgBuf.put(message);
        send(reception, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
    }

    /**
     * generate a smartcard
     */
    public void generateCard(ReceptionTerminal reception) {

        // Create simulator
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();

        // Install applet
        AID scAID = AIDUtil.create(SC_APPLET_AID);
        simulator.installApplet(scAID, Smartcard.class);
        simulator.transmitCommand(SELECT_APDU);

        Object[] scKeyPair = generateKeyPair();
        PublicKey scPubSK = (PublicKey) scKeyPair[0];
        PrivateKey scPrivSK = (PrivateKey) scKeyPair[1];
        byte[] scID = dc.generateID();
        byte[] scCERT = issueCertificate(scPubSK, scID, dbPrivSK);

        String sql = "INSERT INTO cards(id,publickey,certificate) VALUES(?,?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, conv.toHexString(scID));
            pstmt.setString(2, conv.publicToString(scPubSK));
            pstmt.setString(3, conv.toHexString(scCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        //byte[] cardID, int certLength, byte[] cardCertificate, byte[] privateKeyEncoded
        int certLen = scCERT.length;
        int ibLen = 5 + 4 + scCERT.length + privkToBytes(scPrivSK).length + KEY_LEN;
        ByteBuffer installBuf = ByteBuffer.allocate(ibLen);
        installBuf.put(scID);
        installBuf.putInt(scCERT.length);
        System.out.println(scCERT.length);
        System.out.println(getInt(installBuf.array(), ID_LEN));
        installBuf.put(scCERT);
        installBuf.put(privkToBytes(scPrivSK));
        installBuf.put(pubkToBytes(dbPubSK));
        send(reception, installBuf);

    }

    /**
     * generate a car
     */
    public Auto generateAuto() {
        Object[] autoKeyPair = generateKeyPair();
        PublicKey autoPubSK = (PublicKey) autoKeyPair[0];
        PrivateKey autoPrivSK = (PrivateKey) autoKeyPair[1];
        byte[] autoID = dc.generateID();
        byte[] autoCERT = issueCertificate(autoPubSK, autoID, dbPrivSK);

        String sql = "INSERT INTO autos(id,publickey,certificate) VALUES(?,?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, conv.toHexString(autoID));
            pstmt.setString(2, conv.publicToString(autoPubSK));
            pstmt.setString(3, conv.toHexString(autoCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return new Auto(autoID, autoCERT, autoPrivSK, dbPubSK, smartcard);
    }

    /**
     * generate a reception terminal
     */
    public ReceptionTerminal generateTerminal() {
        Object[] rtKeyPair = generateKeyPair();
        PublicKey rtPubSK = (PublicKey) rtKeyPair[0];
        PrivateKey rtPrivSK = (PrivateKey) rtKeyPair[1];
        byte[] rtID = dc.generateID();
        byte[] rtCERT = issueCertificate(rtPubSK, rtID, dbPrivSK);

        String sql = "INSERT INTO terminals(id,publickey,certificate) VALUES(?,?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, conv.toHexString(rtID));
            pstmt.setString(2, conv.publicToString(rtPubSK));
            pstmt.setString(3, conv.toHexString(rtCERT));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return new ReceptionTerminal(rtID, rtCERT, this, rtPrivSK, smartcard);

    }

    /**
     * check if a card is blocked, e.g. it does not exist in the database
     */
    public boolean isBlocked(byte[] cardID) {
        String sql = "SELECT id FROM cards WHERE id = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, conv.toHexString(cardID));
            ResultSet rs = pstmt.executeQuery();
            //If the cardID is not listed
            return !rs.next();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return false;
    }

    private class DatabaseCrypto extends CryptoImplementationExtended {

        public DatabaseCrypto(byte[] databaseID, byte[] databaseCertificate) {
            super.ID = databaseID;
            super.certificate = databaseCertificate;
            DatabaseWallet dbWallet = new DatabaseWallet();
            dbWallet.storePrivateKey(dbPrivSK);
            super.rc = dbWallet;
        }

        private void setCertificate(byte[] cert) {
            super.certificate = cert;
        }

        private class DatabaseWallet extends RSACrypto implements KeyWallet {

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
