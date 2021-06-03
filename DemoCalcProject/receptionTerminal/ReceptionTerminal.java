package receptionTerminal;

import Interfaces.CommunicatorExtended;
import Interfaces.KeyWallet;
import Smartcard.Smartcard;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import db.Database;
import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import rsa.CryptoImplementationExtended;
import rsa.RSACrypto;
import utility.Logger;

import javax.smartcardio.*;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 * @author Laura Philipse
 * @author Alessandra van Veen
 */
public class ReceptionTerminal extends CommunicatorExtended {

    public PublicKey dbPubSK;
    public PublicKey scPubSK;
    public int kilometerage;
    protected ByteBuffer initBuffer;
    private final RTCrypto rtc;
    private short termNonce; //Placeholder
    private short scNonce; //Placeholder
    private byte[] cardID; //TEMP see above
    private final Database database; //who knows at this point
    private final Logger rtLogger;
    private int offset;
    private final CardSimulator smartcard;
    private final CardTerminals cardTerminals; //= CardTerminalSimulator.terminals(Arrays.toString(rtc.getID()));
    private final CardTerminal rtTerminal; //= cardTerminals.getTerminal(Arrays.toString(rtc.getID()));


    public ReceptionTerminal(byte[] rtID, byte[] rtCertificate, Database db, PrivateKey privateKey, CardSimulator smartcard) {
        rtc = new receptionTerminal.ReceptionTerminal.RTCrypto(rtID, rtCertificate, privateKey);
        File logFile = new File(Base64.getEncoder().encodeToString(rtID) + "_reception_terminal_log.log");
        rtLogger = new Logger(logFile);
        super.logger = rtLogger;
        database = db;
        dbPubSK = db.getDbPubSK();
        this.smartcard = smartcard;
        cardTerminals = CardTerminalSimulator.terminals(Arrays.toString(rtc.getID()));
        rtTerminal = cardTerminals.getTerminal(Arrays.toString(rtc.getID()));
        (new SimulatedCardThread()).start();
    }

    /**
     * protocol 4 - car return and kilometerage check
     */
    public int carReturnInitiate() throws ProcessFailedException {
        CommandAPDU commandAPDU = new CommandAPDU(CARD_PROC, CAR_RETURN_START, 0, 0, 256);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return -1;
        }
        return carReturn(apdu);
    }

    /**
     * protocol 4 - car return and kilometerage check
     */
    public int carReturn(ResponseAPDU apdu) throws ProcessFailedException {
        if (!cardAuthenticated) {
            errorState("Card is not authenticated");
            rtLogger.warning("Aborting: Card is not authenticated", "CarReturn", cardID);
            return -1;
        }
        offset = ERESPAPDU_CDATA_OFFSET;
        //Message 1
        byte[] msg1 = apdu.getData();

        byte[] carReturnBytes = new byte[10];
        memCpy(carReturnBytes, msg1, offset, 10);
        //msg1.get(carReturnBytes,offset,10);
        offset += 10;
        String carReturn = new String(carReturnBytes, StandardCharsets.UTF_8);
        if (!carReturn.equals("Car Return")) {
            errorState("Wrong command, expected Car Return, got " + carReturn);
            rtLogger.warning("Wrong command, expected Car Return, got " + carReturn, "CarReturn message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return -1;
        }
        short seqNum = getShort(msg1, offset);//msg1.getShort();
        offset += NONCE_LEN;
        if (!rtc.areSubsequentNonces(termNonce, seqNum)) {
            errorState("Wrong sequence number in carReturn message 1");
            rtLogger.fatal("Wrong sequence number", "carReturn message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return -1;
        }
        boolean manipulation = booleanFromByte(msg1[offset]);
        offset += BOOL_LEN;
        int msg1HashSignLen = getInt(msg1, offset);//msg1.getInt();
        offset += INT_LEN;
        byte[] msg1HashSign = new byte[msg1HashSignLen];
        memCpy(msg1HashSign, msg1, offset, msg1HashSignLen);
        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[10 + NONCE_LEN + BOOL_LEN]);
        msg1Cmps.put(carReturnBytes).putShort(seqNum).put(booleanToByteArray(manipulation));
        if (!rtc.verify(msg1Cmps, msg1HashSign, scPubSK)) {
            errorState("Hashes don't match in carReturn message 1");
            rtLogger.fatal("Hashes don't match", "carReturn message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return -1;
        }
        if (manipulation) {
            errorState("Kilometerage on card " + Arrays.toString(cardID) + " might have been manipulated. Please verify");
            rtLogger.warning("Kilometerage on card " + Arrays.toString(cardID) + " might have been manipulated. Please verify", "carReturn message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return -1;
        }

        //Message 2
        short kmmNonce = rtc.generateNonce();
        msgBuf.clear();
        msgBuf.rewind();
        msgBuf.putShort(kmmNonce);
        short seqNum2 = (short) (scNonce + 1);
        msgBuf.putShort(seqNum2);
        byte[] msg2Sign = rtc.sign(concatBytes(shortToByteArray(kmmNonce), shortToByteArray(seqNum2)));
        msgBuf.putInt(msg2Sign.length).put(msg2Sign);
        apdu = sendAPDU(CARD_CONT, CAR_RETURN_M2, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 3
        if (apdu.getSW() == PROC_FAILED){
            rtLogger.fatal("Something went wrong", "carReturn", cardID);
            throw new ProcessFailedException("Something has gone wrong, the car return has failed.");

        }

        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] msg3 = apdu.getData();
        kilometerage = getInt(msg3, offset);//msg3.getInt();
        offset += INT_LEN;
        short kmmNonceResp = getShort(msg3, offset);//msg3.getShort();
        offset += NONCE_LEN;
        if (kmmNonce != kmmNonceResp) {
            errorState("Wrong kilometerage nonce returned");
            rtLogger.fatal("Wrong kilometerage nonce returned", "message 3 carReturn", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return -1;
        }
        short seqNum3 = getShort(msg3, offset);
        offset += NONCE_LEN;
        if (!rtc.areSubsequentNonces(termNonce, seqNum3, 2)) {
            errorState("Wrong sequence number in carReturn message 3");
            rtLogger.fatal("Wrong sequence number", "carReturn message 3", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return -1;
        }
        int msg3HashSignLen = getInt(msg3, offset);//msg3.getInt();
        offset += 4;
        byte[] msg3HashSign = new byte[msg3HashSignLen];
        memCpy(msg3HashSign, msg3, offset, msg3HashSignLen);

        ByteBuffer msg3Cmps = ByteBuffer.wrap(new byte[INT_LEN + NONCE_LEN + NONCE_LEN]);
        msg3Cmps.putInt(kilometerage).putShort(kmmNonceResp).putShort(seqNum3);
        if (!rtc.verify(msg3Cmps, msg3HashSign, scPubSK)) {
            errorState("Hash in carReturn message 3 invalid");
            rtLogger.fatal("Invalid hash", "carReturn message 3", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return -1;
        }

        //Success Message
        msgBuf.clear();
        msgBuf.rewind();
        msgBuf.put(SUCCESS_BYTE).putShort((short) (scNonce + 2));
        byte[] success = {SUCCESS_BYTE};
        byte[] succHash = rtc.sign(concatBytes(success, shortToByteArray((short) (scNonce + 2))));
        msgBuf.putInt(succHash.length).put(succHash);
        sendAPDU(CARD_CONT, CAR_RETURN_MS, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        rtLogger.info("Car returned successfully", "carReturn", cardID);
        //Notify database
        msgBuf.put(cardID);
        Thread t1 = new Thread(() -> send(database, msgBuf));
        Thread t2 = new Thread(() -> database.carUnassign(this));
        t1.start();
        t2.start();
        try {
            t1.join();
            //TODO: t2.join();?????
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        msgBuf.clear();
        msgBuf.rewind();
        cardAuthenticated = false;
        cardID = null;
        return kilometerage;
    }

    /**
     * Protocol 2 - Mutual Authentication between smartcard and reception terminal
     */
    public void cardAuthenticationInitiate() throws AuthenticationFailedException {
        select();
        rtLogger.info("Started Card Authentication", "cardAuthenticationInitiate", cardID);
        if (initBuffer != null) {
            sendAPDU(CARD_INIT, INIT, initBuffer);
            initBuffer.clear();
            initBuffer.rewind();
            initBuffer = null;
        }
        CommandAPDU commandAPDU = new CommandAPDU(CARD_AUTH, AUTH_RECEPTION_START, 0, 0, 512);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return;
        }
        cardAuthentication(apdu);
    }

    /**
     * protocol 2 - mutual authentication between smartcard and reception terminal
     */
    public void cardAuthentication(ResponseAPDU apdu) throws AuthenticationFailedException {
        //Message 1
        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] response = apdu.getData(); //Step 2

        //cardPubSK + cardID = Certificate
        byte[] cardPubSKEncoded = new byte[KEY_LEN];
        memCpy(cardPubSKEncoded, response, offset, KEY_LEN);

        offset += KEY_LEN;
        scPubSK = bytesToPubkey(cardPubSKEncoded);
        cardID = new byte[ID_LEN];
        memCpy(cardID, response, offset, ID_LEN);
        offset += ID_LEN;

        if (database.isBlocked(cardID)) {
            errorState("Card is blocked");
            rtLogger.fatal("Invalid card: Card is blocked", "cardAuthentication message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }

        //Signed hash of certificate
        int cardCertHashSignLen = getInt(response, offset);
        offset += 4;
        byte[] cardCertHashSign = new byte[cardCertHashSignLen];
        memCpy(cardCertHashSign, response, offset, cardCertHashSignLen);
        offset += cardCertHashSignLen;
        scNonce = getShort(response, offset);//response.getShort();

        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[KEY_LEN + ID_LEN]);
        msg1Cmps.put(cardPubSKEncoded).put(cardID);
        if (!rtc.verify(msg1Cmps, cardCertHashSign, dbPubSK)) { //Step 3
            errorState("Hash does not match known card");
            rtLogger.fatal("Invalid certificate: Hash does not match known card", "cardAuthentication message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }

        //Message 2
        termNonce = rtc.generateNonce();
        msgBuf.put(rtc.getCertificate()).putShort(termNonce);
        apdu = sendAPDU(CARD_CONT, AUTH_RECEPTION_M2, msgBuf);

        msgBuf.clear();
        msgBuf.rewind();


        //Step 4
        //Message 3
        if (apdu.getSW() == PROC_FAILED){
            rtLogger.fatal("Something went wrong", "cardAuthentication", cardID);
            throw new AuthenticationFailedException("Something has gone wrong. Authentication between the card and reception has failed.");

        }

        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] response2 = apdu.getData();

        short termNonceResp = getShort(response2, offset);
        offset += 2;
        if (termNonceResp != termNonce) {
            errorState("Wrong nonce in message 3 of cardAuthentication");
            rtLogger.fatal("Wrong nonce", "cardAuthentication message 3", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }

        int receptionNonceHashSignLen = getInt(response2, offset);//response2.getInt();
        offset += 4;
        byte[] receptionNonceHashSign = new byte[receptionNonceHashSignLen];
        memCpy(receptionNonceHashSign, response2, offset, receptionNonceHashSignLen);

        offset += receptionNonceHashSignLen;

        ByteBuffer msg3Cmps = ByteBuffer.wrap(new byte[NONCE_LEN]);
        msg3Cmps.putShort(termNonceResp);
        if (!rtc.verify(msg3Cmps, receptionNonceHashSign, scPubSK)) { //Step 7
            errorState("Invalid hash in message 3 of P2");
            rtLogger.fatal("Invalid Hash", "cardAuthentication message 3", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }

        //Success message
        msgBuf.put(SUCCESS_BYTE);
        byte[] succByte = {SUCCESS_BYTE};
        byte[] nonceCardHashSign = rtc.sign(concatBytes(succByte, shortToByteArray(scNonce)));
        msgBuf.putShort(scNonce).putInt(nonceCardHashSign.length).put(nonceCardHashSign);
        sendAPDU(CARD_CONT, AUTH_RECEPTION_MS, msgBuf);

        //Step 8
        rtLogger.info("Smartcard authenticated successfully", "cardAuthentification", cardID);
        cardAuthenticated = true; //When to make it false again

    }

    /**
     * Protocol 3 - Assignment of car to smartcard
     */
    public void carAssignmentInitiate() throws ProcessFailedException {
        select();
        CommandAPDU commandAPDU = new CommandAPDU(CARD_PROC, CAR_ASSIGNMENT_START, 0, 0, 256);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return;
        }
        carAssignment(apdu);
    }

    /**
     * protocol 3 - assignment of car to smartcard
     */
    public void carAssignment(ResponseAPDU apdu) throws ProcessFailedException {
        if (!cardAuthenticated) { //Step 1
            errorState("Card not authenticated");
            rtLogger.warning("Aborting: Card not authenticated", "carAssignment", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }

        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] response = apdu.getData();
        byte[] requestBytes = new byte[4];
        memCpy(requestBytes, response, offset, 4);
        offset += 4;
        String request = new String(requestBytes, StandardCharsets.UTF_8);
        if (!request.equals("Car?")) {
            errorState("Expected car request");
            rtLogger.fatal("Expected car request, got " + request, "carAssignment", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }
        short seqNum1 = getShort(response, offset);
        offset += 2;
        if (!rtc.areSubsequentNonces(termNonce, seqNum1)) {
            errorState("Wrong sequence number in message 1 of P3");
            rtLogger.fatal("Wrong sequence number", "carAssignment message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.;
            return;
        }

        int giveCarHashSignLen = getInt(response, offset);
        offset += 4;
        byte[] giveCarHashSign = new byte[giveCarHashSignLen];
        memCpy(giveCarHashSign, response, offset, giveCarHashSignLen);

        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[4 + NONCE_LEN]);
        msg1Cmps.put(requestBytes).putShort(seqNum1);
        if (!rtc.verify(msg1Cmps, giveCarHashSign, scPubSK)) { //Step 3
            errorState("Invalid hash in message 1 of P3");
            rtLogger.fatal("Invalid Hash", "carAssingment message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }
        msgBuf.clear().rewind();
        msgBuf.put(cardID);

        //Step 4
        Thread t1 = new Thread(() -> send(database, msgBuf));
        Thread t2 = new Thread(() -> database.carAssign(this));
        t1.start();
        t2.start();
        try {
            t1.join();
            t2.join();
            //TODO: t2.join();?????
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        msgBuf.clear();
        msgBuf.rewind();

        ByteBuffer response2;
        try {
            response2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout database carAssignment");
            rtLogger.warning("Aborting: Timeout", "carAssignment database communication", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }
        byte[] autoPubSKBytes = new byte[KEY_LEN];
        response2.get(autoPubSKBytes, 0, KEY_LEN);
        PublicKey autoPubSK = bytesToPubkey(autoPubSKBytes);
        byte[] autoID = new byte[ID_LEN];
        response2.get(autoID, 0, ID_LEN);
        int autoCertHashSignLen = response2.getInt();
        byte[] autoCertHashSign = new byte[autoCertHashSignLen];
        response2.get(autoCertHashSign, 0, autoCertHashSignLen);

        //Step 5
        msgBuf.put(pubkToBytes(autoPubSK));
        msgBuf.put(autoID).putInt(autoCertHashSignLen).put(autoCertHashSign).putShort((short) (scNonce + 1));
        byte[] msg2Sign = rtc.sign(concatBytes(pubkToBytes(autoPubSK), autoID, autoCertHashSign, shortToByteArray((short) (scNonce + 1))));
        msgBuf.putInt(msg2Sign.length).put(msg2Sign);
        apdu = sendAPDU(CARD_CONT, CAR_ASSIGNMENT_M2, msgBuf);

        //Step 6
        msgBuf.clear();
        msgBuf.rewind();

        if (apdu.getSW() == PROC_FAILED){
            rtLogger.fatal("Something went wrong", "carAssignment", cardID);
            throw new ProcessFailedException("Something has gone wrong, the car assignment has failed.");

        }

        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] succMsg = apdu.getData();

        byte success = succMsg[0];
        offset++;
        if (success != SUCCESS_BYTE) {
            errorState("Wrong byte code, expected 0xFF");
            rtLogger.warning("Wrong byte, expected 0xFF, got " + success, "carAssignment", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }
        short seqNum2 = getShort(succMsg, offset);
        offset += NONCE_LEN;
        if (!rtc.areSubsequentNonces(termNonce, seqNum2, 2)) {
            errorState("Wrong sequence number in success message of P3");
            rtLogger.fatal("Wrong sequence number ", "carAssignment success message", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }
        int succHashSignLen = getInt(succMsg, offset);
        offset += 4;
        byte[] succHashSign = newB(succHashSignLen);
        memCpy(succHashSign, succMsg, offset, succHashSignLen);

        ByteBuffer succMsgCmps = ByteBuffer.wrap(newB(BOOL_LEN + NONCE_LEN));
        succMsgCmps.put(success).putShort(seqNum2);
        if (!rtc.verify(succMsgCmps, succHashSign, scPubSK)) {
            errorState("Invalid hash in success message of P3");
            rtLogger.fatal("Invalid hash", "carAssignment success message", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }
        rtLogger.info("Car " + Arrays.toString(autoID) + " successfully assigned", "carAssignment", cardID);
        cardID = null;
        cardAuthenticated = false;
        deselect();
    }

    /**
     * protocol 6 - card blocking
     */
    public void blockCard(byte[] cardID) {
        ByteBuffer blockBuf = newBB(ID_LEN);
        blockBuf.put(cardID); //cardID is null -> Which card will it even block?
        send(database, blockBuf);
        database.deleteCard(this);
        ByteBuffer resp;
        try {
            resp = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return;
        }

        int msgLen = ID_LEN + 29;
        byte[] msg = new byte[msgLen];
        resp.get(msg, 0, msgLen);
        String request = new String(msg, StandardCharsets.UTF_8);
        //String request = Base64.getEncoder().encodeToString(msg);
        //System.out.println("bytebuffer: " + StandardCharsets.UTF_8.decode(resp).toString());
        //System.out.println("DB msg: " + request);
        //System.out.println("rt msg: " + new String(cardID) + " has been removed from cards.");
        if (!request.equals(new String(cardID) + " has been removed from cards.")) { //TODO this does not work
            errorState("Database returned wrong message after blocking card");
            rtLogger.fatal("Database returned wrong message", "blockCard", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            return;
        }
        rtLogger.info("Card blocked successfully", "blockCard", cardID);
    }

    public void initialDataForSC() {
        try {
            initBuffer = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return;
        }
        System.out.println(getInt(initBuffer.array(), 5));
    }

    private void select() {
        try {
            if (rtTerminal.isCardPresent()) {
                return;
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
        smartcard.assignToTerminal(rtTerminal);
        try {
            Card card = rtTerminal.connect("*");
            applet = card.getBasicChannel();
            ResponseAPDU resp = applet.transmit(SELECT_APDU);
            if (resp.getSW() != 0x9000) {
                throw new Exception("Select failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void deselect() {
        try {
            if (!rtTerminal.isCardPresent()) {
                rtLogger.warning("Tried to deselect card that is not present", "Deselect", cardID);
                return;
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
        smartcard.assignToTerminal(null);
        applet = null;
    }

    private static class RTCrypto extends CryptoImplementationExtended {

        public RTCrypto(byte[] rtID, byte[] rtCertificate, PrivateKey privateKey) {
            super.ID = rtID;
            super.certificate = rtCertificate;
            super.rc = new RTWallet();
            ((KeyWallet) super.rc).storePrivateKey(privateKey);
        }

        private static class RTWallet extends RSACrypto implements KeyWallet {

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

    class SimulatedCardThread extends Thread {
        public void run() {
            AID scAppletAID = AIDUtil.create(SC_APPLET_AID);
            smartcard.installApplet(scAppletAID, Smartcard.class);
            select();
        }
    }
}
