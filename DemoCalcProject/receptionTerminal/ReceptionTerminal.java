package receptionTerminal;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.CommunicatorExtended;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import db.Database;
import javacard.framework.AID;
import rsa.CryptoImplementation;
import rsa.RSACrypto;
import utility.Logger;

import javax.smartcardio.*;
import java.io.File;
import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import static utility.Util.print;

/**
 @author Matti Eisenlohr
 @author Egidius Mysliwietz
 @author Laura Philipse
 @author Alessandra van Veen
 */
public class ReceptionTerminal extends CommunicatorExtended {

    private RTCrypto rtc;
    public PublicKey dbPubSK;
    private short termNonce; //Placeholder
    private short scNonce; //Placehoder
    private byte[] cardID; //TEMP see above
    private Database database; //who knows at this point
    public PublicKey scPubSK;
    public int kilometerage;
    private Logger rtLogger;
    protected ByteBuffer initBuffer;
    private int offset;
    private CardSimulator smartcard;
    private CardTerminals cardTerminals; //= CardTerminalSimulator.terminals(Arrays.toString(rtc.getID()));
    private CardTerminal rtTerminal; //= cardTerminals.getTerminal(Arrays.toString(rtc.getID()));



    public ReceptionTerminal(byte[] rtID, byte[] rtCertificate, Database db, PrivateKey privateKey, CardSimulator smartcard) {
        rtc = new receptionTerminal.ReceptionTerminal.RTCrypto(rtID, rtCertificate, privateKey);
        File logFile = new File(Base64.getEncoder().encodeToString(rtID)+"_reception_terminal_log.txt");
        rtLogger = new Logger(logFile);
        super.logger = rtLogger;
        database = db;
        dbPubSK = db.getDbPubSK();
        this.smartcard = smartcard;
        cardTerminals = CardTerminalSimulator.terminals(Arrays.toString(rtc.getID()));
        rtTerminal = cardTerminals.getTerminal(Arrays.toString(rtc.getID()));
        (new SimulatedCardThread()).start();
    }

    /**protocol 4 - car return and kilometerage check */
    public int carReturnInitiate(){
        CommandAPDU commandAPDU = new CommandAPDU(CARD_PROC,CAR_RETURN_START,0,0,256);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return -1;
        }
        return carReturn(apdu);
    }

    /**protocol 4 - car return and kilometerage check */
    public int carReturn(ResponseAPDU apdu){
        if (!cardAuthenticated){
            errorState("Card is not authenticated");
            rtLogger.warning("Aborting: Card is not authenticated", "CarReturn", cardID);
            return -1;
        }
        offset = ERESPAPDU_CDATA_OFFSET;
        //Message 1
        byte[] msg1 = apdu.getData();
        /*try {
            msg1 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout message1 carReturn");
            rtLogger.warning("Timeout while waiting for message", "CarReturn message 1", cardID);
            return -1;
        }*/
        byte[] carReturnBytes = new byte[10];
        memCpy(carReturnBytes,msg1,offset,10);
        //msg1.get(carReturnBytes,offset,10);
        offset+=10;
        String carReturn = new String(carReturnBytes, StandardCharsets.UTF_8);
        if (!carReturn.equals("Car Return")) {
            errorState("Wrong command, expected Car Return, got " + carReturn);
            rtLogger.warning("Wrong command, expected Car Return, got " + carReturn, "CarReturn message 1", cardID);
            return -1;
        }
        short seqNum = getShort(msg1,offset);//msg1.getShort();
        offset+=2;
        if(!rtc.areSubsequentNonces(termNonce,seqNum)){
            errorState("Wrong sequence number in carReturn message 1");
            rtLogger.fatal("Wrong sequence number", "carReturn message 1", cardID);
            return -1;
        }
        boolean manipulation = booleanFromByte(msg1[offset]);
        offset++;
        int msg1HashSignLen = getInt(msg1,offset);//msg1.getInt();
        offset+=4;
        byte[] msg1HashSign = new byte[msg1HashSignLen];
        memCpy(msg1HashSign,msg1,offset,msg1HashSignLen);
        //msg1.get(msg1HashSign,offset,msg1HashSignLen);
        //byte[] msg1Hash = rtc.unsign(msg1HashSign, scPubSK);
        //byte[] msg1ConfHash = rtc.createHash(concatBytes(carReturn.getBytes(StandardCharsets.UTF_8), shortToByteArray(seqNum), booleanToByteArray(manipulation)));
        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[13]);
        msg1Cmps.put(carReturnBytes).putShort(seqNum).put(booleanToByteArray(manipulation));
        if(!rtc.verify(msg1Cmps,msg1HashSign,scPubSK)){
            errorState("Hashes don't match in carReturn message 1");
            rtLogger.fatal("Hashes don't match", "carReturn message 1", cardID);
            return -1;
        }
        if (manipulation){
            errorState("Kilometerage on card " + Arrays.toString(cardID) + " might have been manipulated. Please verify");
            rtLogger.warning("Kilometerage on card " + Arrays.toString(cardID) + " might have been manipulated. Please verify", "carReturn message 1", cardID);
            return -1;
        }

        //Message 2
        short kmmNonce = rtc.generateNonce();
        msgBuf.clear();
        msgBuf.rewind();
        msgBuf.putShort(kmmNonce);
        short seqNum2 = (short) (scNonce+1);
        msgBuf.putShort(seqNum2);
        byte[] msg2Sign = rtc.sign(concatBytes(shortToByteArray(kmmNonce), shortToByteArray(seqNum2)));
        msgBuf.putInt(msg2Sign.length).put(msg2Sign);
        apdu = sendAPDU(CARD_CONT,CAR_RETURN_M2,msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 3
        offset=ERESPAPDU_CDATA_OFFSET;
        byte[] msg3 = apdu.getData();
        /*try {
            msg3 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in message3 carReturn response");
            rtLogger.warning("Timeout while waiting for response", "message3 carReturn", cardID);
            return -1;
        }*/
        kilometerage = getInt(msg3,offset);//msg3.getInt();
        offset+=4;
        short kmmNonceResp = getShort(msg3,offset);//msg3.getShort();
        offset+=2;
        if(kmmNonce != kmmNonceResp){
            //TODO: Error
            errorState("Wrong kilometerage nonce returned");
            rtLogger.fatal("Wrong kilometerage nonce returned", "message 3 carReturn", cardID);
            return -1;
        }
        short seqNum3 = getShort(msg3,offset);//msg3.getShort();
        offset+=2;
        if(!rtc.areSubsequentNonces(termNonce,seqNum3,2)){
            errorState("Wrong sequence number in carReturn message 3");
            rtLogger.fatal("Wrong sequence number", "carReturn message 3", cardID);
            return -1;
        }
        int msg3HashSignLen = getInt(msg3,offset);//msg3.getInt();
        offset+=4;
        byte[] msg3HashSign = new byte[msg3HashSignLen];
        memCpy(msg3HashSign,msg3,offset,msg3HashSignLen);
        //msg3.get(msg3HashSign,offset,msg3HashSignLen);
        //byte[] msg3Hash = rtc.unsign(msg3HashSign,scPubSK);
        //byte[] validMsg3Hash = rtc.createHash(concatBytes(intToByteArray(kilometerage), shortToByteArray(kmmNonceResp), shortToByteArray(seqNum3)));
        ByteBuffer msg3Cmps = ByteBuffer.wrap(new byte[8]);
        msg3Cmps.putInt(kilometerage).putShort(kmmNonceResp).putShort(seqNum3);
        if(!rtc.verify(msg3Cmps,msg3HashSign,scPubSK)){
            //TODO: Error
            errorState("Hash in carReturn message 3 invalid");
            rtLogger.fatal("Invalid hash", "carReturn message 3", cardID);
            return -1;
        }

        //Success Message
        msgBuf.clear();
        msgBuf.rewind();
        msgBuf.put(SUCCESS_BYTE).putShort((short) (scNonce + 2));
        byte[] success = {SUCCESS_BYTE};
        byte[] succHash = rtc.sign(concatBytes(success, shortToByteArray((short) (scNonce + 2))));
        msgBuf.putInt(succHash.length).put(succHash);
        sendAPDU(CARD_CONT,CAR_RETURN_MS,msgBuf);
        //send(sc, msgBuf);
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

    /**Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    public void cardAuthenticationInitiate(){
        select();
        rtLogger.info("Started Card Authentication", "cardAuthenticationInitiate", cardID);
        if (initBuffer != null){
            sendAPDU(CARD_INIT,INIT,initBuffer);
            initBuffer.clear();
            initBuffer.rewind();
            initBuffer = null;
        }
        //isBlocked MOVED TO cardAuthentication
        CommandAPDU commandAPDU = new CommandAPDU(CARD_AUTH,AUTH_RECEPTION_START,0,0,512);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return;
        }
        cardAuthentication(apdu);
    }

    /** protocol 2 - mutual authentication between smartcard and reception terminal */
    public void cardAuthentication(ResponseAPDU apdu){
        //Message 1
        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] response = apdu.getData(); //Step 2
        /*try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response cardAuthentication");
            rtLogger.warning("Timeout while waiting for message", "cardAuthentication message 1", cardID);
            return;
        }*/

        //cardPubSK + cardID = Certificate
        byte[] cardPubSKEncoded = new byte[KEY_LEN];
        memCpy(cardPubSKEncoded,response,offset,KEY_LEN);
        //response.get(cardPubSKEncoded,offset,KEY_LEN);
        offset+=KEY_LEN;
        scPubSK = bytesToPubkey(cardPubSKEncoded);
        cardID = new byte[5];
        memCpy(cardID,response,offset,5);
        //response.get(cardID,offset,5);
        offset += 5;

        if(database.isBlocked(cardID)){ //Moved to down under otherwise no card ID exists yet.
            //Issue, does not work. Not sure why yet. TODO
            CommandAPDU commandAPDU = new CommandAPDU(CARD_EOL,BLOCK,0,0,0);
            ResponseAPDU apduNew;
            try {
                apduNew = applet.transmit(commandAPDU);
            } catch (CardException e) {
                e.printStackTrace();
                return;
            }
            return;
        }

        //Signed hash of certificate
        int cardCertHashSignLen = getInt(response,offset);//response.getInt();
        offset+=4;
        byte[] cardCertHashSign = new byte[cardCertHashSignLen];
        memCpy(cardCertHashSign,response,offset,cardCertHashSignLen);
        offset+=cardCertHashSignLen;
        //response.get(cardCertHashSign,offset,cardCertHashSignLen);
        scNonce = getShort(response,offset);//response.getShort();
        //byte[] cardCertHash = rtc.unsign(cardCertHashSign, dbPubSK);
        //byte[] cardIDPubSKHash = rtc.createHash(prepareMessage(cardPubSK, cardID));
        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[KEY_LEN+5]);
        msg1Cmps.put(cardPubSKEncoded).put(cardID);
        if (!rtc.verify(msg1Cmps,cardCertHashSign,dbPubSK)){ //Step 3
            errorState("Hash does not match known card");
            rtLogger.fatal("Invalid certificate: Hash does not match known card", "cardAuthentication message 1", cardID);
            return;
        }

        //Message 2
        termNonce = rtc.generateNonce();
        msgBuf.put(rtc.getCertificate()).putShort(termNonce);
        print(Arrays.toString(rtc.getCertificate()));
        print(Arrays.toString(shortToByteArray(termNonce)));
        apdu = sendAPDU(CARD_CONT,AUTH_RECEPTION_M2,msgBuf);
        //send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        //Step 4

        //Message 3
        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] response2 = apdu.getData(); //empty!
        /*try {
            response2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response 2 cardAuthentication");
            rtLogger.warning("Aborting: Timeout", "cardAuthentication response 2", cardID);
            return;
        }*/

        short termNonceResp = getShort(response2,offset);//response2.getShort(); //ERROR HERE, RESPONSE2 EMPTY
        offset+=2;
        if(termNonceResp != termNonce){
            errorState("Wrong nonce in message 3 of cardAuthentication");
            rtLogger.fatal("Wrong nonce", "cardAuthentication message 3", cardID);
            return;
        }

        int receptionNonceHashSignLen = getInt(response2,offset);//response2.getInt();
        offset+=4;
        byte[] receptionNonceHashSign = new byte[receptionNonceHashSignLen];
        memCpy(receptionNonceHashSign,response2,offset,receptionNonceHashSignLen);
        //response2.get(receptionNonceHashSign,offset,receptionNonceHashSignLen);
        offset+=receptionNonceHashSignLen;
        //byte[] receptionNonceHash = rtc.unsign(receptionNonceHashSign, cardPubSK);
        //byte[] nonceReceptionHashValid = rtc.createHash(shortToByteArray(termNonce));
        ByteBuffer msg3Cmps = ByteBuffer.wrap(new byte[2]);
        msg3Cmps.putShort(termNonceResp);
        if (!rtc.verify(msg3Cmps,receptionNonceHashSign,scPubSK)){ //Step 7
            errorState("Invalid hash in message 3 of P2");
            rtLogger.fatal("Invalid Hash", "cardAuthentication message 3", cardID);
            return;
        }

        //Success message
        msgBuf.put(SUCCESS_BYTE);
        byte[] succByte = {SUCCESS_BYTE};
        byte[] nonceCardHashSign = rtc.sign(concatBytes(succByte, shortToByteArray(scNonce)));
        msgBuf.putShort(scNonce).putInt(nonceCardHashSign.length).put(nonceCardHashSign);
        sendAPDU(CARD_CONT,AUTH_RECEPTION_MS,msgBuf);
        //send(sc, msgBuf); //Step 8
        rtLogger.info("Smartcard authenticated successfully", "cardAuthentification", cardID);
        cardAuthenticated = true; //When to make it false again

    }

    /** Protocol 3 - Assignment of car to smartcard */
    public void carAssignmentInitiate(){
        select();
        CommandAPDU commandAPDU = new CommandAPDU(CARD_PROC,CAR_ASSIGNMENT_START,0,0,256);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return;
        }
        carAssignment(apdu);
    }

    /** protocol 3 - assignment of car to smartcard */
    public void carAssignment(ResponseAPDU apdu){
        if (!cardAuthenticated){ //Step 1
            rtLogger.warning("Aborting: Card not authenticated", "carAssignment", cardID);
            //APDU RESPONSE BYTE:
            return; //TODO: Placeholder
        }
        inputQueue.clear();

        offset=ERESPAPDU_CDATA_OFFSET;
        //ByteBuffer response = ByteBuffer.wrap(apdu.getData());
        byte[] response = apdu.getData();
        /*try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssignment");
            rtLogger.warning("Aborting: Timeout", "carAssignment message 1", cardID);
            return;
        }*/
        byte[] requestBytes = new byte[4];
        memCpy(requestBytes,response, offset,4);
        offset+=4;
        String request = new String(requestBytes, StandardCharsets.UTF_8);
        if (!request.equals("Car?")){
            errorState("Expected car request");
            rtLogger.fatal("Expected car request, got " + request, "carAssignment", cardID);
            return;
        }
        short seqNum1 = getShort(response, offset);
        offset+=2;
        if(!rtc.areSubsequentNonces(termNonce, seqNum1)){
            errorState("Wrong sequence number in message 1 of P3");
            rtLogger.fatal("Wrong sequence number", "carAssignment message 1", cardID);
        }

        int giveCarHashSignLen = getInt(response, offset);
        offset+=4;
        byte[] giveCarHashSign = new byte[giveCarHashSignLen];
        memCpy(giveCarHashSign,response, offset,giveCarHashSignLen);
        //byte[] giveCarHash= rtc.unsign(giveCarHashSign, cardPubSK);
        //byte[] giveCarHashValid = rtc.createHash(concatBytes("Car?".getBytes(StandardCharsets.UTF_8), shortToByteArray(seqNum1))); //We still dont know if this works
        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[6]);
        msg1Cmps.put(requestBytes).putShort(seqNum1);
        if (!rtc.verify(msg1Cmps,giveCarHashSign,scPubSK)){ //Step 3
            //TODO: Error
            errorState("Invalid hash in message 1 of P3");
            rtLogger.fatal("Invalid Hash", "carAssingment message 1", cardID);
            return;
        }
        msgBuf.clear().rewind();
        msgBuf.put(cardID);
        //send(database, message); //Step 4
        //database.carAssign(this);

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
            rtLogger.warning("Aborting: Timeout", "carAssignment database communication",cardID);
            return;
        }
        byte[] autoPubSKBytes = new byte[KEY_LEN];
        response2.get(autoPubSKBytes,0,KEY_LEN);
        PublicKey autoPubSK = bytesToPubkey(autoPubSKBytes);
        byte[] autoID = new byte[5];
        response2.get(autoID,0,5);
        int autoCertHashSignLen = response2.getInt();
        byte[] autoCertHashSign = new byte[autoCertHashSignLen];
        response2.get(autoCertHashSign,0,autoCertHashSignLen);

        //System.out.println(new String(autoID)); //Step 5 - Kinda filler, maybe later so process doesnt get aborted
        msgBuf.put(pubkToBytes(autoPubSK));
        msgBuf.put(autoID).putInt(autoCertHashSignLen).put(autoCertHashSign).putShort((short) (scNonce+1));
        byte[] msg2Sign = rtc.sign(concatBytes(pubkToBytes(autoPubSK), autoID, autoCertHashSign, shortToByteArray((short) (scNonce+1))));
        msgBuf.putInt(msg2Sign.length).put(msg2Sign);
        apdu = sendAPDU(CARD_CONT,CAR_ASSIGNMENT_M2,msgBuf);
        //send(sc, msgBuf);//Step 6
        msgBuf.clear();
        msgBuf.rewind();

        // Success message?
        offset=ERESPAPDU_CDATA_OFFSET;
        //ByteBuffer succMsg = ByteBuffer.wrap(apdu.getData());
        byte[] succMsg = apdu.getData();
        /*try {
            succMsg = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response2 carAssignment");
            rtLogger.warning("Aborting: timeout", "carAssignment message 3", cardID);
            return;
        }*/

        byte success = succMsg[0];
        offset++;
        if(success != SUCCESS_BYTE){
            errorState("Wrong byte code, expected 0xFF");
            rtLogger.warning("Wrong byte, expected 0xFF, got " + success, "carAssignment", cardID);
            return;
        }
        short seqNum2 = getShort(succMsg, offset);
        offset+=2;
        if(!rtc.areSubsequentNonces(termNonce, seqNum2, 2)){
            errorState("Wrong sequence number in success message of P3");
            rtLogger.fatal("Wrong sequence number ", "carAssignment success message", cardID);
            return;
        }
        int succHashSignLen = getInt(succMsg, offset);
        offset+=4;
        byte[] succHashSign = new byte[succHashSignLen];
        memCpy(succHashSign,succMsg, offset,succHashSignLen);
        //byte[] succHash = rtc.unsign(succHashSign, cardPubSK);
        //byte[] succByte = {success};
        ByteBuffer succMsgCmps = ByteBuffer.wrap(new byte[3]);
        succMsgCmps.put(success).putShort(seqNum2);
        if(!rtc.verify(succMsgCmps,succHashSign,scPubSK)){
            errorState("Invalid hash in success message of P3");
            rtLogger.fatal("Invalid hash", "carAssignment success message", cardID);
            return;
        }
        rtLogger.info("Car " + Arrays.toString(autoID) + " successfully assigned", "carAssignment", cardID);
        cardID = null;
        cardAuthenticated = false;
        deselect();
    }

    /**protocol 6 - card blocking */
    public void blockCard(){
        ByteBuffer blockBuf = ByteBuffer.allocate(5);
        System.out.println(cardID);
        blockBuf.put(cardID); //cardID is null -> Which card will it even block?
        send(database,blockBuf);
        ByteBuffer resp;
        try {
            resp = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return;
        }
        int msgLen = new String(cardID).length() + 29;
        byte[] msg = new byte[msgLen];
        resp.get(msg,0,msgLen);
        String request = new String(msg, StandardCharsets.UTF_8);
        if(!request.equals(new String(cardID) + " has been removed from cards.")){
            errorState("Database returned wrong message after blocking card");
            rtLogger.fatal("Database returned wrong message", "blockCard", cardID);
            return;
        }
        rtLogger.info("Card blocked successfully", "blockCard",cardID);
    }

    private static class RTCrypto extends CryptoImplementation {

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
            public PublicKey getPublicKey() {return null;}
        }
    }

    public void initialDataForSC(){
        try {
            initBuffer = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return;
        }
        System.out.println(getInt(initBuffer.array(),5));
    }

    private void select(){
        try {
            if(rtTerminal.isCardPresent()){
                return;
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
        smartcard.assignToTerminal(rtTerminal);
        try{
            Card card = rtTerminal.connect("*");
            applet = card.getBasicChannel();
            ResponseAPDU resp = applet.transmit(SELECT_APDU);
            if(resp.getSW() != 0x9000){
                throw new Exception("Select failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void deselect(){
        try {
            if (!rtTerminal.isCardPresent()){
                rtLogger.warning("Tried to deselect card that is not present","Deselect",cardID);
                return;
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
        smartcard.assignToTerminal(null);
        applet = null;
    }

    class SimulatedCardThread extends Thread {
        public void run(){
            //CardSimulator smartcard = new CardSimulator();
            AID scAppletAID = AIDUtil.create(SC_APPLET_AID);
            smartcard.installApplet(scAppletAID,Smartcard.class);
            select();
        }
    }
}
