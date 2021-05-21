package receptionTerminal;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.UUID;

public class ReceptionTerminal implements Communicator {

    static final byte[] SC_APPLET_AID = {
            (byte) 0x3B,
            (byte) 0x29,
            (byte) 0x63,
            (byte) 0x61,
            (byte) 0x6C,
            (byte) 0x63,
            (byte) 0x02
    };
    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, SC_APPLET_AID);
    CardChannel applet;

    private ReceptionTerminal.RTCrypto rtc;
    public PublicKey dbPubSK;
    private boolean cardAuthenticated = false;
    private short termNonce; //Placeholder
    private short scNonce; //Placeholder
    private PublicKey cardPubSK; //TEMP until better solution
    private byte[] cardID; //TEMP see above
    private Database database; //who knows at this point
    public PublicKey scPubSK;
    public int kilometerage;
    private Logger rtLogger;
    private ByteBuffer msgBuf = ByteBuffer.allocate(256);

    @Override
    public Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        cardAuthenticated = false;
        cardID = null;
        return null;
    }

    public ReceptionTerminal(byte[] rtID, byte[] rtCertificate, Database db, PrivateKey privateKey) {
        rtc = new receptionTerminal.ReceptionTerminal.RTCrypto(rtID, rtCertificate, privateKey);
        File logFile = new File(rtID.toString()+"_reception_terminal_log.txt");
        rtLogger = new Logger(logFile);
        database = db;
        (new SimulatedCardThread()).start();
    }

    public int carReturn(Smartcard sc){
        if (!cardAuthenticated){
            errorState("Card is not authenticated");
            rtLogger.warning("Aborting: Card is not authenticated", "CarReturn", cardID);
            return -1;
        }

        //Message 1
        ByteBuffer msg1;
        try {
            msg1 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout message1 carReturn");
            rtLogger.warning("Timeout while waiting for message", "CarReturn message 1", cardID);
            return -1;
        }
        byte[] carReturnBytes = new byte[10];
        msg1.get(carReturnBytes,0,10);
        String carReturn = new String(carReturnBytes, StandardCharsets.UTF_8);
        if (!carReturn.equals("Car Return")) {
            errorState("Wrong command, expected Car Return, got " + carReturn);
            rtLogger.warning("Wrong command, expected Car Return, got " + carReturn, "CarReturn message 1", cardID);
            return -1;
        }
        short seqNum = msg1.getShort();
        if(!rtc.areSubsequentNonces(termNonce,seqNum)){
            errorState("Wrong sequence number in carReturn message 1");
            rtLogger.fatal("Wrong sequence number", "carReturn message 1", cardID);
            return -1;
        }
        boolean manipulation = booleanFromByte(msg1.get());
        int msg1HashSignLen = msg1.getInt();
        byte[] msg1HashSign = new byte[msg1HashSignLen];
        msg1.get(msg1HashSign,17,msg1HashSignLen);
        byte[] msg1Hash = rtc.unsign(msg1HashSign, scPubSK);
        byte[] msg1ConfHash = rtc.createHash(concatBytes(carReturn.getBytes(StandardCharsets.UTF_8), shortToByteArray(seqNum), booleanToByteArray(manipulation)));
        if(!Arrays.equals(msg1Hash,msg1ConfHash)){
            errorState("Hashes don't match in carReturn message 1");
            rtLogger.fatal("Hashes don't match", "carReturn message 1", cardID);
            return -1;
        }
        if (manipulation){
            errorState("Kilometerage on card " + cardID.toString() + " might have been manipulated. Please verify");
            rtLogger.warning("Kilometerage on card " + cardID.toString() + " might have been manipulated. Please verify", "carReturn message 1", cardID);
            return -1;
        }

        //Message 2
        short kmmNonce = rtc.generateNonce();
        msgBuf.putShort(kmmNonce);
        short seqNum2 = (short) (scNonce+1);
        msgBuf.putShort(seqNum2);
        byte[] msg2Sign = rtc.hashAndSign(concatBytes(shortToByteArray(kmmNonce), shortToByteArray(seqNum2)));
        msgBuf.putInt(msg2Sign.length).put(msg2Sign);
        send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 3
        ByteBuffer msg3;
        try {
            msg3 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in message3 carReturn response");
            rtLogger.warning("Timeout while waiting for response", "message3 carReturn", cardID);
            return -1;
        }
        kilometerage = msg3.getInt();
        short kmmNonceResp = msg3.getShort();
        if(kmmNonce != kmmNonceResp){
            //TODO: Error
            errorState("Wrong kilometerage nonce returned");
            rtLogger.fatal("Wrong kilometerage nonce returned", "message 3 carReturn", cardID);
            return -1;
        }
        short seqNum3 = msg3.getShort();
        if(!rtc.areSubsequentNonces(termNonce,seqNum3,2)){
            errorState("Wrong sequence number in carReturn message 3");
            rtLogger.fatal("Wrong sequence number", "carReturn message 3", cardID);
            return -1;
        }
        int msg3HashSignLen = msg3.getInt();
        byte[] msg3HashSign = new byte[msg3HashSignLen];
        msg3.get(msg3HashSign,12,msg3HashSignLen);
        byte[] msg3Hash = rtc.unsign(msg3HashSign,scPubSK);
        byte[] validMsg3Hash = rtc.createHash(concatBytes(intToByteArray(kilometerage), shortToByteArray(kmmNonceResp), shortToByteArray(seqNum3)));
        if(!Arrays.equals(msg3Hash,validMsg3Hash)){
            //TODO: Error
            errorState("Hash in carReturn message 3 invalid");
            rtLogger.fatal("Invalid hash", "carReturn message 3", cardID);
            return -1;
        }

        //Success Message
        msgBuf.put(SUCCESS_BYTE).putShort((short) (scNonce + 2));
        byte[] succHash = rtc.hashAndSign(prepareMessage(SUCCESS_BYTE, (short) (scNonce + 2)));
        msgBuf.putInt(succHash.length).put(succHash);
        send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        rtLogger.info("Car returned successfully", "carReturn", cardID);
        cardAuthenticated = false;
        cardID = null;
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
        return kilometerage;
    }

    /*Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    public void cardAuthentication(Smartcard sc){
        //Message 1
        ByteBuffer response; //Step 2
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response cardAuthentication");
            rtLogger.warning("Timeout while waiting for message", "cardAuthentication message 1", cardID);
            return;
        }
        int cardCertHashSignLen = response.getInt();

        //cardPubSK + cardID
        byte[] cardPubSKEncoded = new byte[128];
        response.get(cardPubSKEncoded,4,128);
        int curBufIndex = 132;
        cardPubSK = bytesToPubkey(cardPubSKEncoded);
        cardID = new byte[5];
        response.get(cardID,curBufIndex,5);
        curBufIndex += 5;

        //Signed hash of certificate
        byte[] cardCertHashSign = new byte[cardCertHashSignLen];
        response.get(cardCertHashSign,curBufIndex,cardCertHashSignLen);
        scNonce = response.getShort();
        byte[] cardCertHash = rtc.unsign(cardCertHashSign, dbPubSK);

        byte[] cardIDPubSKHash = rtc.createHash(prepareMessage(cardPubSK, cardID));
        if (!Arrays.equals(cardCertHash,cardIDPubSKHash)){ //Step 3
            errorState("Hash does not match known card");
            rtLogger.fatal("Invalid certificate: Hash does not match known card", "cardAuthentication message 1", cardID);
            return;
        }

        //Message 2
        termNonce = rtc.generateNonce();
        msgBuf.putInt(rtc.getCertificate().length - 133).put(rtc.getCertificate()).putShort(termNonce);
        send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();
        //Step 4

        //Message 3
        ByteBuffer response2;
        try {
            response2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response 2 cardAuthentication");
            rtLogger.warning("Aborting: Timeout", "cardAuthentication response 2", cardID);
            return;
        }

        short termNonceResp = response2.getShort();
        if(termNonceResp != termNonce){
            errorState("Wrong nonce in message 3 of cardAuthentication");
            rtLogger.fatal("Wrong nonce", "cardAuthentication message 3", cardID);
            return;
        }

        int receptionNonceHashSignLen = response2.getInt();
        byte[] receptionNonceHashSign = new byte[receptionNonceHashSignLen];
        response2.get(receptionNonceHashSign,6,receptionNonceHashSignLen);
        byte[] receptionNonceHash = rtc.unsign(receptionNonceHashSign, cardPubSK);
        byte[] nonceReceptionHashValid = rtc.createHash(shortToByteArray(termNonce));
        if (!Arrays.equals(nonceReceptionHashValid,receptionNonceHash)){ //Step 7
            errorState("Invalid hash in message 3 of P2");
            rtLogger.fatal("Invalid Hash", "cardAuthentication message 3", cardID);
            return;
        }

        //Success message
        msgBuf.put(SUCCESS_BYTE);
        byte[] succByte = {SUCCESS_BYTE};
        byte[] nonceCardHashSign = rtc.hashAndSign(concatBytes(succByte, shortToByteArray(scNonce)));
        msgBuf.putShort(scNonce).putInt(nonceCardHashSign.length).put(nonceCardHashSign);
        send(sc, msgBuf); //Step 8
        rtLogger.info("Smartcard authenticated successfully", "cardAuthentification", cardID);
        cardAuthenticated = true; //When to make it false again

    }

    /*Protocol 3 - Assignment of car to smartcard */
    public void carAssignment(Smartcard sc){
        if (!cardAuthenticated){ //Step 1
            rtLogger.warning("Aborting: Card not authenticated", "carAssignment", cardID);
            return; //TODO: Placeholder
        }

        ByteBuffer response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssignment");
            rtLogger.warning("Aborting: Timeout", "carAssignment message 1", cardID);
            return;
        }
        byte[] requestBytes = new byte[4];
        response.get(requestBytes,0,4);
        String request = new String(requestBytes, StandardCharsets.UTF_8);
        if (!request.equals("Car?")){
            errorState("Expected car request");
            rtLogger.fatal("Expected car request, got " + request, "carAssignment", cardID);
            return;
        }
        short seqNum1 = response.getShort();
        if(!rtc.areSubsequentNonces(termNonce, seqNum1)){
            errorState("Wrong sequence number in message 1 of P3");
            rtLogger.fatal("Wrong sequence number", "carAssignment message 1", cardID);
        }

        int giveCarHashSignLen = response.getInt();
        byte[] giveCarHashSign = new byte[giveCarHashSignLen];
        response.get(giveCarHashSign,10,giveCarHashSignLen);
        byte[] giveCarHash= rtc.unsign(giveCarHashSign, cardPubSK);
        byte[] giveCarHashValid = rtc.createHash(concatBytes("Car?".getBytes(StandardCharsets.UTF_8), shortToByteArray(seqNum1))); //We still dont know if this works
        if (!Arrays.equals(giveCarHash,giveCarHashValid)){ //Step 3
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
            errorState("Timeout response2 carAssignment");
            rtLogger.warning("Aborting: Timeout", "carAssignment response 2",cardID);
            return;
        }
        byte[] autoPubSKBytes = new byte[128];
        response2.get(autoPubSKBytes,0,128);
        PublicKey autoPubSK = bytesToPubkey(autoPubSKBytes);
        byte[] autoID = new byte[5];
        response2.get(autoID,128,5);
        int autoCertHashSignLen = response2.getInt();
        byte[] autoCertHashSign = new byte[autoCertHashSignLen];
        response2.get(autoCertHashSign,133,autoCertHashSignLen);

        System.out.println(autoID); //Step 5 - Kinda filler, maybe later so process doesnt get aborted
        msgBuf.put(autoPubSK.getEncoded());
        msgBuf.put(autoID).put(autoCertHashSign).putShort((short) (scNonce+1));
        msgBuf.put(rtc.hashAndSign(concatBytes(autoPubSK.getEncoded(), autoID, autoCertHashSign, shortToByteArray((short) (scNonce+1)))));
        send(sc, msgBuf);//Step 6
        msgBuf.clear();
        msgBuf.rewind();

        // Success message?
        ByteBuffer succMsg;
        try {
            succMsg = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response2 carAssignment");
            rtLogger.warning("Aborting: timeout", "carAssignment message 3", cardID);
            return;
        }

        byte success = succMsg.get();
        if(success != SUCCESS_BYTE){
            errorState("Wrong byte code, expected 0xFF");
            rtLogger.warning("Wrong byte, expected 0xFF, got " + success, "carAssignment", cardID);
            return;
        }
        short seqNum2 = succMsg.getShort();
        if(!rtc.areSubsequentNonces(termNonce, seqNum2, 2)){
            errorState("Wrong sequence number in success message of P3");
            rtLogger.fatal("Wrong sequence number ", "carAssignment success message", cardID);
            return;
        }
        int succHashSignLen = succMsg.getInt();
        byte[] succHashSign = new byte[succHashSignLen];
        succMsg.get(succHashSign,7,succHashSignLen);
        byte[] succHash = rtc.unsign(succHashSign, cardPubSK);
        byte[] succByte = {success};
        if(!Arrays.equals(succHash,rtc.createHash(concatBytes(succByte, shortToByteArray(seqNum2))))){
            errorState("Invalid hash in success message of P3");
            rtLogger.fatal("Invalid hash", "carAssignment success message", cardID);
            return;
        }
        rtLogger.info("Car " + autoID + " successfully assigned", "carAssignment", cardID);
        cardID = null;
        cardAuthenticated = false;
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

    class SimulatedCardThread extends Thread {
        public void run(){
            CardTerminals cardTerminals = CardTerminalSimulator.terminals("Rental smartcard terminals");
            CardTerminal rtTerminal = cardTerminals.getTerminal(Arrays.toString(rtc.getID()));
            CardSimulator smartcard = new CardSimulator();
            AID scAppletAID = new AID(SC_APPLET_AID,(byte)0,(byte)7);
            smartcard.installApplet(scAppletAID,Smartcard.class);
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
    }
}