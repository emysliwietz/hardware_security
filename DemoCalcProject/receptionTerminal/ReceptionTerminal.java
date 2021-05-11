package receptionTerminal;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import db.Database;
import rsa.CryptoImplementation;
import rsa.RSACrypto;
import utility.Logger;

import java.io.File;
import java.math.BigDecimal;
import java.security.PublicKey;
import java.util.UUID;

public class ReceptionTerminal implements Communicator {

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

    @Override
    public Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        cardAuthenticated = false;
        cardID = null;
        return null;
    }

    public ReceptionTerminal(byte[] rtID, byte[] rtCertificate) {
        rtc = new receptionTerminal.ReceptionTerminal.RTCrypto(rtID, rtCertificate);
        File logFile = new File(rtID.toString()+"_reception_terminal_log.txt");
        rtLogger = new Logger(logFile);
    }

    public int carReturn(Smartcard sc){
        if (!cardAuthenticated){
            errorState("Card is not authenticated");
            rtLogger.warning("Aborting: Card is not authenticated", "CarReturn", cardID);
            return -1;
        }
        byte[] msg1b = new byte[0];
        try {
            msg1b = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout message1 carReturn");
            rtLogger.warning("Timeout while waiting for message", "CarReturn message 1", cardID);
            return -1;
        }
        Object[] msg1o = processMessage(msg1b);
        short seqNum = (short) msg1o[1];
        if(!rtc.areSubsequentNonces(termNonce,seqNum)){
            errorState("Wrong sequence number in carReturn message 1");
            rtLogger.fatal("Wrong sequence number", "carReturn message 1", cardID);
            return -1;
        }
        boolean manipulation = (boolean) msg1o[2];
        byte[] msg1Hash = rtc.unsign(((byte[]) msg1o[3]), scPubSK);
        byte[] msg1ConfHash = rtc.createHash(prepareMessage(((byte) msg1o[0]), seqNum, manipulation));
        if(msg1Hash != msg1ConfHash){
            errorState("Hashes don't match in carReturn message 1");
            rtLogger.fatal("Hashes don't match", "carReturn message 1", cardID);
            return -1;
        }
        if (manipulation){
            errorState("Kilometerage on card " + cardID.toString() + " might have been manipulated. Please verify");
            rtLogger.warning("Kilometerage on card " + cardID.toString() + " might have been manipulated. Please verify", "carReturn message 1", cardID);
            return -1;
        }
        short kmmNonce = rtc.generateNonce();
        short seqNum2 = (short) (scNonce+1);
        byte[] msg2Sign = rtc.hashAndSign(prepareMessage(kmmNonce, seqNum2));
        send(sc, kmmNonce, seqNum2, msg2Sign);
        byte[] msg3b;
        try {
            msg3b = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in message3 carReturn response");
            rtLogger.warning("Timeout while waiting for response", "message3 carReturn", cardID);
            return -1;
        }
        Object[] msg3 = processMessage(msg3b);
        kilometerage = (int) msg3[0];
        short kmmNonceResp = (short) msg3[1];
        if(kmmNonce != kmmNonceResp){
            //TODO: Error
            errorState("Wrong kilometerage nonce returned");
            rtLogger.fatal("Wrong kilometerage nonce returned", "message 3 carReturn", cardID);
            return -1;
        }
        short seqNum3 = (short) msg3[2];
        if(!rtc.areSubsequentNonces(termNonce,seqNum3,2)){
            errorState("Wrong sequence number in carReturn message 3");
            rtLogger.fatal("Wrong sequence number", "carReturn message 3", cardID);
            return -1;
        }
        byte[] msg3Hash = rtc.unsign(((byte[]) msg3[3]),scPubSK);
        byte[] validMsg3Hash = rtc.createHash(prepareMessage(kilometerage, kmmNonceResp, seqNum3));
        if(msg3Hash != validMsg3Hash){
            //TODO: Error
            errorState("Hash in carReturn message 3 invalid");
            rtLogger.fatal("Invalid hash", "carReturn message 3", cardID);
            return -1;
        }
        send(sc, SUCCESS_BYTE, (short) (scNonce + 2), rtc.hashAndSign(prepareMessage(SUCCESS_BYTE, (short) (scNonce + 2))));
        rtLogger.info("Car returned successfully", "carReturn", cardID);
        cardAuthenticated = false;
        cardID = null;
        return kilometerage;
    }

    /*Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    public void cardAuthentication(Smartcard sc){
        byte[] response = new byte[0]; //Step 2
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response cardAuthentication");
            rtLogger.warning("Timeout while waiting for message", "cardAuthentication message 1", cardID);
            return;
        }
        Object[] responseData = processMessage(response);

        cardPubSK = (PublicKey) responseData[0];
        cardID = (byte[]) responseData[1];
        byte[] cardCertHashSign = (byte[]) responseData[2];
        scNonce = (short) responseData[3];
        byte[] cardCertHash = rtc.unsign(cardCertHashSign, dbPubSK);

        byte[] cardIDPubSKHash = rtc.createHash(prepareMessage(cardPubSK, cardID));
        if (cardCertHash != cardIDPubSKHash){ //Step 3
            errorState("Hash does not match known card");
            rtLogger.fatal("Invalid certificate: Hash does not match known card", "cardAuthentication message 1", cardID);
            return;
        }

        termNonce = rtc.generateNonce();
        send(sc, rtc.getCertificate(), termNonce); //Step 4

        byte[] response2 = new byte[0];
        try {
            response2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response 2 cardAuthentication");
            rtLogger.warning("Aborting: Timeout", "cardAuthentication response 2", cardID);
            return;
        }
        Object[] responseData2 = processMessage(response2);
        short termNonceResp = (short) responseData2[0];
        if(termNonceResp != termNonce){
            errorState("Wrong nonce in message 3 of cardAuthentication");
            rtLogger.fatal("Wrong nonce", "cardAuthentication message 3", cardID);
            return;
        }

        byte[] receptionNonceHash = rtc.unsign((byte[]) responseData2[1], cardPubSK);
        byte[] nonceReceptionHashValid = rtc.createHash(prepareMessage(termNonce));
        if (nonceReceptionHashValid != receptionNonceHash){ //Step 7
            errorState("Invalid hash in message 3 of P2");
            rtLogger.fatal("Invalid Hash", "cardAuthentication message 3", cardID);
            return;
        }

        byte[] nonceCardHashSign = rtc.hashAndSign(prepareMessage(SUCCESS_BYTE, scNonce));
        send(sc, SUCCESS_BYTE, scNonce, nonceCardHashSign); //Step 8
        rtLogger.info("Smartcard authenticated successfully", "cardAuthentification", cardID);
        cardAuthenticated = true; //When to make it false again

    }

    /*Protocol 3 - Assignment of car to smartcard */
    public void carAssignment(Smartcard sc){
        if (!cardAuthenticated){ //Step 1
            rtLogger.warning("Aborting: Card not authenticated", "carAssignment", cardID);
            return; //TODO: Placeholder
        }

        byte[] response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssignment");
            rtLogger.warning("Aborting: Timeout", "carAssignment message 1", cardID);
            return;
        }
        Object[] responseData = processMessage(response);
        String request = (String) responseData[0];
        if (!request.equals("Car?")){
            errorState("Expected car request");
            rtLogger.fatal("Expected car request, got " + request, "carAssignment", cardID);
            return;
        }
        short seqNum1 = (short) responseData[1];
        if(!rtc.areSubsequentNonces(termNonce, seqNum1)){
            errorState("Wrong sequence number in message 1 of P3");
            rtLogger.fatal("Wrong sequence number", "carAssignment message 1", cardID);
        }

        byte[] giveCarHash= rtc.unsign(prepareMessage(responseData[2]), cardPubSK);
        byte[] giveCarHashValid = rtc.createHash(prepareMessage("Car?", seqNum1)); //We still dont know if this works
        if (giveCarHash != giveCarHashValid){ //Step 3
            //TODO: Error
            errorState("Invalid hash in message 1 of P3");
            rtLogger.fatal("Invalid Hash", "carAssingment message 1", cardID);
            return;
        }

        byte[] message = prepareMessage(cardID);
        send(database, message); //Step 4

        byte[] response2 = new byte[0];
        try {
            response2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response2 carAssignment");
            rtLogger.warning("Aborting: Timeout", "carAssignment response 2",cardID);
            return;
        }
        Object[] responseData2 = processMessage(response2);
        PublicKey autoPubSK = (PublicKey) responseData2[0];
        byte[] autoID = (byte[]) responseData2[1];
        byte[] autoCertHashSign = (byte[]) responseData2[2];

        System.out.println(autoID); //Step 5 - Kinda filler, maybe later so process doesnt get aborted
        send(sc, autoPubSK, autoID, autoCertHashSign, (short) (scNonce+1),
                rtc.hashAndSign(prepareMessage(autoPubSK, autoID, autoCertHashSign, (short) (scNonce+1))));//Step 6

        // Success message?
        byte[] succMsgB;
        try {
            succMsgB = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response2 carAssignment");
            rtLogger.warning("Aborting: timeout", "carAssignment message 3", cardID);
            return;
        }
        Object[] succMsg = processMessage(succMsgB);
        byte success = (byte) succMsg[0];
        if(success != SUCCESS_BYTE){
            errorState("Wrong byte code, expected 0xFF");
            rtLogger.warning("Wrong byte, expected 0xFF, got " + success, "carAssignment", cardID);
            return;
        }
        short seqNum2 = (short) succMsg[1];
        if(!rtc.areSubsequentNonces(termNonce, seqNum2, 2)){
            errorState("Wrong sequence number in success message of P3");
            rtLogger.fatal("Wrong sequence number ", "carAssignment success message", cardID);
            return;
        }
        byte[] succHash = (byte[]) succMsg[2];
        if(succHash != rtc.createHash(prepareMessage(success, seqNum2))){
            errorState("Invalid hash in success message of P3");
            rtLogger.fatal("Invalid hash", "carAssignment success message", cardID);
            return;
        }
        rtLogger.info("Car " + autoID + " successfully assigned", "carAssignment", cardID);
        cardID = null;
        cardAuthenticated = false;
    }

    private static class RTCrypto extends CryptoImplementation {

        public RTCrypto(byte[] rtID, byte[] rtCertificate) {
            super.ID = rtID;
            super.certificate = rtCertificate;
            super.rc = new RTWallet();
        }

        private static class RTWallet extends RSACrypto implements KeyWallet {

            @Override
            public void storePublicKey() {

            }

            @Override
            public void storePrivateKey() {

            }

            @Override
            public PublicKey getPublicKey() {return null;}
        }
    }
}