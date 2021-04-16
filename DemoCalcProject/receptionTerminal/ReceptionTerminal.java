package receptionTerminal;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import db.Database;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

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

    public ReceptionTerminal(byte[] rtID, byte[] rtCertificate) {
        rtc = new receptionTerminal.ReceptionTerminal.RTCrypto(rtID, rtCertificate);
    }

    public void carReturn(Smartcard sc, PublicKey scPubSK){
        if (!cardAuthenticated){
            errorState("Card is not authenticated");
            return;
        }
        byte[] msg1b = new byte[0];
        try {
            msg1b = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout message1 carReturn");
            return;
        }
        Object[] msg1o = processMessage(msg1b);
        short seqNum = (short) msg1o[1];
        if(!rtc.areSubsequentNonces(termNonce,seqNum)){
            errorState("Wrong sequence number in carReturn message 1");
            return;
        }
        boolean manipulation = (boolean) msg1o[2];
        byte[] msg1Hash = rtc.unsign(((byte[]) msg1o[3]), scPubSK);
        byte[] msg1ConfHash = rtc.createHash(prepareMessage(((byte) msg1o[0]), seqNum, manipulation));
        if(msg1Hash != msg1ConfHash){
            errorState("Hashes don't match in carReturn message 1");
            return;
        }
        if (manipulation){
            errorState("Kilometerage on card " + cardID.toString() + " might have been manipulated. Please verify");
            return;
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
            return;
        }
        Object[] msg3 = processMessage(msg3b);
        int kilometerage = (int) msg3[0];
        short kmmNonceResp = (short) msg3[1];
        if(kmmNonce != kmmNonceResp){
            //TODO: Error
            errorState("Wrong kilometerage nonce returned");
            return;
        }
        short seqNum3 = (short) msg3[2];
        if(!rtc.areSubsequentNonces(termNonce,seqNum3,2)){
            errorState("Wrong sequence number in carReturn message 3");
            return;
        }
        byte[] msg3Hash = rtc.unsign(((byte[]) msg3[3]),scPubSK);
        byte[] validMsg3Hash = rtc.createHash(prepareMessage(kilometerage, kmmNonceResp, seqNum3));
        if(msg3Hash != validMsg3Hash){
            //TODO: Error
            errorState("Hash in carReturn message 3 invalid");
            return;
        }
        send(sc, SUCCESS_BYTE, (short) (scNonce + 2), rtc.hashAndSign(prepareMessage(SUCCESS_BYTE, (short) (scNonce + 2))));
    }

    /*Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    private void cardAuthentication(Smartcard sc){
        byte[] response = new byte[0]; //Step 2
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout response cardAuthentication");
            return;
        }
        Object[] responseData = processMessage(response);

        cardPubSK = (PublicKey) responseData[0];
        byte[] cardID = (byte[]) responseData[1];
        byte[] cardCertHashSign = (byte[]) responseData[2];
        scNonce = (short) responseData[3];
        byte[] cardCertHash = rtc.unsign(cardCertHashSign, dbPubSK);

        byte[] cardIDPubSKHash = rtc.createHash(prepareMessage(cardPubSK, cardID));
        if (cardCertHash != cardIDPubSKHash){ //Step 3
            errorState("Hash does not match known card");
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
            return;
        }
        Object[] responseData2 = processMessage(response2);
        short termNonceResp = (short) responseData2[0];
        if(termNonceResp != termNonce){
            errorState("Wrong nonce in message 3 of P2");
            return;
        }

        byte[] receptionNonceHash = rtc.unsign((byte[]) responseData2[1], cardPubSK);
        byte[] nonceReceptionHashValid = rtc.createHash(prepareMessage(termNonce));
        if (nonceReceptionHashValid != receptionNonceHash){ //Step 7
            errorState("Invalid hash in message 3 of P2");
            return;
        }

        byte[] nonceCardHashSign = rtc.hashAndSign(prepareMessage(SUCCESS_BYTE, scNonce));
        send(sc, SUCCESS_BYTE, scNonce, nonceCardHashSign); //Step 8

        cardAuthenticated = true; //When to make it false again

    }

    /*Protocol 3 - Assignment of car to smartcard */
    public void carAssignment(Smartcard sc){
        if (!cardAuthenticated){ //Step 1
            return; //TODO: Placeholder
        }

        byte[] response;
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssignment");
            return;
        }
        Object[] responseData = processMessage(response);
        String request = (String) responseData[0];
        if (!request.equals("Car?")){
            errorState("Expected car request");
            return;
        }
        short seqNum1 = (short) responseData[1];
        if(!rtc.areSubsequentNonces(termNonce, seqNum1)){
            errorState("Wrong sequence number in message 1 of P3");
        }

        byte[] giveCarHash= rtc.unsign(prepareMessage(responseData[2]), cardPubSK);
        byte[] giveCarHashValid = rtc.createHash(prepareMessage("Car?", seqNum1)); //We still dont know if this works
        if (giveCarHash != giveCarHashValid){ //Step 3
            //TODO: Error
            errorState("Invalid hash in message 1 of P3");
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
            return;
        }
        Object[] succMsg = processMessage(succMsgB);
        byte success = (byte) succMsg[0];
        if(success != SUCCESS_BYTE){
            errorState("Wrong byte code, expected 0xFF");
            return;
        }
        short seqNum2 = (short) succMsg[1];
        if(!rtc.areSubsequentNonces(termNonce, seqNum2, 2)){
            errorState("Wrong sequence number in success message of P3");
            return;
        }
        byte[] succHash = (byte[]) succMsg[2];
        if(succHash != rtc.createHash(prepareMessage(success, seqNum2))){
            errorState("Invalid hash in success message of P2");
            return;
        }
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
            public PublicKey getPublicKey() {
                return null;
            }
        }
    }
}