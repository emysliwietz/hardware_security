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
            return; //TODO: Placeholder
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
        int seqNum = (int) msg1o[1];
        //TODO: Check sequence number
        boolean manipulation = (boolean) msg1o[2];
        byte[] msg1Hash = rtc.unsign(((byte[]) msg1o[3]), scPubSK);
        byte[] msg1ConfHash = rtc.createHash(prepareMessage(((byte) msg1o[0]), seqNum, manipulation));
        if(msg1Hash != msg1ConfHash){
            //TODO: Error
        }
        if (manipulation){
            //TODO: Throw exception/error
        }
        short kmmNonce = rtc.generateNonce();
        int seqNum2 = 0; //Placeholder
        byte[] msg2Sign = rtc.hashAndSign(prepareMessage(kmmNonce, seqNum2));
        send(sc, kmmNonce, seqNum2, msg2Sign);
        byte[] msg3b = waitForInput();
        Object[] msg3 = processMessage(msg3b);
        int kilometerage = (int) msg3[0];
        short kmmNonceResp = (short) msg3[1];
        if(kmmNonce != kmmNonceResp){
            //TODO: Error
        }
        int seqNum3 = (int) msg3[2];
        byte[] msg3Hash = rtc.unsign(((byte[]) msg3[3]),scPubSK);
        byte[] validMsg3Hash = rtc.createHash(prepareMessage(kilometerage, kmmNonceResp, seqNum3));
        if(msg3Hash != validMsg3Hash){
            //TODO: Error
        }
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

        byte[] receptionNonceUnsigned = rtc.unsign((byte[]) responseData2[0], cardPubSK);
        byte[] nonceReceptionHash = rtc.createHash(prepareMessage(termNonce));
        if (nonceReceptionHash != receptionNonceUnsigned){ //Step 7
            errorState("Hash does not match reception nonce.");
            return;
        }

        byte[] noncePrepped = prepareMessage(scNonce);
        byte[] nonceCardHashSign = sc.hashAndSign(noncePrepped);
        send(sc, nonceCardHashSign); //Step 8

        //Do we want some success message back?
        cardAuthenticated = true; //When to make it false again

    }

    /*Protocol 3 - Assignment of car to smartcard */
    public void carAssignment(Smartcard sc){
        if (!cardAuthenticated){ //Step 1
            return; //TODO: Placeholder
        }

        byte[] response = new byte[0];
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Waiting for response carAssignment");
            return;
        }
        Object[] responseData = processMessage(response);

        byte[] giveCarUnsigned = sc.unsign(responseData[0], cardPubSK);
        byte[] giveCarHash = sc.createHash(prepareMessage(nonceReception+1)); //We still dont know if this works
        if (giveCarUnsigned != giveCarHash){ //Step 3
            //TODO: Error
            errorState("Hashes don't match carAssignment");
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
        byte[] cert = prepareMessage(autoPubSK, autoID, autoCertHashSign, scNonce+1); //who knows if this works
        send(sc, cert);//Step 6

        // Success message?
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