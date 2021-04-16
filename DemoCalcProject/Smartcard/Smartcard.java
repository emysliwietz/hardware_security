package Smartcard;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import receptionTerminal.ReceptionTerminal;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.math.BigDecimal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class Smartcard implements Communicator {
    private SmartcardCrypto sc;
    public PublicKey dbPubSK;
    private boolean manipulation = false;
    private int kilometerage; //TODO: Change to less storage intensive type (e.g. short or int)
    boolean terminalAuthenticated = false; //in temporary storage
    private short nonceReception; //TEMP because this should be yeeted when card is pulled out
    private short nonceCard; //TEMP same as above

    //This should actually be stored somehow?
    private byte[] autoIDStored;
    private PublicKey autoPubSKStored;

    public Smartcard(byte[] cardID, byte[] cardCertificate) {
        sc = new SmartcardCrypto(cardID, cardCertificate);
    }


    public PublicKey insert(Auto auto){ //P1
        short nonceCard = sc.generateNonce();
        send(auto, sc.getCertificate(), nonceCard);
        byte[] msg2b = new byte[0];
        try {
            msg2b = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return (PublicKey) errorState("Timeout in insert");
        }
        Object[] msg2o = processMessage(msg2b);
        PublicKey autoPubSK = (PublicKey) msg2o[0];
        byte[] autoID = (byte[]) msg2o[1];
        byte[] autoCertHashSign = (byte[]) msg2o[2];
        byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);

        byte[] autoIDPubSKHash = sc.createHash(prepareMessage(autoPubSK, autoID));
        if (autoCertHash != autoIDPubSKHash){
            //TODO: throw error or something (tamper bit). Also stop further actions.
            manipulation = true;
            return null;
        }

        short nonceCardResponse = (short) msg2o[3];
        if (nonceCard != nonceCardResponse){
            manipulation = true;
            return null; //Placeholder
        }
        byte[] nonceCardResponseHashSign = (byte[]) msg2o[4];
        byte[] nonceCardResponseHash = sc.unsign(nonceCardResponseHashSign, autoPubSK);

        byte[] nonceValidHash = sc.createHash(prepareMessage(nonceCard));
        if (nonceValidHash != nonceCardResponseHash){
            //TODO: throw error or something (tamper bit). Also stop further actions.
            manipulation = true;
            return null; //Placeholder probably
        }
        short nonceAuto = (short) msg2o[5];
        byte[] msg3tmp = prepareMessage(nonceAuto);
        byte[] nonceAutoHashSign = sc.hashAndSign(msg3tmp);
        send(auto, nonceAuto, nonceAutoHashSign);
        byte[] succMb;
        try {
            succMb = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return (PublicKey) errorState("Timeout in insert");
        }
        Object[] succM = processMessage(succMb);
        byte success = (byte) succM[0];
        if(success != SUCCESS_BYTE){
            errorState("Wrong code, expected 0xFF");
            return null;
        }
        short nonceSucc = (short) succM[1];
        if (!sc.areSubsequentNonces(nonceCard, nonceSucc)){
            errorState("Wrong nonce in success message of P1");
            return null;
        }
        byte[] succMHash = sc.unsign((byte[]) succM[2], autoPubSK);
        if((sc.createHash(prepareMessage(success))) != succMHash){
            errorState("Invalid hash in sucess message (P1)");
            return null;
        }
        return autoPubSK;
    }

    /*Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    public void authReception(ReceptionTerminal reception) {
        // How does the card know if it is in a terminal or a car?
        // Potential solution: terminal or auto sends a basic message like "terminal!" or  "auto!"
        //note for P1: overleaf states you send 2 nonces in step 4. Current algorithm sends only 1.
        nonceCard = sc.generateNonce();
        send(reception, sc.getCertificate(), nonceCard); //Step 2
        byte[] response = new byte[0]; //Step 4
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in authReception response 1");
            return;
        }
        Object[] responseData = processMessage(response);

        PublicKey receptionPubSK = (PublicKey) responseData[0];
        byte[] receptionID = (byte[]) responseData[1];
        byte[] receptionCertHashSign = (byte[]) responseData[2];
        nonceReception = (short) responseData[3];
        byte[] receptionCertHash = sc.unsign(receptionCertHashSign, dbPubSK);

        byte[] receptionIDPubSKHash = sc.createHash(prepareMessage(receptionPubSK, receptionID));
        if (receptionCertHash != receptionIDPubSKHash){ //Step 5
            manipulation = true;
            //TODO: Send message to terminal that process is stopped
            return;
        }
        byte[] noncePrepped = prepareMessage(nonceReception);
        byte[] nonceReceptionHashSign = sc.hashAndSign(noncePrepped);
        send(reception, nonceReception, nonceReceptionHashSign); //Step 6

        byte[] response2 = new byte[0];
        try {
            response2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in authReception response 2");
            return;
        }
        Object[] responseData2 = processMessage(response2);
        byte success = (byte) responseData2[0];
        if(success != SUCCESS_BYTE){
            errorState("Wrong byte code, expected 0xFF");
            return;
        }
        short nonceCardResp = (short) responseData2[1];
        if(nonceCardResp != nonceCard){
            errorState("Wrong nonce returned in message 4 of P2");
            return;
        }
        byte[] cardNonceHash = sc.unsign((byte[]) responseData2[1], receptionPubSK);
        byte[] nonceCardHashValid = sc.createHash(prepareMessage(success, nonceCard));
        if (nonceCardHashValid != cardNonceHash){ //Step 9
            errorState("Invalid hash in message 4 of P2");
            //TODO: error
            return;
        }

        terminalAuthenticated = true;
        //Maybe let the terminal know how it went

    }
    /*Protocol 3 - Assignment of car to smartcard */
    public void carAssignment(ReceptionTerminal reception){
        if (!terminalAuthenticated){ //Step 1
            return; //TODO: Placeholder
        }

        byte[] giveCarMsg = prepareMessage("Car?", nonceReception+1); //Does this work? We don't know :)
        byte[] giveCarSigned = sc.hashAndSign(giveCarMsg);
        send(reception, "Car?", (short)(nonceReception+1), giveCarSigned); //Step 2

        byte[] response = new byte[0];
        try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in carAssignment response");
            return;
        }
        Object[] responseData = processMessage(response);

        PublicKey autoPubSK = (PublicKey) responseData[0];
        byte[] autoID = (byte[]) responseData[1];
        byte[] autoCertHashSign = (byte[]) responseData[2];
        short nonceCard2 = (short) responseData[3];
        if (nonceCard2 != ((short) (nonceCard+1))){ //Step 7 - Sequence
            //TODO: Error
            errorState("Wrong sequence number in message 2 of P3");
            return;
        }

        byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);

        byte[] autoIDPubSKHash = sc.createHash(prepareMessage(autoPubSK, autoID));
        if (autoCertHash != autoIDPubSKHash){ //Step 7 - certificate
            //manipulation = true;
            errorState("Invalid car signature received");
            //TODO: Send message to terminal that process is stopped
            return;
        }
        autoIDStored = autoID;
        autoPubSKStored = autoPubSK; //Step 8
        //State transition????

        //Success message!
        send(reception, SUCCESS_BYTE, (short) (nonceReception+2), sc.createHash(prepareMessage(SUCCESS_BYTE, (short) (nonceReception+2))));
    }

    public void kilometerageUpdate(Auto auto, PublicKey autoPubSK){
        byte[] receivedKmm = new byte[0];
        try {
            receivedKmm = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in kilometerageUpdate km meter from car");
            return;
        }
        Object[] receivedKmmO = processMessage(receivedKmm);
        int oldKMM = kilometerage;
        kilometerage = (int) receivedKmmO[0];
        byte[] recKmmHashSign = (byte[]) receivedKmmO[1];
        byte[] recKmmHash = sc.unsign(recKmmHashSign, autoPubSK);
        byte[] validRecKmmHash = sc.createHash(prepareMessage(kilometerage));
        if(recKmmHash != validRecKmmHash){
            //TODO: throw error or something (tamper bit). Also stop further actions.
        }
        if (oldKMM >= kilometerage){
            manipulation = true;
            kilometerage = oldKMM; //TODO: Is this a security problem?
        }
        byte confirmation = (byte) 1;
        byte[] confirmationHash = sc.hashAndSign(prepareMessage(confirmation, kilometerage));
        send(auto, confirmation, kilometerage, confirmationHash);
    }

    public void carReturn(ReceptionTerminal rt, PublicKey rtPubSK){
        short seqNum1 = (short) (nonceReception + 1);
        byte[] msg1Hash = sc.hashAndSign(prepareMessage(((byte) 56), seqNum1, manipulation));
        send(rt, (byte) 56, seqNum1, manipulation, msg1Hash);
        byte[] msg2b;
        try {
            msg2b = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in waiting for message 2 carReturn");
            return;
        }
        Object[] msg2 = processMessage(msg2b);
        short kmmNonce = (short) msg2[0];
        short seqNum2 = (short) msg2[1];
        if(!sc.areSubsequentNonces(nonceCard, seqNum2)){
            errorState("Wrong sequence number in carReturn message 2");
            return;
        }
        byte[] msg2Hash = sc.unsign((byte[]) msg2[2], rtPubSK);
        byte[] validMsg2Hash = sc.createHash(prepareMessage(kmmNonce, seqNum2));
        if(msg2Hash != validMsg2Hash){
            //TODO: Error; also check sequence number (not in this if clause (obviously))
            errorState("Message hashes do not match in msg2 carReturn");
            return;
        }
        byte[] msg3Hash = sc.hashAndSign(prepareMessage(kilometerage, kmmNonce, (short) (seqNum1 + 1)));
        send(rt, kilometerage, kmmNonce, seqNum1 + 1, msg3Hash);
        kilometerage = 0;

        //TODO: Remove certificate of car (e.g. by setting it to null)
        autoIDStored = null; //Placeholder
        autoPubSKStored = null; //Placeholder

        byte[] succMsgB;
        try {
            succMsgB = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in waiting for message 2 carReturn");
            return;
        }
        Object[] succMsg = processMessage(succMsgB);
        byte success = (byte) succMsg[0];
        if(success != SUCCESS_BYTE){
            errorState("Wrong code, expected 0xFF");
            return;
        }
        short succNonce = (short) succMsg[1];
        if (!sc.areSubsequentNonces(nonceCard, succNonce, 2)){
            errorState("Wrong sequence number in success message of P4");
            return;
        }
        byte[] succHash = sc.unsign((byte[]) succMsg[3], rtPubSK);
        if(succHash != sc.createHash(prepareMessage(success,succNonce))){
            errorState("Invalid hash in success message of Protocol 4");
            return;
        }
    }

    private class SmartcardCrypto extends CryptoImplementation {


        public SmartcardCrypto(byte[] cardID, byte[] cardCertificate) {
            super.ID = cardID;
            super.certificate = cardCertificate;
            super.rc = new SmartCardWallet();
        }

        private class SmartCardWallet extends RSACrypto implements KeyWallet{

            private PrivateKey privk;
            private PublicKey pubk;

            @Override
            public void storePublicKey() {
                //TODO: Make sure only database is able to set key
            }

            @Override
            public void storePrivateKey() {
                //TODO: Make sure only database is able to set key
            }

            @Override
            public PublicKey getPublicKey() {
                return pubk;
            }
        }
    }


}