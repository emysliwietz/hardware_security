package Smartcard;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import db.Database;
import receptionTerminal.ReceptionTerminal;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Smartcard implements Communicator {
    private SmartcardCrypto sc;
    public PublicKey dbPubSK;
    private boolean manipulation = false;
    private int kilometerage; //TODO: Change to less storage intensive type (e.g. short or int)
    boolean terminalAuthenticated = false; //in temporary storage
    private short nonceReception; //TEMP because this should be yeeted when card is pulled out
    private short nonceCard; //TEMP same as above
    public PublicKey rtPubSK;

    //This should actually be stored somehow?
    private byte[] autoIDStored;
    public PublicKey autoPubSK;
    public enum States{EMPTY, ASSIGNED_NONE, ASSIGNED, END_OF_LIFE}
    public States state = States.EMPTY;
    private ByteBuffer msgBuf = ByteBuffer.allocate(256);


    public Smartcard(byte[] cardID, byte[] cardCertificate, PrivateKey privateKey) {
        sc = new SmartcardCrypto(cardID, cardCertificate, privateKey);
        state = States.ASSIGNED_NONE;
    }


    public PublicKey insert(Auto auto){ //P1
        short nonceCard = sc.generateNonce();
        send(auto, sc.getCertificate(), nonceCard);
        byte[] msg2b = new byte[0];
        try {
             msg2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return (PublicKey) errorState("Timeout in insert");
        }

        //autoPubSK
        byte[] autoPubSKEncoded = new byte[128];
        msg2.get(autoPubSKEncoded,0,128);
        autoPubSK = bytesToPubkey(autoPubSKEncoded);

        //autoID
        byte[] autoID = new byte[5];
        msg2.get(autoID,128,5);

        //signature of hash of certificate
        int certSignLen = msg2.getInt(133);
        byte[] autoCertHashSign = new byte[certSignLen];
        msg2.get(autoCertHashSign,137,certSignLen);
        byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);
        byte[] autoIDPubSKHash = sc.createHash(concatBytes(autoPubSK.getEncoded(), autoID));
        if (autoCertHash != autoIDPubSKHash){
            //TODO: throw error or something (tamper bit). Also stop further actions.
            errorState("Invalid certificate send in message 2 of P1");
            manipulation = true;
            return null;
        }

        //Response of nonceCard
        short nonceCardResponse = msg2.getShort(137+certSignLen);
        int curBufIndex = 139 + certSignLen;
        if (nonceCard != nonceCardResponse){
            errorState("Wrong nonce returned in message 2 of P1");
            manipulation = true;
            return null; //Placeholder
        }

        //signed hash of nonceCard
        int msg2NonceSignLen = msg2.getInt(curBufIndex);
        curBufIndex += 4;
        byte[] nonceCardResponseHashSign = new byte[msg2NonceSignLen];
        msg2.get(nonceCardResponseHashSign,curBufIndex,msg2NonceSignLen);
        curBufIndex += msg2NonceSignLen;
        byte[] nonceCardResponseHash = sc.unsign(nonceCardResponseHashSign, autoPubSK);
        byte[] nonceValidHash = sc.createHash(prepareMessage(nonceCard));
        if (nonceValidHash != nonceCardResponseHash){
            //TODO: throw error or something (tamper bit). Also stop further actions.
            errorState("Invalid hash of nonce returned in message 2 of P1");
            manipulation = true;
            return null; //Placeholder probably
        }

        //nonceAuto
        short nonceAuto = msg2.getShort(curBufIndex);

        //Message 3
        msgBuf.putShort(nonceAuto);
        msgBuf.put(sc.hashAndSign(shortToByteArray(nonceAuto)));
        send(auto, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Success message
        ByteBuffer succMb = msg2; //Recycling buffer to save storage
        try {
            succMb = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return (PublicKey) errorState("Timeout in insert");
        }
        byte success = succMb.get(0);
        if(success != SUCCESS_BYTE){
            errorState("Wrong code, expected 0xFF");
            return null;
        }
        short nonceSucc = succMb.getShort(1);
        if (!sc.areSubsequentNonces(nonceCard, nonceSucc)){
            errorState("Wrong nonce in success message of P1");
            return null;
        }
        int nonceSuccSignLen = succMb.getInt(3);
        byte[] succMHashSign = new byte[nonceSuccSignLen];
        succMb.get(succMHashSign,7,nonceSuccSignLen);
        byte[] succMHash = sc.unsign(succMHashSign, autoPubSK);
        byte[] succByte = {success};
        if((sc.createHash(succByte)) != succMHash){
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

        rtPubSK = (PublicKey) responseData[0];
        byte[] receptionID = (byte[]) responseData[1];
        byte[] receptionCertHashSign = (byte[]) responseData[2];
        nonceReception = (short) responseData[3];
        byte[] receptionCertHash = sc.unsign(receptionCertHashSign, dbPubSK);

        byte[] receptionIDPubSKHash = sc.createHash(prepareMessage(rtPubSK, receptionID));
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
        byte[] cardNonceHash = sc.unsign((byte[]) responseData2[1], rtPubSK);
        byte[] nonceCardHashValid = sc.createHash(prepareMessage(success, nonceCard));
        if (nonceCardHashValid != cardNonceHash){ //Step 9
            errorState("Invalid hash in message 4 of P2");
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

        autoPubSK = (PublicKey) responseData[0];
        byte[] autoID = (byte[]) responseData[1];
        byte[] autoCertHashSign = (byte[]) responseData[2];
        short nonceCard2 = (short) responseData[3];
        if (nonceCard2 != ((short) (nonceCard+1))){ //Step 7 - Sequence
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
        //State transition????
        state = States.ASSIGNED;
        //Success message!
        send(reception, SUCCESS_BYTE, (short) (nonceReception+2), sc.createHash(prepareMessage(SUCCESS_BYTE, (short) (nonceReception+2))));
    }

    public void kilometerageUpdate(Auto auto){
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

    public void carReturn(ReceptionTerminal rt){
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
        state = States.ASSIGNED_NONE;
        autoIDStored = null; //Placeholder
        autoPubSK = null; //Placeholder

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


        public SmartcardCrypto(byte[] cardID, byte[] cardCertificate, PrivateKey privateKey) {
            super.ID = cardID;
            super.certificate = cardCertificate;
            super.rc = new SmartCardWallet();
            ((KeyWallet) super.rc).storePrivateKey(privateKey);
        }

        private class SmartCardWallet extends RSACrypto implements KeyWallet{

            private PrivateKey privk;
            private PublicKey pubk;

            @Override
            public void storePublicKey() {
                //TODO: Make sure only database is able to set key
            }

            @Override
            public void storePrivateKey(PrivateKey privateKey) {
                //TODO: Make sure only database is able to set key
                super.privk = privateKey;
            }

            @Override
            public PublicKey getPublicKey() {
                return pubk;
            }
        }
    }


}