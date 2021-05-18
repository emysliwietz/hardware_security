package Auto;

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
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.UUID;

public class Auto implements Receivable, Communicator {

    private AutoCrypto ac;
    public PublicKey dbPubSK;
    private boolean cardAuthenticated = false;
    private int kilometerage = 0;
    public PublicKey scPubSK;
    private Logger autoLogger;
    private byte[] cardID  = null;
    private ByteBuffer msgBuf = ByteBuffer.allocate(256);

    @Override
    public Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        cardAuthenticated = false;
        cardID = null;
        return null;
    }

    public Auto(byte[] autoID, byte[] autoCertificate, PrivateKey privateKey) {
        ac = new AutoCrypto(autoID, autoCertificate, privateKey);
        File logFile = new File(Arrays.toString(autoID) +"_auto_log.txt");
        autoLogger = new Logger(logFile);
    }

    //Protocol 1
    public PublicKey authenticateSmartCard(Smartcard sc){
        //Message 1
        ByteBuffer msg1;
        try {
            msg1 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            autoLogger.warning("Aborting: timeout", "authenticateSmartCard message 1", cardID);
            return (PublicKey) errorState("Timeout in msg1 authenticate smartcard");
        }
        int curBufIndex = 0;
        int scCertHashSignLen = msg1.getInt(curBufIndex);
        curBufIndex += 4;

        //scPubSK + cardID
        byte[] scPubSKEncoded = new byte[128];
        msg1.get(scPubSKEncoded,curBufIndex,128);
        curBufIndex += 128;
        scPubSK = bytesToPubkey(scPubSKEncoded);
        cardID = new byte[5];
        msg1.get(cardID,curBufIndex,5);
        curBufIndex += 5;

        //scCertHash signature
        byte[] scCertHashSign = new byte[scCertHashSignLen];
        msg1.get(scCertHashSign,curBufIndex,scCertHashSignLen);
        curBufIndex += scCertHashSignLen;
        byte[] scCertHash = ac.unsign(scCertHashSign, dbPubSK);
        byte[] cardIDPubSKHash = ac.createHash(concatBytes(scPubSK.getEncoded(), cardID));
        if (scCertHash != cardIDPubSKHash){
            errorState("Invalid cerificate: hash does not match");
            autoLogger.fatal("Invalid cerificate: hash does not match", "authenticateSmartCard message 1", cardID);
            return null;
        }

        //Nonces
        short cardNonce = msg1.getShort(curBufIndex);

        //Message 2
        curBufIndex = 0;
        short autoNonce = ac.generateNonce();
        byte[] cardNonceHashSign = ac.hashAndSign(shortToByteArray(cardNonce));
        msgBuf.putInt(ac.getCertificate().length - 133);
        msgBuf.put(ac.getCertificate());
        msgBuf.putShort(cardNonce);
        msgBuf.putInt(cardNonceHashSign.length);
        msgBuf.put(cardNonceHashSign);
        msgBuf.putShort(autoNonce);
        send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 3
        ByteBuffer msg3 = msg1;
        try {
            msg3 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            autoLogger.warning("Aborting: Timeout", "authenticateSmartCard message 3", cardID);
            return (PublicKey) errorState("Timeout in msg3 authenticate smartcard");
        }
        //
        short autoNonceResp = msg3.getShort(0);
        byte[] autoNonceRespHashSignLenByte = new byte[4];
        msg3.get(autoNonceRespHashSignLenByte,2,4);
        int autoNonceRespHashSignLen = intFromByteArray(autoNonceRespHashSignLenByte);
        byte[] autoNonceRespHashSign = new byte[autoNonceRespHashSignLen];
        byte[] autoNonceRespHash = ac.unsign(autoNonceRespHashSign, scPubSK);
        byte[] autoNonceHash = ac.createHash(shortToByteArray(autoNonce));
        if (autoNonceRespHash != autoNonceHash){
            //TODO: throw error or something (logs). Also stop further actions.
            errorState("Wrong nonce in P1 msg3 returned");
            autoLogger.fatal("Wrong nonce returned", "authenticateSmartCard message 3", cardID);
            return null;
        }
        else{
            //Success message
            cardAuthenticated = true;
            msgBuf.put(SUCCESS_BYTE);
            msgBuf.putShort((short) (cardNonce + 1));
            byte[] succByte = {SUCCESS_BYTE};
            msgBuf.putInt(ac.hashAndSign(concatBytes(succByte, shortToByteArray((short) (cardNonce + 1)))).length).put(ac.hashAndSign(concatBytes(succByte, shortToByteArray((short) (cardNonce + 1)))));
            send(sc, msgBuf);
            msgBuf.clear();
            msgBuf.rewind();
            autoLogger.info("Card successfully authenticated", "authenticateSmartCard", cardID);
            return scPubSK;
        }

    }

    public void kilometerageUpdate(Smartcard sc){
        if(!cardAuthenticated){
            errorState("Card not authenticated in kilometerageUpdate");
            autoLogger.warning("Aborting: Card not authenticated", "kilometerageUpdate", cardID);
            return;
        }
        //Message 1
        msgBuf.putInt(kilometerage).putInt(ac.hashAndSign(intToByteArray(kilometerage)).length).put(ac.hashAndSign(intToByteArray(kilometerage)));
        send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 2
        ByteBuffer confirmation;
        try {
            confirmation = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in waiting for update confirmation kilomerage Update");
            autoLogger.warning("Aborting: Timeout", "kilometerageUpdate wait for update", cardID);
            return;
        }
        byte confBYTE = confirmation.get();
        int curKmmCard = confirmation.getInt();
        if (kilometerage != curKmmCard){
            errorState("Kilometerage does not match");
            autoLogger.warning("Kilometerage does not match, possible tampering. Please check.", "kilometerageUpdate", cardID);
        }
        int confHashSignLen = confirmation.getInt();
        byte[] confHashSigned = new byte[confHashSignLen];
        confirmation.get(confHashSigned,9,confHashSignLen);
        byte[] confHash = ac.unsign(confHashSigned, scPubSK);
        byte[] hashValidation = ac.createHash(prepareMessage(confBYTE, curKmmCard));
        if (confHash != hashValidation){
            errorState("Invalid Hash in kilometerageUpdate");
            autoLogger.fatal("Invalid Hash", "kilometerageUpdate", cardID);
        } else {
            autoLogger.info("Kilometerage successfully updated", "kilometerageUpdate", cardID);
        }
    }

    private static class AutoCrypto extends CryptoImplementation {

        public AutoCrypto(byte[] autoID, byte[] autoCertificate, PrivateKey privateKey) {
            super.ID = autoID;
            super.certificate = autoCertificate;
            super.rc = new AutoWallet();
            ((KeyWallet) super.rc).storePrivateKey(privateKey);
        }

        private static class AutoWallet extends RSACrypto implements KeyWallet {


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