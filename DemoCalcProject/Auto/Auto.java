package Auto;

import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import rsa.CryptoImplementation;
import rsa.RSACrypto;
import utility.Logger;

import java.io.File;
import java.math.BigDecimal;
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

    public Auto(byte[] autoID, byte[] autoCertificate) {
        ac = new AutoCrypto(autoID, autoCertificate);
        File logFile = new File(Arrays.toString(autoID) +"_auto_log.txt");
        autoLogger = new Logger(logFile);
    }

    public PublicKey authenticateSmartCard(Smartcard sc){
        byte[] msg1b;
        try {
            msg1b = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            autoLogger.warning("Aborting: timeout", "authenticateSmartCard message 1", cardID);
            return (PublicKey) errorState("Timeout in msg1 authenticate smartcard");
        }
        Object[] msg1o = processMessage(msg1b);
        scPubSK = (PublicKey) msg1o[0];
        cardID = (byte[]) msg1o[1];
        byte[] scCertHashSign = (byte[]) msg1o[2];
        byte[] scCertHash = ac.unsign(scCertHashSign, dbPubSK);
        byte[] cardIDPubSKHash = ac.createHash(prepareMessage(scPubSK, cardID));
        if (scCertHash != cardIDPubSKHash){
            errorState("Invalid cerificate: hash does not match");
            autoLogger.fatal("Invalid cerificate: hash does not match", "authenticateSmartCard message 1", cardID);
            return null;
        }
        short cardNonce = (short) msg1o[3];
        short autoNonce = ac.generateNonce();
        byte[] cardNonceBytes = prepareMessage(cardNonce);
        byte[] cardNonceHashSign = ac.hashAndSign(cardNonceBytes);
        send(sc, ac.getCertificate(), cardNonce, cardNonceHashSign, autoNonce);
        byte[] msg3b = new byte[0];
        try {
            msg3b = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            autoLogger.warning("Aborting: Timeout", "authenticateSmartCard message 3", cardID);
            return (PublicKey) errorState("Timeout in msg3 authenticate smartcard");
        }
        Object[] msg3o = processMessage(msg3b);
        short autoNonceResp = (short) msg3o[0];
        byte[] autoNonceRespHashSign = (byte[]) msg3o[1];
        byte[] autoNonceRespHash = ac.unsign(autoNonceRespHashSign, scPubSK);
        byte[] autoNonceHash = ac.createHash(prepareMessage(autoNonce));
        if (autoNonceRespHash != autoNonceHash){
            //TODO: throw error or something (logs). Also stop further actions.
            errorState("Wrong nonce in P1 msg3 returned");
            autoLogger.fatal("Wrong nonce returned", "authenticateSmartCard message 3", cardID);
            return null;
        }
        else{
            cardAuthenticated = true;
            send(sc, SUCCESS_BYTE, (short) (cardNonce + 1), ac.hashAndSign(prepareMessage(SUCCESS_BYTE, (short) (cardNonce + 1))));
            return scPubSK;
            //TODO: log success?
        }

    }

    public void kilometerageUpdate(Smartcard sc){
        if(!cardAuthenticated){
            return;
        }
        byte[] curKmm = prepareMessage(kilometerage);
        byte[] kmmSigned = ac.hashAndSign(curKmm);
        send(sc, (Object) kmmSigned);
        byte[] confirmation = new byte[0];
        try {
            confirmation = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in waiting for update confirmation kilomerage Update");
            return;
        }
        Object[] confirmO = processMessage(confirmation);
        byte confBYTE = (byte) confirmO[0];
        int curKmmCard = (int) confirmO[1];
        if (kilometerage != curKmmCard){
            //TODO: Log discrepancy
        }
        byte[] confHashSigned = (byte[]) confirmO[2];
        byte[] confHash = ac.unsign(confHashSigned, scPubSK);
        byte[] hashValidation = ac.createHash(prepareMessage(confBYTE, curKmmCard));
        if (confHash != hashValidation){
            //TODO: Throw error and log failure
        } else {
            //TODO: Log success
        }
    }

    private static class AutoCrypto extends CryptoImplementation {

        public AutoCrypto(byte[] autoID, byte[] autoCertificate) {
            super.ID = autoID;
            super.certificate = autoCertificate;
            super.rc = new AutoWallet();
        }

        private static class AutoWallet extends RSACrypto implements KeyWallet {


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