package Auto;

import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.math.BigDecimal;
import java.security.PublicKey;
import java.util.UUID;

public class Auto implements Receivable, Communicator {

    private AutoCrypto ac;
    public PublicKey dbPubSK;
    private boolean cardAuthenticated = false;
    private int kilometerage = 0;

    public Auto(byte[] autoID, byte[] autoCertificate) {
        ac = new Auto.Auto.AutoCrypto(autoID, autoCertificate);
    }

    public PublicKey authenticateSmartCard(Smartcard sc){
        byte[] msg1b = waitForInput();
        Object[] msg1o = processMessage(msg1b);
        PublicKey scPubSK = (PublicKey) msg1o[0];
        byte[] cardID = (byte[]) msg1o[1];
        byte[] scCertHashSign = (byte[]) msg1o[2];
        byte[] scCertHash = ac.unsign(scCertHashSign, dbPubSK);
        // TODO: Validate hash
        byte[] cardIDPubSKHash = ac.createHash(prepareMessage(scPubSK, cardID));
        if (scCertHash != cardIDPubSKHash){
            //TODO: throw error or something (logs). Also stop further actions.
        }
        UUID cardNonce = (UUID) msg1o[3];
        UUID autoNonce = ac.generateNonce();
        byte[] cardNonceBytes = prepareMessage(cardNonce);
        byte[] cardNonceHashSign = ac.hashAndSign(cardNonceBytes);
        send(sc, ac.getCertificate(), cardNonce, cardNonceHashSign, autoNonce);
        byte[] msg3b = waitForInput();
        Object[] msg3o = processMessage(msg3b);
        UUID autoNonceResp = (UUID) msg3o[0];
        byte[] autoNonceRespHashSign = (byte[]) msg3o[1];
        byte[] autoNonceRespHash = ac.unsign(autoNonceRespHashSign, scPubSK);
        //TODO: Validate hash and log success/failure
        byte[] autoNonceHash = ac.createHash(prepareMessage(autoNonce));
        if (autoNonceRespHash != autoNonceHash){
            //TODO: throw error or something (logs). Also stop further actions.
            return null;
        }
        else{
            cardAuthenticated = true;
            return scPubSK;
            //TODO: log success?
        }

    }

    public void kilometerageUpdate(PublicKey scPubSK, Smartcard sc){
        if(!cardAuthenticated){
            return;
        }
        byte[] curKmm = prepareMessage(kilometerage);
        byte[] kmmSigned = ac.hashAndSign(curKmm);
        send(sc, (Object) kmmSigned);
        //TODO: Need waitForInput with timeout
        byte[] confirmation = waitForInput();
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