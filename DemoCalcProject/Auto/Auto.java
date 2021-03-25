package Auto;

import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.security.PublicKey;
import java.util.UUID;

public class Auto implements Receivable, Communicator {

    private AutoCrypto ac;
    public PublicKey dbPubSK;

    @Override
    public void receive(byte[] message) {
        inputQueue.add(message);
    }

    public void send(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }

    public void authenticateSmartCard(Smartcard sc){
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
        }
        else{
            //TODO: log success?
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