package Smartcard;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class Smartcard implements Receivable, Communicator {
    private SmartcardCrypto sc;
    public PublicKey dbPubSK;
    private boolean manipulation;

    public Smartcard(byte[] cardID, byte[] cardCertificate) {
        sc = new SmartcardCrypto(cardID, cardCertificate);
        manipulation = false;
    }

    public void send(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }



    public void insert(Auto auto){ //P1
        UUID nonceCard = sc.generateNonce();
        send(auto, sc.getCertificate(), nonceCard);
        byte[] msg2b = waitForInput();
        Object[] msg2o = processMessage(msg2b);
        PublicKey autoPubSK = (PublicKey) msg2o[0];
        byte[] autoID = (byte[]) msg2o[1];
        byte[] autoCertHashSign = (byte[]) msg2o[2];
        byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);

        byte[] autoIDPubSKHash = sc.createHash(prepareMessage(autoPubSK, autoID));
        if (autoCertHash != autoIDPubSKHash){
            //TODO: throw error or something (tamper bit). Also stop further actions.
            manipulation = true;
            return;
        }

        UUID nonceCardResponse = (UUID) msg2o[3];
        if (nonceCard != nonceCardResponse){
            manipulation = true;
            return; //Placeholder
        }
        byte[] nonceCardResponseHashSign = (byte[]) msg2o[4];
        byte[] nonceCardResponseHash = sc.unsign(nonceCardResponseHashSign, autoPubSK);

        byte[] nonceValidHash = sc.createHash(prepareMessage(nonceCard));
        if (nonceValidHash != nonceCardResponseHash){
            //TODO: throw error or something (tamper bit). Also stop further actions.
            manipulation = true;
            return; //Placeholder probably
        }
        UUID nonceAuto = (UUID) msg2o[5];
        byte[] msg3tmp = prepareMessage(nonceAuto);
        byte[] nonceAutoHashSign = sc.hashAndSign(msg3tmp);
        send(auto, nonceAuto, nonceAutoHashSign);
    }



    @Override
    public void receive(byte[] message) {
        inputQueue.add(message);
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