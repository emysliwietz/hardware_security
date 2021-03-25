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

    public Smartcard(byte[] cardID, byte[] cardCertificate) {
        sc = new SmartcardCrypto(cardID, cardCertificate);
    }

    public void send(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }



    public void insert(Auto auto){
        UUID nonceCard = sc.generateNonce();
        send(auto, sc.getCertificate(), nonceCard);
        byte[] msg2b = waitForInput();
        Object[] msg2o = processMessage(msg2b);
        PublicKey autoPubSK = (PublicKey) msg2o[0];
        byte[] autoID = (byte[]) msg2o[1];
        byte[] autoCertHashSign = (byte[]) msg2o[2];
        byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);
        //TODO: create and validate hash
        UUID nonceCardResponse = (UUID) msg2o[3];
        if (nonceCard != nonceCardResponse){
            return; //Placeholder
        }
        byte[] nonceCardResponseHashSign = (byte[]) msg2o[4];
        byte[] nonceCardResponseHash = sc.unsign(nonceCardResponseHashSign, autoPubSK);
        //TODO: create and validate hash
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