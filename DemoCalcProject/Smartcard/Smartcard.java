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

public class Smartcard implements Receivable, Communicator {
    private SmartcardCrypto sc;
    public PublicKey dbPubSK;
    private boolean manipulation = false;
    private int kilometerage; //TODO: Change to less storage intensive type (e.g. short or int)

    public Smartcard(byte[] cardID, byte[] cardCertificate) {
        sc = new SmartcardCrypto(cardID, cardCertificate);
    }

    public void send(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }



    public PublicKey insert(Auto auto){ //P1
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
            return null;
        }

        UUID nonceCardResponse = (UUID) msg2o[3];
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
        UUID nonceAuto = (UUID) msg2o[5];
        byte[] msg3tmp = prepareMessage(nonceAuto);
        byte[] nonceAutoHashSign = sc.hashAndSign(msg3tmp);
        send(auto, nonceAuto, nonceAutoHashSign);
        return autoPubSK;
    }

    public void kilometerageUpdate(Auto auto, PublicKey autoPubSK){
        byte[] receivedKmm = waitForInput();
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
        int seqNum1 = 0; //Placeholder
        byte[] msg1Hash = sc.hashAndSign(prepareMessage(((byte) 56), seqNum1, manipulation));
        send(rt, (byte) 56, seqNum1, manipulation, msg1Hash);
        byte[] msg2b = waitForInput();
        Object[] msg2 = processMessage(msg2b);
        UUID kmmNonce = (UUID) msg2[0];
        int seqNum2 = (int) msg2[1]; //Placeholder
        byte[] msg2Hash = sc.unsign((byte[]) msg2[2], rtPubSK);
        byte[] validMsg2Hash = sc.createHash(prepareMessage(kmmNonce, seqNum2));
        if(msg2Hash != validMsg2Hash){
            //TODO: Error; also check sequence number (not in this if clause (obviously))
        }
        byte[] msg3Hash = sc.hashAndSign(prepareMessage(kilometerage, kmmNonce, seqNum1 + 1));
        send(rt, kilometerage, kmmNonce, seqNum1 + 1, msg3Hash);
        kilometerage = 0;
        //TODO: Remove certificate of car (e.g. by setting it to null)
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