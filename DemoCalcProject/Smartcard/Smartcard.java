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
    boolean terminalAuthenticated = false; //in temporary storage
    private UUID nonceReception; //TEMP because this should be yeeted when card is pulled out
    private UUID nonceCard; //TEMP same as above

    //This should actually be stored somehow?
    private byte[] autoIDStored;
    private PublicKey autoPubSKstored;

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

    /*Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    public void authReception(ReceptionTerminal reception) {
        // How does the card know if it is in a terminal or a card?
        // Potential solution: terminal or auto sends a basic message like "terminal!" or  "auto!"
        //note for P1: overleaf states you send 2 nonces in step 4. Current algorithm sends only 1.
        nonceCard = sc.generateNonce();
        send(reception, sc.getCertificate(), nonceCard); //Step 2
        byte[] response = waitForInput(); //Step 4
        Object[] responseData = processMessage(response);

        PublicKey receptionPubSK = (PublicKey) responseData[0];
        byte[] receptionID = (byte[]) responseData[1];
        byte[] receptionCertHashSign = (byte[]) responseData[2];
        nonceReception = (UUID) responseData[3];
        byte[] receptionCertHash = sc.unsign(receptionCertHashSign, dbPubSK);

        byte[] receptionIDPubSKHash = sc.createHash(prepareMessage(receptionPubSK, receptionID));
        if (receptionCertHash != receptionIDPubSKHash){ //Step 5
            manipulation = true;
            //TODO: Send message to terminal that process is stopped
            return null;
        }
        byte[] noncePrepped = prepareMessage(nonceReception);
        byte[] nonceReceptionHashSign = sc.hashAndSign(noncePrepped);
        send(reception, nonceReceptionHashSign); //Step 6

        byte[] response2 = waitForInput();
        Object[] responseData2 = processMessage(response2);

        byte[] cardNonceUnsigned = sc.unsign(responseData2[0], cardPubSK);
        byte[] nonceCardHash = sc.createHash(prepareMessage(nonceCard));
        if (nonceCardHash != cardNonceUnsigned){ //Step 9
            //TODO: Error
            return null;
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
        send(reception, giveCarSigned); //Step 2

        byte[] response = waitForInput();
        Object[] responseData = processMessage(response);

        byte[] autoPubSK = (PublicKey) responseData[0];
        byte[] autoID = (byte[]) responseData[1];
        byte[] autoCertHashSign = (byte[]) responseData[2];
        UUID nonceCard2 = (UUID) responseData[3];
        if (nonceCard2 != nonceCard+1){ //Step 7 - Sequence
            //TODO: Error
            return null;
        }

        byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);

        byte[] autoIDPubSKHash = sc.createHash(prepareMessage(autoPubSK, autoID));
        if (autoCertHash != autoIDPubSKHash){ //Step 7 - certificate
            manipulation = true;
            //TODO: Send message to terminal that process is stopped
            return null;
        }
        autoIDStored = autoID;
        autoPubSKStored = autoPubSK; //Step 8
        //State transition????

        //Success message!

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