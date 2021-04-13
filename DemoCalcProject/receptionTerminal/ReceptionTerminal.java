package receptionTerminal;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.math.BigDecimal;
import java.security.PublicKey;
import java.util.UUID;

public class ReceptionTerminal implements Receivable, Communicator {

    private ReceptionTerminal.RTCrypto rtc;
    public PublicKey dbPubSK;
    private boolean cardAuthenticated = false;
    private UUID termNonce; //Placeholder
    private UUID scNonce; //Placeholder
    private byte[] cardPubSK; //TEMP until better solution
    private byte[] cardID; //TEMP see above
    private Database database; //who knows at this point



    @Override
    public void receive(byte[] message) {
        inputQueue.add(message);
    }

    public void send(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }

    public ReceptionTerminal(byte[] rtID, byte[] rtCertificate) {
        rtc = new receptionTerminal.ReceptionTerminal.RTCrypto(rtID, rtCertificate);
    }

    public void carReturn(Smartcard sc, PublicKey scPubSK){
        if (!cardAuthenticated){
            return; //TODO: Placeholder
        }
        byte[] msg1b = waitForInput();
        Object[] msg1o = processMessage(msg1b);
        int seqNum = (int) msg1o[1];
        //TODO: Check sequence number
        boolean manipulation = (boolean) msg1o[2];
        byte[] msg1Hash = rtc.unsign(((byte[]) msg1o[3]), scPubSK);
        byte[] msg1ConfHash = rtc.createHash(prepareMessage(((byte) msg1o[0]), seqNum, manipulation));
        if(msg1Hash != msg1ConfHash){
            //TODO: Error
        }
        if (manipulation){
            //TODO: Throw exception/error
        }
        UUID kmmNonce = rtc.generateNonce();
        int seqNum2 = 0; //Placeholder
        byte[] msg2Sign = rtc.hashAndSign(prepareMessage(kmmNonce, seqNum2));
        send(sc, kmmNonce, seqNum2, msg2Sign);
        byte[] msg3b = waitForInput();
        Object[] msg3 = processMessage(msg3b);
        int kilometerage = (int) msg3[0];
        UUID kmmNonceResp = (UUID) msg3[1];
        if(kmmNonce != kmmNonceResp){
            //TODO: Error
        }
        int seqNum3 = (int) msg3[2];
        byte[] msg3Hash = rtc.unsign(((byte[]) msg3[3]),scPubSK);
        byte[] validMsg3Hash = rtc.createHash(prepareMessage(kilometerage, kmmNonceResp, seqNum3));
        if(msg3Hash != validMsg3Hash){
            //TODO: Error
        }
    }

    /*Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    private void cardAuthentication(Smartcard sc){
        byte[] response = waitForInput(); //Step 2
        Object[] responseData = processMessage(response);

        cardPubSK = (PublicKey) responseData[0];
        byte[] cardID = (byte[]) responseData[1];
        byte[] cardCertHashSign = (byte[]) responseData[2];
        scNonce = (UUID) responseData[3];
        byte[] cardCertHash = sc.unsign(cardCertHashSign, dbPubSK);

        byte[] cardIDPubSKHash = sc.createHash(prepareMessage(cardPubSK, cardID));
        if (cardCertHash != cardIDPubSKHash){ //Step 3
            //TODO: Error
            return null;
        }

        termNonce = sc.generateNonce();
        send(sc, sc.getCertificate(), termNonce); //Step 4

        byte[] response2 = waitForInput();
        Object[] responseData2 = processMessage(response2);

        byte[] receptionNonceUnsigned = sc.unsign(responseData2[0], cardPubSK);
        byte[] nonceReceptionHash = sc.createHash(prepareMessage(nonceReception));
        if (nonceReceptionHash != receptionNonceUnsigned){ //Step 7
            //TODO: Error
            return null;
        }

        byte[] noncePrepped = prepareMessage(scNonce);
        byte[] nonceCardHashSign = sc.hashAndSign(noncePrepped);
        send(sc, nonceCardHashSign); //Step 8

        //Do we want some succes message back?
        cardAuthenticated = true; //When to make it false again

    }

    /*Protocol 3 - Assignment of car to smartcard */
    public void carAssignment(Smartcard sc){
        if (!cardAuthenticated){ //Step 1
            return; //TODO: Placeholder
        }

        byte[] response = waitForInput();
        Object[] responseData = processMessage(response);

        byte[] giveCarUnsigned = sc.unsign(responseData[0], cardPubSK);
        byte[] giveCarHash = sc.createHash(prepareMessage(nonceReception+1)); //We still dont know if this works
        if (giveCarUnsigned != giveCarHash){ //Step 3
            //TODO: Error
            return null;
        }

        byte[] message = prepareMessage(cardID);
        send(database, message); //Step 4

        byte[] response2 = waitForInput();
        Object[] responseData2 = processMessage(response2);
        byte[] autoPubSK = (PublicKey) responseData[0];
        byte[] autoID = (byte[]) responseData[1];
        byte[] autoCertHashSign = (byte[]) responseData[2];

        System.out.println(autoID); //Step 5 - Kinda filler, maybe later so process doesnt get aborted
        byte[] cert = prepareMessage(autoPubSk, autoID, autoCertHashSign, scNonce+1); //who knows if this works
        send(sc, cert);//Step 6

        // Success message?
    }

    private static class RTCrypto extends CryptoImplementation {

        public RTCrypto(byte[] rtID, byte[] rtCertificate) {
            super.ID = rtID;
            super.certificate = rtCertificate;
            super.rc = new RTWallet();
        }

        private static class RTWallet extends RSACrypto implements KeyWallet {


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