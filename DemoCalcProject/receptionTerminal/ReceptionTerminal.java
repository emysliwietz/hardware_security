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
    boolean cardAuthenticated = false;
    UUID termNonce; //Placeholder
    UUID scNonce; //Placeholder


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