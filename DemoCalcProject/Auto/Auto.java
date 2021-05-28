package Auto;

import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import Smartcard.Smartcard;
import com.licel.jcardsim.utils.AIDUtil;
import db.Database;
import javacard.framework.AID;
import rsa.CryptoImplementation;
import rsa.RSACrypto;
import utility.Logger;

import java.io.File;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;
import javax.smartcardio.*;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.smartcardio.CardSimulator;

public class Auto implements Receivable, Communicator {

    static final byte[] SC_APPLET_AID = {
            (byte) 0x3B,
            (byte) 0x29,
            (byte) 0x63,
            (byte) 0x61,
            (byte) 0x6C,
            (byte) 0x63,
            (byte) 0x01
    };
    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, SC_APPLET_AID);
    CardChannel applet;

    private AutoCrypto ac;
    public PublicKey dbPubSK;
    private boolean cardAuthenticated = false;
    private int kilometerage = 0;
    public PublicKey scPubSK;
    private Logger autoLogger;
    private byte[] cardID  = null;
    private ByteBuffer msgBuf = ByteBuffer.allocate(256);
    int offset;

    @Override
    public Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        cardAuthenticated = false;
        cardID = null;
        return null;
    }

    private ResponseAPDU sendAPDU(int cla, int ins, ByteBuffer data) {
        CommandAPDU commandAPDU = new CommandAPDU(cla,ins,0,0,data.array(),data.arrayOffset(),data.array().length);
        try {
            return applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return null;
        }
    }

    public Auto(byte[] autoID, byte[] autoCertificate, PrivateKey privateKey) {
        ac = new AutoCrypto(autoID, autoCertificate, privateKey);
        File logFile = new File(Base64.getEncoder().encodeToString(autoID) +"_auto_log.txt");
        autoLogger = new Logger(logFile);
        (new SimulatedCardThread()).start();
    }

    public void authenticateSCInitiate(){
        CommandAPDU start = new CommandAPDU(CARD_AUTH,INSERT_START,0,0,256);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(start);
        } catch (CardException e) {
            e.printStackTrace();
            return;
        }
        authenticateSmartCard(apdu);
    }

    //Protocol 1
    public void authenticateSmartCard(ResponseAPDU apdu){
        //Message 1
        offset = 0;
        ByteBuffer msg1 = ByteBuffer.wrap(apdu.getData());
        /*try {
            msg1 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            autoLogger.warning("Aborting: timeout", "authenticateSmartCard message 1", cardID);
            return (PublicKey) errorState("Timeout in msg1 authenticate smartcard");
        }*/
        int scCertHashSignLen = msg1.getInt(offset);
        offset += 4;

        //scPubSK + cardID
        byte[] scPubSKEncoded = new byte[KEY_LEN];
        msg1.get(scPubSKEncoded,offset,KEY_LEN);
        offset += KEY_LEN;
        scPubSK = bytesToPubkey(scPubSKEncoded);
        cardID = new byte[5];
        msg1.get(cardID,offset,5);
        offset += 5;

        //scCertHash signature
        byte[] scCertHashSign = new byte[scCertHashSignLen];
        msg1.get(scCertHashSign,offset,scCertHashSignLen);
        offset += scCertHashSignLen;
        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[KEY_LEN + 5]);
        msg1Cmps.put(scPubSKEncoded).put(cardID);
        //byte[] scCertHash = ac.unsign(scCertHashSign, dbPubSK);
        //byte[] cardIDPubSKHash = ac.createHash(concatBytes(scPubSK.getEncoded(), cardID));
        if (!ac.verify(msg1Cmps,scCertHashSign,dbPubSK)){
            errorState("Invalid cerificate: hash does not match");
            autoLogger.fatal("Invalid cerificate: hash does not match", "authenticateSmartCard message 1", cardID);
            return;
        }

        //Nonces
        short cardNonce = msg1.getShort();

        //Message 2
        short autoNonce = ac.generateNonce();
        byte[] cardNonceHashSign = ac.sign(shortToByteArray(cardNonce));
        msgBuf.putInt(ac.getCertificate().length - 133);
        msgBuf.put(ac.getCertificate());
        msgBuf.putShort(cardNonce);
        msgBuf.putInt(cardNonceHashSign.length);
        msgBuf.put(cardNonceHashSign);
        msgBuf.putShort(autoNonce);
        apdu = sendAPDU(CARD_CONT,INSERT_M2,msgBuf);
        //send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 3
        offset=0;
        ByteBuffer msg3 = ByteBuffer.wrap(apdu.getData());
        /*try {
            msg3 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            autoLogger.warning("Aborting: Timeout", "authenticateSmartCard message 3", cardID);
            errorState("Timeout in msg3 authenticate smartcard");
            return;
        }*/
        //
        short autoNonceResp = msg3.getShort();
        offset+=2;
        byte[] autoNonceRespHashSignLenByte = new byte[4];
        msg3.get(autoNonceRespHashSignLenByte,offset,4);
        offset+=4;
        int autoNonceRespHashSignLen = intFromByteArray(autoNonceRespHashSignLenByte);
        byte[] autoNonceRespHashSign = new byte[autoNonceRespHashSignLen];
        msg3.get(autoNonceRespHashSign,offset,autoNonceRespHashSignLen);
        //byte[] autoNonceRespHash = ac.unsign(autoNonceRespHashSign, scPubSK);
        //byte[] autoNonceHash = ac.createHash(shortToByteArray(autoNonce));
        ByteBuffer msg3Cmps = ByteBuffer.wrap(new byte[2]);
        msg3Cmps.putShort(autoNonceResp);
        if (!ac.verify(msg3Cmps,autoNonceRespHashSign,scPubSK)){
            //TODO: throw error or something (logs). Also stop further actions.
            errorState("Wrong nonce in P1 msg3 returned");
            autoLogger.fatal("Wrong nonce returned", "authenticateSmartCard message 3", cardID);
        }
        else{
            //Success message
            cardAuthenticated = true;
            msgBuf.put(SUCCESS_BYTE);
            msgBuf.putShort((short) (cardNonce + 1));
            byte[] succByte = {SUCCESS_BYTE};
            msgBuf.putInt(ac.sign(concatBytes(succByte, shortToByteArray((short) (cardNonce + 1)))).length).put(ac.sign(concatBytes(succByte, shortToByteArray((short) (cardNonce + 1)))));
            sendAPDU(CARD_CONT,INSERT_MS,msgBuf);
            //send(sc, msgBuf);
            msgBuf.clear();
            msgBuf.rewind();
            autoLogger.info("Card successfully authenticated", "authenticateSmartCard", cardID);
        }

    }

    public void kilometerageUpdate(){
        if(!cardAuthenticated){
            errorState("Card not authenticated in kilometerageUpdate");
            autoLogger.warning("Aborting: Card not authenticated", "kilometerageUpdate", cardID);
            return;
        }
        //Message 1
        msgBuf.putInt(kilometerage).putInt(ac.sign(intToByteArray(kilometerage)).length).put(ac.sign(intToByteArray(kilometerage)));
        ResponseAPDU apdu = sendAPDU(CARD_PROC,KMM_UPDATE,msgBuf);
        //send(sc, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 2
        offset=0;
        ByteBuffer confirmation = ByteBuffer.wrap(apdu.getData());
        /*try {
            confirmation = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in waiting for update confirmation kilomerage Update");
            autoLogger.warning("Aborting: Timeout", "kilometerageUpdate wait for update", cardID);
            return;
        }*/
        byte confBYTE = confirmation.get();
        offset++;
        int curKmmCard = confirmation.getInt();
        offset+=4;
        if (kilometerage != curKmmCard){
            errorState("Kilometerage does not match");
            autoLogger.warning("Kilometerage does not match, possible tampering. Please check.", "kilometerageUpdate", cardID);
        }
        int confHashSignLen = confirmation.getInt();
        offset+=4;
        byte[] confHashSigned = new byte[confHashSignLen];
        confirmation.get(confHashSigned,offset,confHashSignLen);
        //byte[] confHash = ac.unsign(confHashSigned, scPubSK);
        //byte[] hashValidation = ac.createHash(prepareMessage(confBYTE, curKmmCard));
        ByteBuffer msgCmps = ByteBuffer.wrap(new byte[5]);
        msgCmps.put(confBYTE).putInt(curKmmCard);
        if (!ac.verify(msgCmps,confHashSigned,scPubSK)){
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

    class SimulatedCardThread extends Thread {
        public void run(){
            CardTerminals cardTerminals = CardTerminalSimulator.terminals(
                    Arrays.toString(ac.getID()));
            CardTerminal autoTerminal = cardTerminals.getTerminal(Arrays.toString(ac.getID()));
            CardSimulator smartcard = new CardSimulator();
            AID scAppletAID = AIDUtil.create(SC_APPLET_AID);
            smartcard.installApplet(scAppletAID,Smartcard.class);
            smartcard.assignToTerminal(autoTerminal);
            try{
                Card card = autoTerminal.connect("*");
                applet = card.getBasicChannel();
                ResponseAPDU resp = applet.transmit(SELECT_APDU);
                if(resp.getSW() != 0x9000){
                    throw new Exception("Select failed");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}