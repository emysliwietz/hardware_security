package Auto;

import Interfaces.CommunicatorExtended;
import Interfaces.KeyWallet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import rsa.CryptoImplementationExtended;
import rsa.RSACrypto;
import utility.Logger;

import javax.smartcardio.*;
import java.io.File;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 * @author Laura Philipse
 * @author Alessandra van Veen
 */
public class Auto extends CommunicatorExtended {


    public PublicKey dbPubSK;
    public PublicKey scPubSK;
    private final AutoCrypto ac;
    private int kilometerage = 0;
    private final Logger autoLogger;
    private int offset;
    private final CardSimulator smartcard;
    private final CardTerminals cardTerminals; //= CardTerminalSimulator.terminals(Arrays.toString(ac.getID()));
    private final CardTerminal autoTerminal; //= cardTerminals.getTerminal(Arrays.toString(ac.getID()));

    public Auto(byte[] autoID, byte[] autoCertificate, PrivateKey privateKey, PublicKey pubk, CardSimulator smartcard) {
        ac = new AutoCrypto(autoID, autoCertificate, privateKey);
        File logFile = new File(Base64.getEncoder().encodeToString(autoID) + "_auto_log.log");
        autoLogger = new Logger(logFile);
        super.logger = autoLogger;
        this.smartcard = smartcard;
        cardTerminals = CardTerminalSimulator.terminals(Arrays.toString(ac.getID()));
        autoTerminal = cardTerminals.getTerminal(Arrays.toString(ac.getID()));
        (new SimulatedCardThread()).start();
        dbPubSK = pubk;

    }


    /**
     * protocol 1 - mutual authentication between smartcard and car
     */
    public void authenticateSCInitiate() throws CardNotInitializedException, AuthenticationFailedException {
        select();
        CommandAPDU start = new CommandAPDU(CARD_AUTH, INSERT_START, 0, 0, 256);
        ResponseAPDU apdu;
        try {
            apdu = applet.transmit(start);
        } catch (CardException e) {
            e.printStackTrace();
            throw new AuthenticationFailedException("Something has gone wrong. Please try again");
        }
        authenticateSmartCard(apdu);
    }

    /**
     * protocol 1 - mutual authentication between smartcard and car
     */
    public void authenticateSmartCard(ResponseAPDU apdu) throws CardNotInitializedException, AuthenticationFailedException {
        if (apdu.getSW() == CARD_NOT_INITIALIZED) {
            throw new CardNotInitializedException("Please initialize the card in the Reception Terminal first");
        }
        //Message 1
        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] msg1 = apdu.getData();

        //scPubSK + cardID
        byte[] scPubSKEncoded = new byte[KEY_LEN];
        memCpy(scPubSKEncoded, msg1, offset, KEY_LEN);
        offset += KEY_LEN;
        scPubSK = bytesToPubkey(scPubSKEncoded);
        cardID = new byte[ID_LEN];
        memCpy(cardID, msg1, offset, ID_LEN);
        offset += ID_LEN;

        int scCertHashSignLen = getInt(msg1, offset);
        offset += INT_LEN;

        //scCertHash signature
        byte[] scCertHashSign = new byte[scCertHashSignLen];
        memCpy(scCertHashSign, msg1, offset, scCertHashSignLen);
        offset += scCertHashSignLen;
        ByteBuffer msg1Cmps = ByteBuffer.wrap(new byte[KEY_LEN + ID_LEN]);
        msg1Cmps.put(scPubSKEncoded).put(cardID);

        if (!ac.verify(msg1Cmps, scCertHashSign, dbPubSK)) {
            errorState("Invalid certificate: hash does not match");
            autoLogger.fatal("Invalid certificate: hash does not match", "authenticateSmartCard message 1", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            //TODO: Like this. Look for corresponding method in smartcard, no handling implemented.
            sendErrorAPDU(INSERT_START, INVALID_HASH);
            throw new AuthenticationFailedException("Invalid certificate: hash does not match");
        }

        //Nonces
        short cardNonce = getShort(msg1, offset);
        offset += NONCE_LEN;

        //Message 2
        short autoNonce = ac.generateNonce();
        byte[] cardNonceHashSign = ac.sign(shortToByteArray(cardNonce));
        msgBuf.putShort(cardNonce);
        msgBuf.putInt(cardNonceHashSign.length);
        msgBuf.put(cardNonceHashSign);
        msgBuf.putShort(autoNonce);
        apdu = sendAPDU(CARD_CONT, INSERT_M2, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 3
        if (apdu.getSW() == AUTH_FAILED_MANIPULATION) {
            autoLogger.fatal("Something has been manipulated", "authenticateSmartCard message 3", cardID);
            throw new AuthenticationFailedException("Something has been manipulated, authentication between auto and card failed");
        }
        offset = ERESPAPDU_CDATA_OFFSET;

        byte[] msg3 = apdu.getData();
        short autoNonceResp = getShort(msg3, offset);
        offset += 2;
        byte[] autoNonceRespHashSignLenByte = new byte[INT_LEN];
        memCpy(autoNonceRespHashSignLenByte, msg3, offset, INT_LEN);
        offset += INT_LEN;
        int autoNonceRespHashSignLen = intFromByteArray(autoNonceRespHashSignLenByte);
        byte[] autoNonceRespHashSign = new byte[autoNonceRespHashSignLen];
        memCpy(autoNonceRespHashSign, msg3, offset, autoNonceRespHashSignLen);

        ByteBuffer msg3Cmps = ByteBuffer.wrap(new byte[NONCE_LEN]);
        msg3Cmps.putShort(autoNonceResp);
        if (!ac.verify(msg3Cmps, autoNonceRespHashSign, scPubSK)) {
            errorState("Wrong nonce in P1 msg3 returned");
            autoLogger.fatal("Wrong nonce returned", "authenticateSmartCard message 3", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            sendErrorAPDU(INSERT_M2, INVALID_NONCE);
            throw new AuthenticationFailedException("Wrong nonce returned, authentication between auto and card failed");
        } else {
            //Success message
            cardAuthenticated = true;
            msgBuf.put(SUCCESS_BYTE);
            msgBuf.putShort((short) (cardNonce + 1));
            byte[] succByte = {SUCCESS_BYTE};
            msgBuf.putInt(ac.sign(concatBytes(succByte, shortToByteArray((short) (cardNonce + 1)))).length).put(ac.sign(concatBytes(succByte, shortToByteArray((short) (cardNonce + 1)))));
            sendAPDU(CARD_CONT, INSERT_MS, msgBuf);
            msgBuf.clear();
            msgBuf.rewind();
            if (apdu.getSW() == AUTH_FAILED || apdu.getSW() == AUTH_FAILED_MANIPULATION) {
                autoLogger.fatal("Something went wrong", "authenticateSmartCard", cardID);
                throw new AuthenticationFailedException("Something has gone wrong, authentication between auto and card failed");
            } else {
                autoLogger.info("Card successfully authenticated", "authenticateSmartCard", cardID);
            }

        }
        return;
    }

    /**
     * protocol 5 - adding kilometerage to smartcard
     */
    public int kilometerageUpdate() throws ProcessFailedException {
        if (!cardAuthenticated) {
            errorState("Card not authenticated in kilometerageUpdate");
            autoLogger.warning("Aborting: Card not authenticated", "kilometerageUpdate", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            throw new ProcessFailedException("Aborting: Card not authenticated");
        }
        //Message 1
        kilometerage += 1;
        msgBuf.putInt(kilometerage).putInt(ac.sign(intToByteArray(kilometerage)).length).put(ac.sign(intToByteArray(kilometerage)));
        ResponseAPDU apdu = sendAPDU(CARD_PROC, KMM_UPDATE, msgBuf);
        msgBuf.clear();
        msgBuf.rewind();

        //Message 2
        if (apdu.getSW() == PROC_FAILED){
            autoLogger.fatal("Something went wrong", "kilometerageUpdate", cardID);
            throw new ProcessFailedException("Something has gone wrong, updating the kilometerage has failed");
        }

        offset = ERESPAPDU_CDATA_OFFSET;
        byte[] confirmation = apdu.getData();

        byte confBYTE = confirmation[offset];
        offset += BYTE_LEN;
        int curKmmCard = getInt(confirmation, offset);
        offset += INT_LEN;
        if (kilometerage != curKmmCard) {
            errorState("Kilometerage does not match");
            autoLogger.warning("Kilometerage does not match, possible tampering. Please check.", "kilometerageUpdate", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            throw new ProcessFailedException("Kilometerage does not match. We detected possible tampering");
        }
        int confHashSignLen = getInt(confirmation, offset);
        offset += INT_LEN;
        byte[] confHashSigned = new byte[confHashSignLen];
        memCpy(confHashSigned, confirmation, offset, confHashSignLen);

        ByteBuffer msgCmps = ByteBuffer.wrap(new byte[ID_LEN]);
        msgCmps.put(confBYTE).putInt(curKmmCard);
        if (!ac.verify(msgCmps, confHashSigned, scPubSK)) {
            errorState("Invalid Hash in kilometerageUpdate");
            autoLogger.fatal("Invalid Hash", "kilometerageUpdate", cardID);
            //TODO: send something back to smartcard. How? Who knows.
            throw new ProcessFailedException("Something has gone wrong. Please try again");
        } else {
            autoLogger.info("Kilometerage successfully updated", "kilometerageUpdate", cardID);
        }
        return kilometerage;
    }

    private void select() {
        try {
            if (autoTerminal.isCardPresent()) {
                return;
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
        smartcard.assignToTerminal(autoTerminal);
        try {
            Card card = autoTerminal.connect("*");
            applet = card.getBasicChannel();
            ResponseAPDU resp = applet.transmit(SELECT_APDU);
            if (resp.getSW() != 0x9000) {
                throw new Exception("Select failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void deselect() {
        try {
            if (!autoTerminal.isCardPresent()) {
                autoLogger.warning("Tried to deselect card that is not present", "Deselect", cardID);
                return;
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
        smartcard.assignToTerminal(null);
        applet = null;
    }

    private static class AutoCrypto extends CryptoImplementationExtended {

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
        public void run() {
            CardTerminals cardTerminals = CardTerminalSimulator.terminals(
                    Arrays.toString(ac.getID()));
            CardTerminal autoTerminal = cardTerminals.getTerminal(Arrays.toString(ac.getID()));
            AID scAppletAID = AIDUtil.create(SC_APPLET_AID);
            select();
        }
    }
}
