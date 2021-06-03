package Smartcard;

import Interfaces.Communicator;
import Interfaces.KeyWallet;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacardx.apdu.ExtendedLength;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import java.nio.charset.StandardCharsets;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 * @author Laura Philipse
 * @author Alessandra van Veen
 */
public class Smartcard extends Applet implements Communicator, ISO7816, ExtendedLength {
    public PublicKey dbPubSK;
    public PublicKey rtPubSK;
    public PublicKey autoPubSK;
    public States state = States.EMPTY;
    short offset;
    ProtocolAwaited currentAwaited = ProtocolAwaited.AUTH;
    boolean terminalAuthenticated = false;
    byte[] cardCertificate;
    byte[] cardID;
    PrivateKey privateKey;
    //Everything here is in EEPROM (persistent)
    private SmartcardCrypto sc;
    private boolean manipulation = false;
    private int kilometerage = 0; //TODO: Change to less storage intensive type (short)

    //TODO Move Initialization to constructor and check for out-of-memory
    // ByteBuffer operations translate directly to simple JVM operations, very little overhead,
    // both computationally and spacially (points to underlying msgBufRaw) but much more versatile
    // than byte[].
    private byte[] autoID;
    private short nonceReception;
    private short nonceCard;
    //byte[] cardID, int certLength, byte[] cardCertificate, byte[] privateKeyEncoded
    private Smartcard(byte[] bArray, short bOffset, byte bLength) {
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a SmartCard applet instance
        new Smartcard(bArray, bOffset, bLength);
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command
        if ((buffer[ISO7816.OFFSET_CLA] == CARD_SELECT) &&
                (buffer[ISO7816.OFFSET_INS] == (byte)
                        (0xA4)))
            return;
        switch (buffer[ISO7816.OFFSET_CLA]) {
            case CARD_AUTH:
                /*Deselect is not being called properly and kmmUpdate can't change the protocol state, so it might be
                that the card thinks it is still authenticated to an auto terminal it's no longer connected to*/
                if (currentAwaited != ProtocolAwaited.AUTH && currentAwaited != ProtocolAwaited.PROC) {
                    return;
                }
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INSERT_START:
                        insertStart(apdu);
                        return;
                    case AUTH_RECEPTION_START:
                        authReception(apdu);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        return;
                }
            case CARD_PROC:
                if (currentAwaited != ProtocolAwaited.PROC) {
                    return;
                }
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case CAR_ASSIGNMENT_START:
                        carAssignmentStart(apdu);
                        return;
                    case KMM_UPDATE:
                        kilometerageUpdate(apdu);
                        return;
                    case CAR_RETURN_START:
                        carReturnStart(apdu);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        return;
                }
            case CARD_CONT:
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INSERT_M2:
                        if (currentAwaited != ProtocolAwaited.INS2) {
                            return;
                        }
                        insertM2(apdu);
                        return;
                    case INSERT_MS:
                        if (currentAwaited != ProtocolAwaited.INSS) {
                            return;
                        }
                        insertMS(apdu);
                        return;
                    case AUTH_RECEPTION_M2:
                        if (currentAwaited != ProtocolAwaited.AUTHR2) {
                            return;
                        }
                        authReceptionM2(apdu);
                        return;
                    case AUTH_RECEPTION_MS:
                        if (currentAwaited != ProtocolAwaited.AUTHRS) {
                            return;
                        }
                        authReceptionMS(apdu);
                        return;
                    case CAR_ASSIGNMENT_M2:
                        if (currentAwaited != ProtocolAwaited.CASS2) {
                            return;
                        }
                        carAssignmentM2(apdu);
                        return;
                    case CAR_RETURN_M2:
                        if (currentAwaited != ProtocolAwaited.CRET2) {
                            return;
                        }
                        carReturnM2(apdu);
                        return;
                    case CAR_RETURN_MS:
                        if (currentAwaited != ProtocolAwaited.CRETS) {
                            return;
                        }
                        carReturnMS(apdu);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        return;
                }
            case CARD_EOL:
                if (buffer[ISO7816.OFFSET_INS] == BLOCK) {
                    state = States.END_OF_LIFE;
                } else {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                return;
            case CARD_INIT:
                if (buffer[ISO7816.OFFSET_INS] == INIT) {
                    init(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                return;
            case CARD_DEBUG:
                if (buffer[ISO7816.OFFSET_INS] == DEBUG) {
                    apdu.setOutgoing();
                    byte[] msgBuf = apdu.getBuffer();
                    msgBuf[0] = (byte) 0x42;
                    apdu.setOutgoingLength((short) 1);
                    apdu.sendBytes((short) 0, (short) 1);
                } else {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                return;
            case CARD_ERROR:
                short sw = getShort(apdu.getBuffer(), EAPDU_CDATA_OFFSET);
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INSERT_START:
                        insertStartOnError(sw);
                        return;
                    case INSERT_M2:
                        insertM2OnError(sw);
                        return;
                    case INSERT_MS:
                        insertMSOnError(sw);
                        return;
                    case AUTH_RECEPTION_START:
                        authReceptionOnError(sw);
                        return;
                    case AUTH_RECEPTION_M2:
                        authReceptionM2OnError(sw);
                        return;
                    case AUTH_RECEPTION_MS:
                        authReceptionMSOnError(sw);
                        return;
                    case CAR_ASSIGNMENT_START:
                        carAssignmentStartOnError(sw);
                        return;
                    case CAR_ASSIGNMENT_M2:
                        carAssignmentM2OnError(sw);
                        return;
                    case KMM_UPDATE:
                        kilometerageUpdateOnError(sw);
                        return;
                    case CAR_RETURN_START:
                        carReturnStartOnError(sw);
                        return;
                    case CAR_RETURN_M2:
                        carReturnM2OnError(sw);
                        return;
                    case CAR_RETURN_MS:
                        carReturnMSOnError(sw);
                        return;
                    case INIT:
                        initOnError(sw);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                return;
            default:
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    private void init(APDU apdu) {
        offset = EAPDU_CDATA_OFFSET;
        byte[] tmp = apdu.getBuffer();
        int dataLen = threeBytesToInt(tmp, ISO7816.OFFSET_LC); //Is this one necessary????? No, it's not necessary, but we wrote a full nice method just for this one use case... TODO
        cardID = newStaticB(ID_LEN);
        memCpy(cardID, tmp, offset, ID_LEN);
        offset += ID_LEN;
        int certLength = getInt(tmp, offset);
        offset += INT_LEN;
        cardCertificate = newStaticB(certLength);
        memCpy(cardCertificate, tmp, offset, certLength);
        offset += certLength;
        byte[] privateKeyEncoded = newStaticB(KEY_LEN);
        memCpy(privateKeyEncoded, tmp, offset, KEY_LEN);
        privateKey = bytesToPrivkey(privateKeyEncoded);
        offset += KEY_LEN;
        sc = new SmartcardCrypto(cardID, cardCertificate, privateKey);
        byte[] dbPubkB = newB(KEY_LEN);
        memCpy(dbPubkB, tmp, offset, KEY_LEN);
        dbPubSK = bytesToPubkey(dbPubkB);
        state = States.ASSIGNED_NONE;
    }

    private void initOnError(short sw) {
        switch (sw) {
            case INVALID_NONCE:
                //I failed math...
                return;
            case INVALID_HASH:
                //Back in my day, we used MD5...
                return;
            default:
                //*throws hands in air* Oh, I don't know why it's crashing either!!! :'(
        }
    }

    /**
     * Wakes up smartcard from suspended state and returns whether it's ready to process requests.
     */
    @Override
    public boolean select() {
        //reject activation if card is no longer alive
        sc = new SmartcardCrypto(cardID, cardCertificate, privateKey);
        return state != States.END_OF_LIFE;
    }

    /**
     * card is removed from reader and enters suspend state
     */
    @Override
    public void deselect() {
        currentAwaited = ProtocolAwaited.AUTH;
    }

    public void sendErrorAPDU(short status_word) {
        ISOException.throwIt(status_word);
        /* On the side of the terminal, you'd check this with
        if (apdu.getSW() == status_word) {
            _error_handling_
        }
        */
    }

    /**
     * Protocol 1 - mutual authentication between smartcard and car
     */
    public void insertStart(APDU apdu) {
        //Message 1
        if (sc == null || sc.getID() == null) {
            errorState("Trying to insert card into auto before card is initialized");
            sendErrorAPDU(CARD_NOT_INITIALIZED);
            return;
        }
        nonceCard = sc.generateNonce();
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        byte[] scCert = sc.getCertificate();
        //msgBuf.put(scCert).putShort(nonceCard);
        put(msgBuf, scCert, 0);
        putShort(msgBuf, nonceCard, scCert.length);
        short msgLen = (short) (NONCE_LEN + scCert.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.INS2;
    }

    private void insertStartOnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 1 - mutual authentication between smartcard and car
     */
    private void insertM2(APDU apdu) {
        offset = EAPDU_CDATA_OFFSET;
        byte[] msg2 = apdu.getBuffer();

        //Response of nonceCard
        short nonceCardResponse = getShort(msg2, offset);//msg2.getShort(73 + certSignLen);
        offset += 2;
        if (nonceCard != nonceCardResponse) {
            errorState("Wrong nonce returned in message 2 of P1");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED_MANIPULATION);
            return;
        }

        //signed hash of nonceCard
        int msg2NonceSignLen = getInt(msg2, offset);//msg2.getInt(curBufIndex);
        offset += INT_LEN;
        byte[] nonceCardResponseHashSign = newB(msg2NonceSignLen);
        memCpy(nonceCardResponseHashSign, msg2, offset, msg2NonceSignLen);
        offset += msg2NonceSignLen;

        if (!sc.verify(shortToByteArray(nonceCardResponse), nonceCardResponseHashSign, autoPubSK)) {
            errorState("Invalid hash of nonce returned in message 2 of P1");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED_MANIPULATION);
            return;
        }

        //nonceAuto
        short nonceAuto = getShort(msg2, offset);

        //Message 3
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        byte[] msg3HashSign = sc.sign(shortToByteArray(nonceAuto));
        putShort(msgBuf, nonceAuto, 0);
        putInt(msgBuf, msg3HashSign.length, NONCE_LEN);
        put(msgBuf, msg3HashSign, NONCE_LEN + INT_LEN);
        short msgLen = (short) (NONCE_LEN + INT_LEN + msg3HashSign.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.INSS;
    }

    private void insertM2OnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 1 - mutual authentication between smartcard and car
     */
    private void insertMS(APDU apdu) {
        // Success message
        offset = EAPDU_CDATA_OFFSET;
        byte[] succMb = apdu.getBuffer();

        byte success = succMb[offset];
        offset += BOOL_LEN;
        if (success != SUCCESS_BYTE) {
            errorState("Wrong code, expected 0xFF");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED);
            return;
        }
        short nonceSucc = getShort(succMb, offset);
        offset += NONCE_LEN;
        if (!sc.areSubsequentNonces(nonceCard, nonceSucc)) {
            errorState("Wrong nonce in success message of P1");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED_MANIPULATION);
            return;
        }
        int nonceSuccSignLen = getInt(succMb, offset);
        offset += INT_LEN;
        byte[] succMHashSign = newB(nonceSuccSignLen);
        memCpy(succMHashSign, succMb, offset, nonceSuccSignLen);
        byte[] succMsgCmps = newB(BOOL_LEN + NONCE_LEN);
        succMsgCmps[0] = success;
        putShort(succMsgCmps, nonceSucc, BOOL_LEN);
        if (!sc.verify(succMsgCmps, succMHashSign, autoPubSK)) {
            errorState("Invalid hash in success message (P1)");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED_MANIPULATION);
            return;
        }
        currentAwaited = ProtocolAwaited.PROC;
    }

    private void insertMSOnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 2 - Mutual Authentication between smartcard and reception terminal
     */
    public void authReception(APDU apdu) {
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        byte[] scCert = sc.getCertificate();
        put(msgBuf, scCert, 0);
        nonceCard = sc.generateNonce();
        putShort(msgBuf, nonceCard, scCert.length);
        short msgLen = (short) (NONCE_LEN + INT_LEN + scCert.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.AUTHR2;

    }

    private void authReceptionOnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 2 - Mutual Authentication between smartcard and reception terminal
     */
    private void authReceptionM2(APDU apdu) {
        offset = EAPDU_CDATA_OFFSET;
        byte[] response = apdu.getBuffer();

        byte[] rtPubSkb = newB(KEY_LEN);
        memCpy(rtPubSkb, response, offset, KEY_LEN);
        offset += KEY_LEN;
        rtPubSK = bytesToPubkey(rtPubSkb);

        byte[] receptionID = newB(ID_LEN);
        memCpy(receptionID, response, offset, ID_LEN);
        offset += ID_LEN;

        int receptionCertHSLength = getInt(response, offset);
        offset += INT_LEN;

        byte[] receptionCertHashSign = newB(receptionCertHSLength);
        memCpy(receptionCertHashSign, response, offset, receptionCertHSLength);
        offset += receptionCertHSLength;

        nonceReception = getShort(response, offset);
        byte[] msg2Cmps = newB(KEY_LEN + ID_LEN);
        put(msg2Cmps, rtPubSkb, 0);
        put(msg2Cmps, receptionID, KEY_LEN);

        if (!sc.verify(msg2Cmps, receptionCertHashSign, dbPubSK)) { //Step 5 //ERROR HERE. CRYPTO EXCEPTION
            errorState("ReceptionCertHash does not match expected value, check for manipulation.");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED_MANIPULATION);
            return;
        }
        byte[] noncePrepped = shortToByteArray(nonceReception);
        byte[] nonceReceptionHashSign = sc.sign(noncePrepped);
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        putShort(msgBuf, nonceReception, 0);
        putInt(msgBuf, nonceReceptionHashSign.length, NONCE_LEN);
        put(msgBuf, nonceReceptionHashSign, NONCE_LEN + INT_LEN);
        short msgLen = (short) (NONCE_LEN + INT_LEN + nonceReceptionHashSign.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.AUTHRS;

    }

    private void authReceptionM2OnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 2 - Mutual Authentication between smartcard and reception terminal
     */
    private void authReceptionMS(APDU apdu) {
        offset = EAPDU_CDATA_OFFSET;
        byte[] response2 = apdu.getBuffer();

        byte success = response2[offset];
        offset++;
        if (success != SUCCESS_BYTE) {
            errorState("Wrong byte code, expected 0xFF");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED);
            return;
        }

        short nonceCardResp = getShort(response2, offset);
        offset += NONCE_LEN;
        if (nonceCardResp != nonceCard) {
            errorState("Wrong nonce returned in message 4 of P2");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED_MANIPULATION);
            return;
        }

        int responseData2Length = getInt(response2, offset);
        offset += INT_LEN;
        byte[] responseData2 = newB(responseData2Length);
        memCpy(responseData2, response2, offset, responseData2Length);
        byte[] succMsgCmps = newB(BOOL_LEN + NONCE_LEN);
        succMsgCmps[0] = success;
        putShort(succMsgCmps, nonceCard, BOOL_LEN);
        if (!sc.verify(succMsgCmps, responseData2, rtPubSK)) { //Step 9
            errorState("Invalid hash in message 4 of P2");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(AUTH_FAILED_MANIPULATION);
            return;
        }

        terminalAuthenticated = true;
        currentAwaited = ProtocolAwaited.PROC;
        //Maybe let the terminal know how it went TODO

    }

    private void authReceptionMSOnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 3 - Assignment of car to smartcard
     */
    public void carAssignmentStart(APDU apdu) {
        if (!terminalAuthenticated) { //Step 1
            errorState("Terminal is not authenticated");
            currentAwaited = ProtocolAwaited.AUTH;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        byte[] value = "Car?".getBytes(StandardCharsets.UTF_8);
        short nonceReceptionCount = ((short) (nonceReception + 1));
        byte[] giveCarSigned = sc.sign(concatBytes(value, shortToByteArray(nonceReceptionCount)));

        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        offset = 0;
        put(msgBuf, value, offset);
        offset += value.length;
        offset += putShort(msgBuf, nonceReceptionCount, offset);
        offset += putInt(msgBuf, giveCarSigned.length, offset);
        put(msgBuf, giveCarSigned, offset);
        short msgLen = (short) (INT_LEN + SHORT_LEN + INT_LEN + giveCarSigned.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.CASS2;
    }

    private void carAssignmentStartOnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 3 - Assignment of car to smartcard
     */
    private void carAssignmentM2(APDU apdu) {
        offset = EAPDU_CDATA_OFFSET;
        byte[] response = apdu.getBuffer();

        byte[] autoPubSkb = newB(KEY_LEN);
        memCpy(autoPubSkb, response, offset, KEY_LEN);
        offset += KEY_LEN;
        autoPubSK = bytesToPubkey(autoPubSkb);

        autoID = newB(ID_LEN);
        memCpy(autoID, response, offset, ID_LEN);
        offset += ID_LEN;

        int autoCertHSLength = getInt(response, offset);
        offset += INT_LEN;
        byte[] autoCertHashSign = newB(autoCertHSLength);
        memCpy(autoCertHashSign, response, offset, autoCertHSLength);
        offset += autoCertHSLength;

        byte[] autoCertCmps = newB(KEY_LEN + ID_LEN);
        put(autoCertCmps, autoPubSkb, 0);
        put(autoCertCmps, autoID, KEY_LEN);
        if (!sc.verify(autoCertCmps, autoCertHashSign, dbPubSK)) { //Step 7 - certificate
            errorState("Invalid car certificate received");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }

        short nonceCard2 = getShort(response, offset);
        offset += NONCE_LEN;
        if (nonceCard2 != ((short) (nonceCard + 1))) {
            errorState("Wrong sequence number in message 2 of P3");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        int msg2SignLen = getInt(response, offset);
        offset += INT_LEN;
        byte[] msg2HashSign = newB(msg2SignLen);
        memCpy(msg2HashSign, response, offset, msg2SignLen);
        byte[] msg2Cmps = newB(KEY_LEN + ID_LEN + SIGNED_HASH_LEN + NONCE_LEN);
        offset = 0;
        put(msg2Cmps, autoPubSkb, offset);
        offset += KEY_LEN;
        put(msg2Cmps, autoID, offset);
        offset += autoID.length;
        put(msg2Cmps, autoCertHashSign, offset);
        offset += autoCertHashSign.length;
        putShort(msg2Cmps, nonceCard2, offset);
        if (!sc.verify(msg2Cmps, msg2HashSign, rtPubSK)) {
            errorState("Wrong signature in msg2 of P3");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        state = States.ASSIGNED;
        byte[] successByteArray = {SUCCESS_BYTE};
        byte[] successHash = sc.sign(concatBytes(successByteArray, shortToByteArray((short) (nonceReception + 2))));
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        offset = 0;
        msgBuf[offset] = SUCCESS_BYTE;
        offset += BOOL_LEN;
        offset += putShort(msgBuf, (short) (nonceReception + 2), offset);
        offset += putInt(msgBuf, successHash.length, offset);
        put(msgBuf, successHash, offset);
        short msgLen = (short) (BOOL_LEN + NONCE_LEN + INT_LEN + successHash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.AUTH;
    }

    private void carAssignmentM2OnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * protocol 5  - Adding kilometerage to smartcard
     */
    public void kilometerageUpdate(APDU apdu) {
        byte[] receivedKmm = apdu.getBuffer();
        offset = EAPDU_CDATA_OFFSET;

        int oldKMM = kilometerage;

        kilometerage = getInt(receivedKmm, offset);
        offset += INT_LEN;
        int recKmmHashSignLength = getInt(receivedKmm, offset);
        offset += INT_LEN;
        byte[] recKmmHashSign = newB(recKmmHashSignLength);
        memCpy(recKmmHashSign, receivedKmm, offset, recKmmHashSignLength);

        if (!sc.verify(intToByteArray(kilometerage), recKmmHashSign, autoPubSK)) {
            manipulation = true;
            errorState("Hashes do not match in kilometerage update! Potential manipulation!");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        if (oldKMM >= kilometerage) {
            manipulation = true;
            kilometerage = oldKMM; //TODO: Is this a security problem? race condition?
            errorState("Old kilometerage is higher than the new kilometerage. Potential manipulation!");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
        }
        byte confirmation = (byte) 1;
        byte[] confirmationArray = {confirmation};
        byte[] confirmationHash = sc.sign(concatBytes(confirmationArray, intToByteArray(kilometerage)));
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        offset = 0;
        msgBuf[0] = confirmation;
        offset += BYTE_LEN;
        offset += putInt(msgBuf, kilometerage, offset);
        offset += putInt(msgBuf, confirmationHash.length, offset);
        put(msgBuf, confirmationHash, offset);
        short msgLen = (short) (BYTE_LEN + INT_LEN + INT_LEN + confirmationHash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.PROC;
    }

    private void kilometerageUpdateOnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 4 - Car return and kilometerage check
     */
    private void carReturnStart(APDU apdu) {
        short seqNum1 = (short) (nonceReception + 1);
        byte[] car_return = "Car Return".getBytes(StandardCharsets.UTF_8);
        byte[] msg1Hash = sc.sign(concatBytes(car_return, shortToByteArray(seqNum1), booleanToByteArray(manipulation)));
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        byte[] manByte = booleanToByteArray(manipulation);
        offset = 0;
        offset += put(msgBuf, car_return, offset);
        offset += putShort(msgBuf, seqNum1, offset);
        offset += put(msgBuf, manByte, offset);
        offset += putInt(msgBuf, msg1Hash.length, offset);
        put(msgBuf, msg1Hash, offset);
        short msgLen = (short) (car_return.length + NONCE_LEN + BYTE_LEN + INT_LEN + msg1Hash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.CRET2;
    }

    private void carReturnStartOnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 4 - Car return and kilometerage check
     */
    private void carReturnM2(APDU apdu) {
        byte[] msg2 = apdu.getBuffer();
        offset = EAPDU_CDATA_OFFSET;
        short seqNum1 = (short) (nonceReception + 1);
        short kmmNonce = getShort(msg2, offset);
        offset += NONCE_LEN;
        short seqNum2 = getShort(msg2, offset);
        offset += NONCE_LEN;
        int lengthHash = getInt(msg2, offset);
        offset += INT_LEN;
        byte[] hash = newB(lengthHash);
        memCpy(hash, msg2, offset, lengthHash);
        if (!sc.areSubsequentNonces(nonceCard, seqNum2)) {
            errorState("Wrong sequence number in carReturn message 2");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        byte[] msgCmps = newB(2 * NONCE_LEN);
        putShort(msgCmps, kmmNonce, 0);
        putShort(msgCmps, seqNum2, NONCE_LEN);
        if (!sc.verify(msgCmps, hash, rtPubSK)) {
            errorState("Message hashes do not match in msg2 carReturn");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        byte[] msg3Hash = sc.sign(concatBytes(intToByteArray(kilometerage), shortToByteArray(kmmNonce), shortToByteArray((short) (seqNum1 + 1))));
        apdu.setOutgoing();
        byte[] msgBuf = clearBuf(apdu);
        offset = 0;
        offset += putInt(msgBuf, kilometerage, offset);
        offset += putShort(msgBuf, kmmNonce, offset);
        offset += putShort(msgBuf, ((short) (seqNum1 + 1)), offset);
        offset += putInt(msgBuf, msg3Hash.length, offset);
        put(msgBuf, msg3Hash, offset);
        short msgLen = (short) (INT_LEN + NONCE_LEN + NONCE_LEN + INT_LEN + msg3Hash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        kilometerage = 0;

        state = States.ASSIGNED_NONE;
        autoID = null;
        autoPubSK = null;
        currentAwaited = ProtocolAwaited.CRETS;

    }

    private void carReturnM2OnError(short sw) {
        //TODO: Handle errors
    }

    /**
     * Protocol 4 - Car return and kilometerage check
     */
    private void carReturnMS(APDU apdu) {
        byte[] succMsg = apdu.getBuffer();
        offset = EAPDU_CDATA_OFFSET;

        byte success = succMsg[offset];
        offset++;
        if (success != SUCCESS_BYTE) {
            errorState("Wrong code, expected 0xFF");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        short succNonce = getShort(succMsg, offset);
        offset += NONCE_LEN;
        if (!sc.areSubsequentNonces(nonceCard, succNonce, 2)) {
            errorState("Wrong sequence number in success message of P4");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        int hashLength = getInt(succMsg, offset);
        offset += INT_LEN;
        byte[] signedSuccHash = newB(hashLength);
        memCpy(signedSuccHash, succMsg, offset, hashLength);
        byte[] msgCmps = newB(BYTE_LEN + NONCE_LEN);
        msgCmps[0] = success;
        putShort(msgCmps, succNonce, BYTE_LEN);
        if (!sc.verify(msgCmps, signedSuccHash, rtPubSK)) {
            errorState("Invalid hash in success message of Protocol 4");
            currentAwaited = ProtocolAwaited.PROC;
            sendErrorAPDU(PROC_FAILED);
            return;
        }
        currentAwaited = ProtocolAwaited.AUTH;
    }

    private void carReturnMSOnError(short sw) {
        //TODO: Handle errors
    }

    public enum ProtocolAwaited {
        AUTH,   //card waits for an authentication protocol (insert, authReception)
        PROC,   //card waits for a processing protocol (assignment, kmmUpdate, carReturn)
        INS2,   //card has started Insert        Protocol and is waiting for message 2
        INSS,   //card has started Insert        Protocol and is waiting for success message
        AUTHR2, //card has started authReception Protocol and is waiting for message 2
        AUTHRS, //card has started authReception Protocol and is waiting for success message
        CASS2,  //card has started carAssignment Protocol and is waiting for message 2
        CRET2,  //card has started carReturn     Protocol and is waiting for message 2
        CRETS,  //card has started carReturn     Protocol and is waiting for success message
    }

    public enum States {EMPTY, ASSIGNED_NONE, ASSIGNED, END_OF_LIFE}

    private class SmartcardCrypto extends CryptoImplementation {


        public SmartcardCrypto(byte[] cardID, byte[] cardCertificate, PrivateKey privateKey) {
            super.ID = cardID;
            super.certificate = cardCertificate;
            super.rc = new SmartCardWallet();
            ((KeyWallet) super.rc).storePrivateKey(privateKey);
        }

        private class SmartCardWallet extends RSACrypto implements KeyWallet {

            private PrivateKey privk;
            private PublicKey pubk;

            @Override
            public void storePublicKey() {
                //TODO: Make sure only database is able to set key
            }

            @Override
            public void storePrivateKey(PrivateKey privateKey) {
                //TODO: Make sure only database is able to set key
                super.privk = privateKey;
            }

            @Override
            public PublicKey getPublicKey() {
                return pubk;
            }
        }
    }


}