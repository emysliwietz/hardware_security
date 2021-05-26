package Smartcard;

import Auto.Auto;
import Interfaces.Communicator;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import db.Database;
import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
import receptionTerminal.ReceptionTerminal;
import rsa.CryptoImplementation;
import rsa.RSACrypto;

import javax.print.attribute.standard.MediaSize;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Smartcard extends Applet implements Communicator, ISO7816, ExtendedLength {
    //Everything here is in EEPROM (persistent)
    private SmartcardCrypto sc;
    public PublicKey dbPubSK;
    private boolean manipulation = false;
    private int kilometerage; //TODO: Change to less storage intensive type (short)
    public PublicKey rtPubSK;

    private byte[] autoIDStored;
    public PublicKey autoPubSK;

    // SW APDU Response Codes
    final static short AUTH_SUCCESS = 0x6100;
    final static short AUTH_SUCCESS_MANIPULATION = 0x6101;
    final static short AUTH_FAILED  = 0x5100;
    final static short AUTH_FAILED_MANIPULATION = 0x5101;
    final static short PROC_SUCCCESS = 0x6200;
    final static short PROC_FAILED = 0x5200;
    final static short WRONG_CONTINUATION = 0x5300;

    //TODO: Use this
    public enum ProtocolAwaited{
        AUTH,   //card waits for an authentication protocol (insert, authReception)
        PROC,   //card waits for a processing protocol (assignment, kmmUpdate, carReturn)
        INS2,   //card has started Insert Protocol and is waiting for message 2
        INSS,   //card has started Insert Protocol and is waiting for success message
        AUTHR2, //card has started authReception Protocol and is waiting for message 2
        AUTHRS, //TODO: finish these comments...
        CASS2,
        CRET2,
        CRETS,
    }

    ProtocolAwaited currentAwaited = ProtocolAwaited.AUTH;



    @Override
    public void process(APDU apdu) throws ISOException {
        ByteBuffer buffer = ByteBuffer.wrap(apdu.getBuffer());
        // check SELECT APDU command
        if ((buffer.get(ISO7816.OFFSET_CLA) == CARD_SELECT) &&
                (buffer.get(ISO7816.OFFSET_INS) == (byte)
                        (0xA4)) )
            return;
        switch (buffer.get(ISO7816.OFFSET_CLA)) {
            case CARD_AUTH:
                if (currentAwaited != ProtocolAwaited.AUTH) {
                    return;
                }
                switch (buffer.get(ISO7816.OFFSET_INS)) {
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
                switch(buffer.get(ISO7816.OFFSET_INS)) {
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
                switch(buffer.get(ISO7816.OFFSET_CLA)){
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
                if(buffer.get(ISO7816.OFFSET_CLA) == BLOCK){
                    state = States.END_OF_LIFE;
                } else {
                    ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                }
                return;
            case CARD_INIT:
                if(buffer.get(ISO7816.OFFSET_CLA) == INIT){
                    init(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                }
                return;

            default:
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }


    public enum States{EMPTY, ASSIGNED_NONE, ASSIGNED, END_OF_LIFE}
    public States state = States.EMPTY;

    //TODO Move Initialization to constructor and check for out-of-memory
    //private byte[] msgBufRaw;
    // ByteBuffer operations translate directly to simple JVM operations, very little overhead,
    // both computationally and spacially (points to underlying msgBufRaw) but much more versatile
    // than byte[].
    //private ByteBuffer msgBuf;//ByteBuffer.allocate(256);

    //Move to some temporary storage:
    boolean terminalAuthenticated = false; //in temporary storage
    private short nonceReception; //TEMP because this should be yeeted when card is pulled out
    private short nonceCard; //TEMP same as above
    //byte[] t;
    // t = JCSystem.makeTransientByteArray((short)128,JCSystem.CLEAR_ON_RESET);
                                            //length
    //See slide 32 of february 8 Javacard. We can have 1 or 2. So we gotta be careful.
    //To do: figure out length we can have. Currently pubkey is around 216 bytes.

    public static void install(byte[] bArray, short bOffset, byte bLength){
        // create a SmartCard applet instance
        new Smartcard(bArray, bOffset, bLength);
    }

    //byte[] cardID, int certLength, byte[] cardCertificate, byte[] privateKeyEncoded
    private Smartcard(byte[] bArray, short bOffset, byte bLength) {
        //ByteBuffer tmp = ByteBuffer.wrap(bArray, bOffset, bLength);
        //byte[] cardID = newB(5);
        //tmp.get(cardID, 0, 5);
        //int certLength = tmp.getInt();
        //byte[] cardCertificate = newB(certLength);
        //tmp.get(cardCertificate, 9, certLength);
        //byte[] privateKeyEncoded = newB(bLength - (certLength + 9));
        //tmp.get(privateKeyEncoded, 9 + certLength, bLength - (certLength + 9));
        //PrivateKey privateKey = bytesToPrivkey(privateKeyEncoded);
        //sc = new SmartcardCrypto(cardID, cardCertificate, privateKey);
        ////msgBufRaw = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        ////msgBuf = ByteBuffer.wrap(msgBufRaw);
        register();

    }

    private void init(APDU apdu){
        ByteBuffer tmp = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA, apdu.getBuffer()[ISO7816.OFFSET_LC]);
        byte[] cardID = newB(5);
        tmp.get(cardID, 0, 5);
        int certLength = tmp.getInt();
        byte[] cardCertificate = newB(certLength);
        tmp.get(cardCertificate, 9, certLength);
        byte[] privateKeyEncoded = newB(apdu.getBuffer()[ISO7816.OFFSET_LC] - (certLength + 9));
        tmp.get(privateKeyEncoded, 9 + certLength, apdu.getBuffer()[ISO7816.OFFSET_LC] - (certLength + 9));
        PrivateKey privateKey = bytesToPrivkey(privateKeyEncoded);
        sc = new SmartcardCrypto(cardID, cardCertificate, privateKey);
        state = States.ASSIGNED_NONE;
        //msgBufRaw = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        //msgBuf = ByteBuffer.wrap(msgBufRaw);
    }

    // Wakes up smartcard from suspended state and returns whether it's ready to process requests.
    public boolean select() {
        //reject activation if card is no longer alive
        return state != States.END_OF_LIFE;
    }

    //card is removed from reader and enters suspend state
    public void deselect() {

    }

    public byte[] newB(int len) {
        return JCSystem.makeTransientByteArray((short) len, JCSystem.CLEAR_ON_RESET);
    }

    public ByteBuffer newBB(int len) {
        return ByteBuffer.wrap(newB(len));
    }


    public void insertStart(APDU apdu) {
        //Message 1
        nonceCard = sc.generateNonce();
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.putInt(sc.getCertificate().length - 133);
        msgBuf.put(sc.getCertificate()).putShort(nonceCard);
        //send(auto, sc.getCertificate(), nonceCard);
        //send(auto, msgBuf);
        short msgLen = (short) (4 + 2 + sc.getCertificate().length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        //msgBuf.clear();
        //msgBuf.rewind();
        currentAwaited = ProtocolAwaited.INS2;
    }

    private void insertM2(APDU apdu) {
        //byte dataLen = (byte) apdu.setIncomingAndReceive();
        ByteBuffer msg2 = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA, apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
             msg2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return (PublicKey) errorState("Timeout in insert");
        }*/

        //autoPubSK
        byte[] autoPubSKEncoded = newB(64); //NEW BYTE: DONT DO. We should use transient byte array here
        msg2.get(autoPubSKEncoded, 0, 64);
        autoPubSK = bytesToPubkey(autoPubSKEncoded);

        //autoID
        byte[] autoID = newB(5);
        msg2.get(autoID, 64, 5);

        //signature of hash of certificate
        int certSignLen = msg2.getInt(69);
        byte[] autoCertHashSign = newB(certSignLen); //To do: new byte -> Transient byte array
        msg2.get(autoCertHashSign, 73, certSignLen);
        ByteBuffer msg2HashComponents = newBB(69);
        msg2HashComponents.put(autoPubSKEncoded);
        msg2HashComponents.put(autoID);
        //byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);
        //byte[] autoIDPubSKHash = sc.createHash(concatBytes(autoPubSK.getEncoded(), autoID));
        if (!sc.verify(msg2HashComponents,autoCertHashSign,dbPubSK)) {
            //TODO: throw error or something (tamper bit). Also stop further actions.
            errorState("Invalid certificate send in message 2 of P1");
            manipulation = true;
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }

        //Response of nonceCard
        short nonceCardResponse = msg2.getShort(73 + certSignLen);
        int curBufIndex = 75 + certSignLen;
        if (nonceCard != nonceCardResponse) {
            errorState("Wrong nonce returned in message 2 of P1");
            manipulation = true;
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }

        //signed hash of nonceCard
        int msg2NonceSignLen = msg2.getInt(curBufIndex);
        curBufIndex += 4;
        byte[] nonceCardResponseHashSign = newB(msg2NonceSignLen);
        msg2.get(nonceCardResponseHashSign, curBufIndex, msg2NonceSignLen);
        curBufIndex += msg2NonceSignLen;
        msg2HashComponents.clear();
        msg2HashComponents.rewind();
        msg2HashComponents.putShort(nonceCardResponse);
        //byte[] nonceCardResponseHash = sc.unsign(nonceCardResponseHashSign, autoPubSK);
        //byte[] nonceValidHash = sc.createHash(prepareMessage(nonceCard));
        if (!sc.verify(msg2HashComponents,nonceCardResponseHashSign,autoPubSK)) {
            //TODO: throw error or something (tamper bit). Also stop further actions.
            errorState("Invalid hash of nonce returned in message 2 of P1");
            manipulation = true;
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }

        //nonceAuto
        short nonceAuto = msg2.getShort(curBufIndex);

        //Message 3
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        byte[] msg3HashSign = sc.sign(shortToByteArray(nonceAuto));
        msgBuf.putShort(nonceAuto).putInt(msg3HashSign.length);
        msgBuf.put(msg3HashSign);
        short msgLen = (short) (2 + 4 + msg3HashSign.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        //send(auto, msgBuf);
        //msgBuf.clear();
        //msgBuf.rewind();
        currentAwaited = ProtocolAwaited.INSS;
    }

    private void insertMS(APDU apdu){
        // Success message
        //dataLen = (byte) apdu.setIncomingAndReceive();
        ByteBuffer succMb = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA,apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
            succMb = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            return (PublicKey) errorState("Timeout in insert");
        }*/

        byte success = succMb.get(0);
        if(success != SUCCESS_BYTE){
            errorState("Wrong code, expected 0xFF");
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }
        short nonceSucc = succMb.getShort(1);
        if (!sc.areSubsequentNonces(nonceCard, nonceSucc)){
            errorState("Wrong nonce in success message of P1");
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }
        int nonceSuccSignLen = succMb.getInt(3);
        byte[] succMHashSign = newB(nonceSuccSignLen);
        succMb.get(succMHashSign,7,nonceSuccSignLen);
        //byte[] succMHash = sc.unsign(succMHashSign, autoPubSK);
        //byte[] succByte = {success};
        ByteBuffer succMsgCmps = newBB(3);
        succMsgCmps.put(success);
        succMsgCmps.putShort(nonceSucc);
        if(!sc.verify(succMsgCmps,succMHashSign,autoPubSK)){
            errorState("Invalid hash in success message (P1)");
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }
        currentAwaited = ProtocolAwaited.PROC;
    }

    /*Protocol 2 - Mutual Authentication between smartcard and reception terminal */
    public void authReception(APDU apdu) {
        // How does the card know if it is in a terminal or a car?
        // Potential solution: terminal or auto sends a basic message like "terminal!" or  "auto!"
        //note for P1: overleaf states you send 2 nonces in step 4. Current algorithm sends only 1.
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.putInt(sc.getCertificate().length - 133).put(sc.getCertificate()).putShort(sc.generateNonce());
        short msgLen = (short) (2 + 4 + sc.getCertificate().length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        //send(reception, msgBuf);
        //msgBuf.clear().rewind();
        currentAwaited = ProtocolAwaited.AUTHR2;

    }
    private void authReceptionM2(APDU apdu) {
        //byte dataLen = (byte) apdu.setIncomingAndReceive();
        ByteBuffer response = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA, apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in authReception response 1");
            return;
        }*/

        //Object[] responseData = processMessage(response);
        int receptionCertHSLength = response.get(0);
        byte[] rtPubSkb = newB(64);
        response.get(rtPubSkb, 4, 64);
        rtPubSK = bytesToPubkey(rtPubSkb);

        byte[] receptionID = newB(5);
        response.get(receptionID, 68, 5);


        byte[] receptionCertHashSign = newB(receptionCertHSLength);
        response.get(receptionCertHashSign, 73, receptionCertHSLength);

        nonceReception = response.getShort(73 + receptionCertHSLength);
        ByteBuffer msg2Cmps = newBB(69);
        msg2Cmps.put(rtPubSkb).put(receptionID);

        //byte[] receptionCertHash = sc.unsign(receptionCertHashSign, dbPubSK);

        //byte[] receptionIDPubSKHash = sc.createHash(concatBytes(rtPubSkb, receptionID));
        if (!sc.verify(msg2Cmps,receptionCertHashSign,dbPubSK)) { //Step 5
            manipulation = true;
            errorState("ReceptionCertHash does not match expected value, check for manipulation.");
            //TODO: Send message to terminal that process is stopped
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }
        byte[] noncePrepped = shortToByteArray(nonceReception);
        byte[] nonceReceptionHashSign = sc.sign(noncePrepped);
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.putShort(nonceReception).putInt(nonceReceptionHashSign.length).put(nonceReceptionHashSign);
        short msgLen = (short) (2 + 4 + nonceReceptionHashSign.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        //send(reception, msgBuf); //Step 6
        //msgBuf.clear().rewind();
        currentAwaited = ProtocolAwaited.AUTHRS;

    }
    private void authReceptionMS(APDU apdu) {
        //dataLen = (byte) apdu.setIncomingAndReceive();
        ByteBuffer response2 = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA,apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
            response2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in authReception response 2");
            return;
        }*/

        byte success = response2.get();
        if(success != SUCCESS_BYTE){
            errorState("Wrong byte code, expected 0xFF");
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }

        short nonceCardResp = response2.getShort();
        if(nonceCardResp != nonceCard){
            errorState("Wrong nonce returned in message 4 of P2");
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }

        int responseData2Length = response2.getInt();
        byte[] responseData2 = newB(responseData2Length); //To do: new byte -> Transient byte array
        response2.get(responseData2, 7, responseData2Length);
        //byte[] cardNonceHash = sc.unsign(responseData2, rtPubSK);
        //byte[] successByteArray = {success};
        //byte[] nonceCardHashValid = sc.createHash(concatBytes(successByteArray, shortToByteArray(nonceCard)));
        ByteBuffer succMsgCmps = newBB(3);
        succMsgCmps.put(success).putShort(nonceCard);
        if (!sc.verify(succMsgCmps,responseData2,rtPubSK)){ //Step 9
            errorState("Invalid hash in message 4 of P2");
            currentAwaited = ProtocolAwaited.AUTH;
            return;
        }

        terminalAuthenticated = true;
        currentAwaited = ProtocolAwaited.PROC;
        //Maybe let the terminal know how it went

    }
    /*Protocol 3 - Assignment of car to smartcard */
    public void carAssignmentStart(APDU apdu) {
        if (!terminalAuthenticated) { //Step 1
            return; //TODO: Placeholder
        }
        byte[] value = "Car?".getBytes(StandardCharsets.UTF_8);
        short nonceReceptionCount = ((short) (nonceReception + 1));
        byte[] giveCarSigned = sc.sign(concatBytes(value, shortToByteArray(nonceReceptionCount)));

        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.put(value).putShort(nonceReceptionCount).putInt(giveCarSigned.length).put(giveCarSigned);
        short msgLen = (short) (4 + 2 + 4 + giveCarSigned.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.CASS2;
        //send(reception, msgBuf);
        //msgBuf.clear();
        //msgBuf.rewind();
        //Step2

    }
    private void carAssignmentM2(APDU apdu) {
        //byte dataLen = (byte) apdu.setIncomingAndReceive();
        ByteBuffer response = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA,apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
            response = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in carAssignment response");
            return;
        }*/

        byte[] autoPubSkb = newB(64);
        response.get(autoPubSkb, 0, 64);
        autoPubSK = bytesToPubkey(autoPubSkb);

        byte[] autoID = newB(5); //To do: new byte -> Transient byte array
        response.get(autoID, 69, 5);

        int autoCertHSLength = response.getInt();
        byte[] autoCertHashSign = newB(autoCertHSLength); //To do: new byte -> Transient byte array
        response.get(autoCertHashSign, 73, autoCertHSLength);

        ByteBuffer msg2Cmps = newBB(69);
        msg2Cmps.put(autoPubSkb).put(autoID);
        //byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);
        //byte[] autoIDPubSKHash = sc.createHash(concatBytes(autoPubSkb, autoID));
        if (!sc.verify(msg2Cmps,autoCertHashSign,dbPubSK)){ //Step 7 - certificate
            //manipulation = true;
            errorState("Invalid car certificate received");
            currentAwaited = ProtocolAwaited.PROC;
            //TODO: Send message to terminal that process is stopped
            return;
        }

        short nonceCard2 = response.getShort();
        if (nonceCard2 != ((short) (nonceCard+1))){ //Step 7 - Sequence
            errorState("Wrong sequence number in message 2 of P3");
            currentAwaited = ProtocolAwaited.PROC;
            return;
        }
        int msg2SignLen = response.getInt();
        byte[] msg2HashSign = newB(msg2SignLen);
        response.get(msg2HashSign,79+autoCertHSLength,msg2SignLen);
        msg2Cmps.put(autoCertHashSign).putShort(nonceCard2);

        autoIDStored = autoID;
        //State transition????
        state = States.ASSIGNED;
        //Success message!
        byte[] successByteArray = {SUCCESS_BYTE};
        byte[] successHash = sc.sign(concatBytes(successByteArray, shortToByteArray((short) (nonceReception + 2))));
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.put(SUCCESS_BYTE).putShort((short) (nonceReception+2)).putInt(successHash.length).put(successHash);
        short msgLen = (short) (1+2+4+successHash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.AUTH;
        //send(reception, msgBuf);
        //msgBuf.clear().rewind();
    }

    public void kilometerageUpdate(APDU apdu){
        ByteBuffer receivedKmm = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA,apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
            receivedKmm = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in kilometerageUpdate km meter from car");
            return;
        }*/

        int oldKMM = kilometerage;

        /*kilometerage = (int) receivedKmmO[0];
        byte[] recKmmHashSign = (byte[]) receivedKmmO[1];
        byte[] recKmmHash = sc.unsign(recKmmHashSign, autoPubSK);
        byte[] validRecKmmHash = sc.createHash(prepareMessage(kilometerage));*/
        kilometerage = receivedKmm.getInt();
        int recKmmHashSignLength = receivedKmm.getInt();
        byte[] recKmmHashSign = newB(recKmmHashSignLength);
        receivedKmm.get(recKmmHashSign, 8, recKmmHashSignLength);
        //byte[] recKmmHash = sc.unsign(recKmmHashSign, autoPubSK);
        //byte[] validRecKmmHash = sc.createHash(intToByteArray(kilometerage));
        ByteBuffer msgCmps = newBB(4);
        msgCmps.putInt(kilometerage);
        if(!sc.verify(msgCmps,recKmmHashSign,rtPubSK)){
            errorState("Hashes do not match in kilometerage update! Potential manipulation!");
            currentAwaited = ProtocolAwaited.PROC;
            return;
            //TODO: throw error or something (tamper bit). Also stop further actions.
        }
        if (oldKMM >= kilometerage){
            manipulation = true;
            kilometerage = oldKMM; //TODO: Is this a security problem? race condition?
            currentAwaited = ProtocolAwaited.PROC;
        }
        byte confirmation = (byte) 1;
        byte[] confirmationArray = {1};
        byte[] confirmationHash = sc.sign(concatBytes(confirmationArray, intToByteArray(kilometerage)));
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.put(confirmation).putInt(kilometerage).putInt(confirmationHash.length).put(confirmationHash);
        short msgLen = (short) (1+4+4+confirmationHash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.PROC;
        //send(auto, msgBuf);
        //msgBuf.clear().reset();
    }

    private void carReturnStart(APDU apdu) {
        short seqNum1 = (short) (nonceReception + 1);
        byte[] car_return = "Car Return".getBytes(StandardCharsets.UTF_8);
        byte[] msg1Hash = sc.sign(concatBytes(car_return, shortToByteArray(seqNum1), booleanToByteArray(manipulation)));
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.put(car_return).putShort(seqNum1).put(booleanToByteArray(manipulation)).putInt(msg1Hash.length).put(msg1Hash);
        //send(rt, (byte) 56, seqNum1, manipulation, msg1Hash);
        short msgLen = (short) (10 + 2 + 1 + 4 + msg1Hash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        currentAwaited = ProtocolAwaited.CRET2;
        //send(rt, msgBuf);
        //msgBuf.clear().reset();

    }
    private void carReturnM2(APDU apdu) {
        //byte dataLen = (byte) apdu.setIncomingAndReceive();
        ByteBuffer msg2 = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA, apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
            msg2 = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in waiting for message 2 carReturn");
            return;
        }*/
        short seqNum1 = (short) (nonceReception + 1);
        short kmmNonce = msg2.getShort();
        short seqNum2 = msg2.getShort();
        int lengthHash = msg2.getInt();
        byte[] hash = newB(lengthHash); //To do: new byte -> Transient byte array
        msg2.get(hash, 8, lengthHash);
        if (!sc.areSubsequentNonces(nonceCard, seqNum2)) {
            errorState("Wrong sequence number in carReturn message 2");
            currentAwaited = ProtocolAwaited.PROC;
            return;
        }
        //byte[] msg2Hash = sc.unsign(hash, rtPubSK);
        //byte[] validMsg2Hash = sc.createHash(concatBytes(shortToByteArray(kmmNonce), shortToByteArray(seqNum2)));
        ByteBuffer msgCmps = newBB(4);
        msgCmps.putShort(kmmNonce).putShort(seqNum2);
        if (!sc.verify(msgCmps,hash,rtPubSK)) {
            //TODO: Error; also check sequence number (not in this if clause (obviously))
            errorState("Message hashes do not match in msg2 carReturn");
            currentAwaited = ProtocolAwaited.PROC;
            return;
        }
        byte[] msg3Hash = sc.sign(concatBytes(intToByteArray(kilometerage), shortToByteArray(kmmNonce), shortToByteArray((short) (seqNum1 + 1))));
        apdu.setOutgoing();
        ByteBuffer msgBuf = ByteBuffer.wrap(apdu.getBuffer());
        msgBuf.putInt(kilometerage).putShort(kmmNonce).putShort(((short) (seqNum1 + 1))).putInt(msg3Hash.length).put(msg3Hash);
        short msgLen = (short) (4 + 2 + 2 + 4 + msg3Hash.length);
        apdu.setOutgoingLength(msgLen);
        apdu.sendBytes((short) 0, msgLen);
        //send(rt, kilometerage, kmmNonce, seqNum1 + 1, msg3Hash);
        //send(rt, msgBuf);
        //msgBuf.clear().rewind();
        kilometerage = 0;

        //TODO: Remove certificate of car (e.g. by setting it to null)
        state = States.ASSIGNED_NONE;
        autoIDStored = null; //Placeholder
        autoPubSK = null; //Placeholder
        currentAwaited = ProtocolAwaited.CRETS;

    }
    private void carReturnMS(APDU apdu) {
        //dataLen = (byte) apdu.setIncomingAndReceive();

        ByteBuffer succMsg = ByteBuffer.wrap(apdu.getBuffer()).slice(ISO7816.OFFSET_CDATA, apdu.getBuffer()[ISO7816.OFFSET_LC]);
        /*try {
            succMsg = waitForInput();
        } catch (MessageTimeoutException e) {
            e.printStackTrace();
            errorState("Timeout in waiting for message 2 carReturn");
            return;
        }*/

        byte success = succMsg.get();
        if(success != SUCCESS_BYTE){
            errorState("Wrong code, expected 0xFF");
            currentAwaited = ProtocolAwaited.PROC;
            return;
        }
        short succNonce = succMsg.getShort();
        if (!sc.areSubsequentNonces(nonceCard, succNonce, 2)){
            errorState("Wrong sequence number in success message of P4");
            currentAwaited = ProtocolAwaited.PROC;
            return;
        }
        int hashLength = succMsg.getInt();
        byte[] signedSuccHash = newB(hashLength); //To do: new byte -> Transient byte array
        succMsg.get(signedSuccHash, 7, hashLength);
        //byte[] succHash = sc.unsign((byte[]) signedSuccHash, rtPubSK);
        ByteBuffer msgCmps = newBB(3);
        msgCmps.put(success).putShort(succNonce);
        if(!sc.verify(msgCmps,signedSuccHash,rtPubSK)){
            errorState("Invalid hash in success message of Protocol 4");
            currentAwaited = ProtocolAwaited.PROC;
            return;
        }
        currentAwaited = ProtocolAwaited.AUTH;
    }

    private class SmartcardCrypto extends CryptoImplementation {


        public SmartcardCrypto(byte[] cardID, byte[] cardCertificate, PrivateKey privateKey) {
            super.ID = cardID;
            super.certificate = cardCertificate;
            super.rc = new SmartCardWallet();
            ((KeyWallet) super.rc).storePrivateKey(privateKey);
        }

        private class SmartCardWallet extends RSACrypto implements KeyWallet{

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