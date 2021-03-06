package Interfaces;

import javacard.framework.ISOException;
import org.jetbrains.annotations.NotNull;
import utility.Logger;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 */
public abstract class CommunicatorExtended implements Communicator, Receivable {
    protected static final byte[] SC_APPLET_AID = {
            (byte) 0x3B,
            (byte) 0x29,
            (byte) 0x63,
            (byte) 0x61,
            (byte) 0x6C,
            (byte) 0x63,
            (byte) 0x01
    };
    protected final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, SC_APPLET_AID);
    final int WAITING_TIMEOUT /* ms */ = 10000 * 10;
    protected byte[] cardID;
    protected CardChannel applet;
    protected boolean cardAuthenticated = false;
    protected ByteBuffer msgBuf = ByteBuffer.allocate(512);
    protected Logger logger;

    @Override
    public Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        cardAuthenticated = false;
        cardID = null;
        return null;
    }

    public ResponseAPDU sendErrorAPDU(byte currentMethodINS, short status_word) {
        return sendAPDU(CARD_ERROR, currentMethodINS, shortToByteArray(status_word), (short) 0, SHORT_LEN);
    }

    //make a transient byte array with length len
    @Override
    public byte[] newB(int len) {
        return new byte[len];
    }

    //make a byte buffer with length len
    public ByteBuffer newBB(int len) {
        return ByteBuffer.allocate(len);
    }

    protected ResponseAPDU sendAPDU(int cla, int ins, @NotNull ByteBuffer data) {
       return sendAPDU((byte) cla, (byte) ins, data.array(), (short) data.arrayOffset(), (short) data.array().length);
    }

    protected ResponseAPDU sendAPDU(byte cla, byte ins, @NotNull byte[] data, short dataOffset, short dataLength) {
        CommandAPDU commandAPDU = new CommandAPDU(cla, ins, 0, 0, data, dataOffset, dataLength, 1024);
        try {
            logger.info(String.format("Sent APDU %x %x with %d bytes of data", cla, ins, dataLength), "sendAPDU", cardID);
            ResponseAPDU response = applet.transmit(commandAPDU);
            logger.info(String.format("Received APDU of length %d with %d bytes of data", response.getBytes().length, response.getData().length), "sendAPDU", cardID);
            if (response.getBytes().length == 2) {
                logger.info("APDU has SW: " + Arrays.toString(intToByteArray(response.getSW())), "sendAPDU", cardID);
            }
            return response;
        } catch (CardException e) {
            logger.fatal(e.getMessage(), "sendAPDU", cardID);
            e.printStackTrace();
            return null;
        }
    }

    protected byte[] prepareMessage(Object... objects) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(bos);
            oos.writeObject(objects);
            oos.flush();
            oos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }


    protected void send(Receivable receiver, ByteBuffer msgBuf) {
        receiver.receive(msgBuf.array());
    }

    protected Object[] processMessage(byte[] message) {
        ByteArrayInputStream bis = new ByteArrayInputStream(message);
        Object o = null;
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            o = ois.readObject();
            ois.close();
            bis.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return (Object[]) o;
    }

    protected synchronized ByteBuffer waitForInput() throws MessageTimeoutException {
        //lock.readLock().lock();
        int totalwait = 0;
        while (inputQueue.isEmpty()) {
            try {
                Thread.sleep(100);
                totalwait += 100;
                if (totalwait > WAITING_TIMEOUT)
                    throw new MessageTimeoutException();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        lock.writeLock().lock();
        ByteBuffer input = inputQueue.pop();
        lock.writeLock().unlock();
        return input;
    }

    protected void sendLegacy(Receivable receiver, Object... msgComponents) {
        receiver.receive(prepareMessage(msgComponents));
    }

    protected byte[] clearBuf(ByteBuffer b) {
        return clearBuf(b.array(), b.limit());
    }

    public static class MessageTimeoutException extends Exception {
    }

    public static class CardNotInitializedException extends Exception {
        public CardNotInitializedException(String s) {
            super(s);
        }
    }

    public static class AuthenticationFailedException extends Exception {
        public AuthenticationFailedException(String s) {
            super(s);
        }
    }
    public static class ProcessFailedException extends Exception {
        public ProcessFailedException(String s) {
            super(s);
        }
    }
}
