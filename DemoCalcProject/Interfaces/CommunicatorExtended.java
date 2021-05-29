package Interfaces;

import org.jetbrains.annotations.NotNull;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;
import java.nio.ByteBuffer;

public abstract class CommunicatorExtended implements Communicator, Receivable {
    final int WAITING_TIMEOUT /* ms */ = 1000 * 10;
    protected static final byte[] SC_APPLET_AID = {
            (byte) 0x3B,
            (byte) 0x29,
            (byte) 0x63,
            (byte) 0x61,
            (byte) 0x6C,
            (byte) 0x63,
            (byte) 0x01
    };
    protected byte[] cardID;
    protected CardChannel applet;
    protected boolean cardAuthenticated = false;
    protected final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, SC_APPLET_AID);

    @Override
    public Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        cardAuthenticated = false;
        cardID = null;
        return null;
    }

    protected ResponseAPDU sendAPDU(int cla, int ins, @NotNull ByteBuffer data) {
        CommandAPDU commandAPDU = new CommandAPDU(cla,ins,0,0,data.array(),data.arrayOffset(),data.array().length,1024);
        try {
            return applet.transmit(commandAPDU);
        } catch (CardException e) {
            e.printStackTrace();
            return null;
        }
    }

    protected byte[] prepareMessage(Object ... objects){
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



    protected void send(Receivable receiver, ByteBuffer msgBuf){
        receiver.receive(msgBuf.array());
    }

    protected Object[] processMessage(byte[] message){
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

  /*  default byte[] waitForInputLegacy() throws MessageTimeoutException {
        int totalwait = 0;
        while (inputQueue.isEmpty()){
            try {
                Thread.sleep(100);
                totalwait += 100;
                if (totalwait > WAITING_TIMEOUT)
                    throw new MessageTimeoutException();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return inputQueue.remove();
    }*/

    public static class MessageTimeoutException extends Exception {}

    protected ByteBuffer waitForInput() throws MessageTimeoutException {
        int totalwait = 0;
        while (inputQueue.isEmpty()){
            try {
                Thread.sleep(100);
                totalwait += 100;
                if (totalwait > WAITING_TIMEOUT)
                    throw new MessageTimeoutException();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return inputQueue.remove();
    }

    protected void sendLegacy(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }
}
