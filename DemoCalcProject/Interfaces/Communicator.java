package Interfaces;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedList;
import java.util.Queue;

public interface Communicator extends Receivable {

    public static final byte SUCCESS_BYTE = (byte) 0xFF;
    final int WAITING_TIMEOUT /* ms */ = 1000 * 10;

    default byte[] prepareMessage(Object ... objects){
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

    default PublicKey bytesToPubkey(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }


    default byte[] concatBytes(byte[] a, byte[] b){
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a,0,c,0,a.length);
        System.arraycopy(b,0,c,a.length,b.length);
        return c;
    }

    default byte[] concatBytes(byte[]... byteArrays) {
        int total_length = 0;
        int curr = 0;
        for (byte[] b : byteArrays) {
            total_length += b.length;
        }
        byte[] c = new byte[total_length];
        for (byte[] b : byteArrays) {
            System.arraycopy(b, 0, c, curr, b.length);
            curr += b.length;
        }
        return c;
    }

    default Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        return null;
    }

    default void sendLegacy(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }

    default byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value};
    }

    default int intFromByteArray(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8 ) |
                ((bytes[3] & 0xFF));
    }

    default byte[] shortToByteArray(short value) {
        return new byte[] {
                (byte)(value >>> 8),
                (byte)value};
    }

    default short shortFromByteArray(byte[] bytes) {
        return (short) (((bytes[2] & 0xFF) << 8 ) |
                ((bytes[3] & 0xFF)));
    }

    default void send(Receivable receiver, ByteBuffer msgBuf){
        receiver.receive(msgBuf.array());
    }

    default Object[] processMessage(byte[] message){
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

    default ByteBuffer waitForInput() throws MessageTimeoutException {
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

    class MessageTimeoutException extends Exception {
    }
}
