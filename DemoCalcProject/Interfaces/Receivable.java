package Interfaces;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.Queue;

public interface Receivable {
    Queue<byte[]> inputQueue = new LinkedList<>();

    /*default void receiveLegacy(byte[] message) {
        inputQueue.add(ByteBuffer.wrap(message));
    }*/

    default void receive(byte[] message) {
        inputQueue.add(ByteBuffer.wrap(message));
    }


}