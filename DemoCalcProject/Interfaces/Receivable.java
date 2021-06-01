package Interfaces;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.Queue;

/**
 @author Matti Eisenlohr
 @author Egidius Mysliwietz
 */
public interface Receivable {
    Queue<ByteBuffer> inputQueue = new LinkedList<>();

    /*default void receiveLegacy(byte[] message) {
        inputQueue.add(ByteBuffer.wrap(message));
    }*/

    default void receive(byte[] message) {
        inputQueue.add(ByteBuffer.wrap(message));
    }


}