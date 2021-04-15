package Interfaces;

import java.util.LinkedList;
import java.util.Queue;

public interface Receivable {
    Queue<byte[]> inputQueue = new LinkedList<>();

    default void receive(byte[] message) {
        inputQueue.add(message);
    }


}