package Interfaces;

import java.nio.ByteBuffer;
import java.util.Stack;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 @author Matti Eisenlohr
 @author Egidius Mysliwietz
 */
public interface Receivable {
    Stack<ByteBuffer> inputQueue = new Stack<>();
    ReadWriteLock lock = new ReentrantReadWriteLock();


    default void receive(byte[] message) {
        //possible TOCTOU here in combination with waitingForInput
        lock.readLock().lock();
        //lock.writeLock().lock();
        if(!inputQueue.isEmpty()){
            inputQueue.clear();
        }
        inputQueue.add(ByteBuffer.wrap(message));
        lock.readLock().unlock();
        //lock.writeLock().unlock();
    }


}