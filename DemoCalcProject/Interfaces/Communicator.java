package Interfaces;

import java.io.*;
import java.util.LinkedList;
import java.util.Queue;

public interface Communicator {

    Queue<byte[]> inputQueue = new LinkedList<>();

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

    default byte[] waitForInput(){
        while (inputQueue.isEmpty()){
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return inputQueue.remove();
    }
}
