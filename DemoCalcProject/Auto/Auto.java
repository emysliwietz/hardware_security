package Auto;

import Interfaces.Receivable;

public class Auto implements Receivable {

    @Override
    public void receive(byte[] message) {

        return message;
    }
}