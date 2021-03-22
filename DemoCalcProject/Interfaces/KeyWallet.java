package Interfaces;

import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class KeyWallet {

    public abstract void storePublicKey();
    public abstract void storePrivateKey();
    public abstract PublicKey getPublicKey();
    //public abstract PrivateKey getPrivateKey();

}
