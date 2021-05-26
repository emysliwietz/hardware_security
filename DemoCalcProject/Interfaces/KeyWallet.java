package Interfaces;

import javacard.security.PrivateKey;
import javacard.security.PublicKey;

public interface KeyWallet {

    public abstract void storePublicKey();
    public abstract void storePrivateKey(PrivateKey privateKey);
    public abstract PublicKey getPublicKey();
    //public abstract PrivateKey getPrivateKey();

}
