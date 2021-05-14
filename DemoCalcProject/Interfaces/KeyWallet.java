package Interfaces;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyWallet {

    public abstract void storePublicKey();
    public abstract void storePrivateKey(PrivateKey privateKey);
    public abstract PublicKey getPublicKey();
    //public abstract PrivateKey getPrivateKey();

}
