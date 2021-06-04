package Interfaces;

import javacard.security.PrivateKey;
import javacard.security.PublicKey;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 */
public interface KeyWallet {

    void storePublicKey();

    void storePrivateKey(PrivateKey privateKey);

    PublicKey getPublicKey();
    //public abstract PrivateKey getPrivateKey();

}
