package test.Smartcard;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SmartcardTest {

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void publicKeySize() {
        /* Database db = new Database();
        Object[] kp = db.generateKeyPair();
        RSAPublicKey pk = (RSAPublicKey) kp[0];
        print(pk);
        print("");
        //Smartcard sc = new Smartcard(new byte[1], new byte[1]);
        byte[] mp = sc.prepareMessage(pk);
        print("Byte array of public key using prepareMessage: (length: " + mp.length + "b)");
        print(mp);
        print("");
        byte[] pke = pk.getEncoded();
        print("Byte array of public key using build-in method: (length: " + pke.length + "b)");
        print(pke);
        print("");
        print("Build-in is " + ((mp.length + 0.0) / pke.length) + " times smaller than our garbage code");
        print("");
        RSAPrivateKey prk = (RSAPrivateKey) kp[1];
        print(prk);
        print("");
        byte[] mpr = sc.prepareMessage(prk);
        print("Byte array of private key using prepareMessage: (length: " + mpr.length + "b)");
        print(mpr);
        print("");
        byte[] prke = prk.getEncoded();
        print("Byte array of private key using build-in method: (length: " + prke.length + "b)");
        print(pke);
        print("");
        print("Build-in is " + ((mpr.length + 0.0) / prke.length) + " times smaller than our garbage code");*/
    }
}