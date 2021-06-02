package rsa;

import java.security.SecureRandom;

public abstract class CryptoImplementationExtended extends CryptoImplementation{

    SecureRandom sr = new SecureRandom();

    @Override
    public short generateNonce(){
        byte[] bytes = new byte[2];
        sr.nextBytes(bytes);
        return (short)(((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF));

    }

    @Override
    public byte[] generateID(){
        byte[] bytes = new byte[5];
        sr.nextBytes(bytes);
        return bytes;
    }

}
