package rsa;

import java.security.SecureRandom;

public abstract class CryptoImplementationExtended extends CryptoImplementation {

    SecureRandom sr = new SecureRandom();

    @Override
    public short generateNonce() {
        byte[] bytes = new byte[NONCE_LEN];
        sr.nextBytes(bytes);
        return (short) (((bytes[0] & 0xFF) << BYTE_BIT_LEN) | (bytes[1] & 0xFF));

    }

    @Override
    public byte[] generateID() {
        byte[] bytes = new byte[ID_LEN];
        sr.nextBytes(bytes);
        return bytes;
    }

}
