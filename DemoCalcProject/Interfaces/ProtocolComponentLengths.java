package Interfaces;

/**
 * @author Egidius Mysliwietz
 */
public interface ProtocolComponentLengths {
    //defined by system
    byte SHORT_LEN = Short.BYTES;
    byte INT_LEN = Integer.BYTES;
    byte BYTE_LEN = Byte.BYTES;
    byte BYTE_BIT_LEN = Byte.SIZE;

    //defined by us
    byte BOOL_LEN = 1;
    byte ID_LEN = 5;
    byte NONCE_LEN = SHORT_LEN;

    //defined by cryptographic algorithm used
    byte SIGNED_HASH_LEN = 64;
    byte RSA_KEY_EXPONENT_MAX_LENGTH = 64;
    byte RSA_KEY_MODULUS_MAX_LENGTH = 64;

    //defined by our implementation of turning key to bytes
    short KEY_LEN = SHORT_LEN + RSA_KEY_EXPONENT_MAX_LENGTH
            + SHORT_LEN + RSA_KEY_MODULUS_MAX_LENGTH; //132

}
