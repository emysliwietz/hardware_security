package Interfaces;

public interface ProtocolComponentLengths {
    //defined by system
    final static byte SHORT_LEN = Short.BYTES;
    final static byte INT_LEN = Integer.BYTES;
    final static byte BYTE_LEN = Byte.BYTES;
    final static byte BYTE_BIT_LEN = Byte.SIZE;

    //defined by us
    final static byte BOOL_LEN = 1;
    final static byte ID_LEN = 5;
    final static byte NONCE_LEN = SHORT_LEN;

    //defined by cryptographic algorithm used
    final static byte SIGNED_HASH_LEN = 64;
    final static byte RSA_KEY_EXPONENT_MAX_LENGTH = 64;
    final static byte RSA_KEY_MODULUS_MAX_LENGTH = 64;

    //defined by our implementation of turning key to bytes
    final static short KEY_LEN = SHORT_LEN + RSA_KEY_EXPONENT_MAX_LENGTH
            + SHORT_LEN + RSA_KEY_MODULUS_MAX_LENGTH; //132

}
