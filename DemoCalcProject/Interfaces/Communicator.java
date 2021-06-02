package Interfaces;

import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.security.*;
import javacard.framework.APDU;

/**
 @author Matti Eisenlohr
 @author Egidius Mysliwietz
 */
public interface Communicator {

    // CLA codes for APDU header
    final static byte CARD_SELECT = ISO7816.CLA_ISO7816;
    final static byte CARD_AUTH  = (byte) 0xB0; //authentication protocols
    final static byte CARD_PROC  = (byte) 0xC0; //processing protocols
    final static byte CARD_CONT  = (byte) 0xD0; //protocol continuation messages
    final static byte CARD_EOL   = (byte) 0xE0;
    final static byte CARD_INIT  = (byte) 0xF0;
    final static byte CARD_DEBUG = (byte) 0xA0;

    // INS codes for APDU header
    final static byte INSERT_START = (byte) 0x20;
    final static byte INSERT_M2 = (byte) 0x21;
    final static byte INSERT_MS = (byte) 0x22;
    final static byte AUTH_RECEPTION_START = (byte) 0x30;
    final static byte AUTH_RECEPTION_M2 = (byte) 0x31;
    final static byte AUTH_RECEPTION_MS = (byte) 0x32;
    final static byte CAR_ASSIGNMENT_START = (byte) 0x40;
    final static byte CAR_ASSIGNMENT_M2 = (byte) 0x41;
    final static byte KMM_UPDATE = (byte) 0x50;
    final static byte CAR_RETURN_START = (byte) 0x60;
    final static byte CAR_RETURN_M2 = (byte) 0x62;
    final static byte CAR_RETURN_MS = (byte) 0x63;
    final static byte BLOCK = (byte) 0x70;
    final static byte INIT = (byte) 0x80;
    final static byte DEBUG = (byte) 0x90;

    // SW APDU Response Codes
    // There are only negative SW Codes
    //final static short AUTH_SUCCESS = 0x6100;
    //final static short AUTH_SUCCESS_MANIPULATION = 0x6101;
    final static short AUTH_FAILED  = 0x5100;
    final static short AUTH_FAILED_MANIPULATION = 0x5101;
    //final static short PROC_SUCCCESS = 0x6200;
    final static short PROC_FAILED = 0x5200;
    final static short WRONG_CONTINUATION = 0x5300;
    final static short CARD_NOT_INITIALIZED = 0x4000;

    public static final byte SUCCESS_BYTE = (byte) 0xFF;

    final static int KEY_LEN = 2+64+2+64; //132
    final static int EAPDU_CDATA_OFFSET = 7;
    final static int ERESPAPDU_CDATA_OFFSET = 0;

    //TODO: Remove
    //Smartcard probably doesn't support print method
    default Object errorState(String msg) {
        System.err.println("I don't want to be here...");
        System.err.println(msg);
        return null;
    }

    //make a transient byte array with length len
    default byte[] newB(int len) {
        return JCSystem.makeTransientByteArray((short) len, JCSystem.CLEAR_ON_RESET);
    }

    default byte[] newStaticB(int len) {
        return new byte[len];
        //return JCSystem.makeTransientByteArray((short) len, JCSystem.MEMORY_TYPE_PERSISTENT);
    }

    default PublicKey bytesToPubkey(byte[] bytes) {
        RSAPublicKey pk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
                KeyBuilder.LENGTH_RSA_512, false);
        short expLength = getShort(bytes,0);
        byte[] exp = newB(expLength);
        memCpy(exp,bytes,2,expLength);
        short modLength = getShort(bytes,2+expLength);
        byte[] mod = newB(modLength);
        memCpy(mod,bytes,expLength+4,modLength);
        pk.setExponent(exp, (short) 0, expLength);
        pk.setModulus(mod, (short) 0, modLength);
        return pk;
    }

    default PrivateKey bytesToPrivkey(byte[] bytes) {
        RSAPrivateKey pk = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                KeyBuilder.LENGTH_RSA_512, false);
        short expLength = getShort(bytes,0);
        byte[] exp = newB(expLength);
        memCpy(exp,bytes,2,expLength);
        short modLength = getShort(bytes,2+expLength);
        byte[] mod = newB(modLength);
        memCpy(mod,bytes,expLength+4,modLength);
        pk.setExponent(exp, (short) 0, expLength);
        pk.setModulus(mod, (short) 0, modLength);
        return pk;
    }

    default byte[] pubkToBytes(PublicKey pubk){
        //Crash if we reduce length. Actual lengths trimmed with memCpy
        byte[] b = newB(KEY_LEN);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) pubk;
        short expLength = rsaPublicKey.getExponent(b,(short) 2);
        putShort(b,(short) 0, expLength);
        short modLength = rsaPublicKey.getModulus(b, (short) (4+expLength));
        putShort(b, (short) (2+expLength), modLength);
        //byte[] bb = JCSystem.makeTransientByteArray((short) (expLength+modLength+4),JCSystem.CLEAR_ON_RESET);
        //System.out.println(Arrays.toString(b.array()));
        //memCpy(bb,b.array(),b.arrayOffset(),expLength+modLength+4);
        //print(bb.length);
        return b;
        //return bb;
    }

    default byte[] privkToBytes(PrivateKey privk){
        //Crash if we reduce length. Actual lengthz trimmed with memCpy
        byte[] b = newB(KEY_LEN);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privk;
        short expLength = rsaPrivateKey.getExponent(b,(short) 2);
        putShort(b, (short) 0, expLength);
        short modLength = rsaPrivateKey.getModulus(b,(short) (4+expLength));
        putShort(b, (short) (2+expLength), modLength);
        //byte[] bb = JCSystem.makeTransientByteArray((short) (expLength+modLength+4),JCSystem.CLEAR_ON_RESET);
        //System.out.println(Arrays.toString(b.array()));
        //memCpy(bb,b.array(),b.arrayOffset(),expLength+modLength+4);
        return b;
        //return bb;
    }


    default byte[] concatBytes(byte[] a, byte[] b){
        byte[] c = newB(a.length + b.length);

        //System.arraycopy(a,0,c,0,a.length);
        //System.arraycopy(b,0,c,a.length,b.length);
        memCpy(c, a, 0, 0, a.length);
        memCpy(c, b, a.length, 0, b.length);
        return c;
    }

    default byte[] concatBytes(byte[]... byteArrays) {
        int total_length = 0;
        int curr = 0;
        for (byte[] b : byteArrays) {
            total_length += b.length;
        }
        byte[] c = newB(total_length);
        for (byte[] b : byteArrays) {
            //System.arraycopy(b, 0, c, curr, b.length);
            memCpy(c, b, curr, 0, b.length);
            curr += b.length;
        }
        return c;
    }


    default byte[] intToByteArray(int value) {
        byte[] i = newB(4);
        for (int offset = 0; offset < 4; offset++) {
            i[offset] = (byte)(value >>> (8 * offset));
        }
        return i;
    }

    //Used to return reference to same byte[] so method is nestable,
    //but resulting code is ugly, so returns length of toPut
    default short put(byte[] b, byte[] toPut, int offset) {
        memCpy(b, toPut, offset, toPut.length);
        return (short) toPut.length;
    }

    default short putShort(byte[] b, short s, int offset) {
        byte[] a = shortToByteArray(s);
        memCpy(b, a, (short) offset, (short) 0, (short) a.length);
        return (short) a.length; //2
    }

    default short putInt(byte[] b, int i, int offset){
        byte[] a = intToByteArray(i);
        /*for(byte j=0;j<4;j++){
            b[j+offset] = a[j];
        }*/
        memCpy(b, a, (short) offset, (short) 0, (short) a.length);
        return (short) a.length; //4
    }

    default int threeBytesToInt(byte[] b, int offset){
        return (((b[offset] & 0xFF) << 16) |
                ((b[offset + 1] & 0xFF) << 8 ) |
                ((b[offset + 2] & 0xFF)));
    }

    default int getInt(byte[] b, int offset){
        return intFromByteArray(b, (short) offset);
    }

    default int intFromByteArray(byte[] bytes, short offset) {
        return ((bytes[offset] & 0xFF) << 24) |
                ((bytes[offset + 1] & 0xFF) << 16) |
                ((bytes[offset + 2] & 0xFF) << 8 ) |
                ((bytes[offset + 3] & 0xFF));
    }

    default int intFromByteArray(byte[] bytes) {
        return intFromByteArray(bytes, (short) 0);
    }

    default byte[] shortToByteArray(short value) {
        byte[] s = newB(2);
        s[0] = (byte) (value >>> 8);
        s[1] = (byte) value;
        return s;
    }

    // Take first two bytes of b at the offset and turn them into a short
    default short getShort(byte[] b, int offset){
        return shortFromByteArray(b, (short) offset);
    }

    default short shortFromByteArray(byte[] bytes) {
        return shortFromByteArray(bytes, (short) 0);
    }

    default short shortFromByteArray(byte[] bytes, short offset) {
        return (short) (((bytes[offset] & 0xFF) << 8 ) |
                ((bytes[offset + 1] & 0xFF)));
    }

    default byte[] booleanToByteArray(boolean b) {
        byte[] bb = newB(1);
        bb[0] = b ? Byte.MAX_VALUE : 0x00;
        return bb;
    }

    default boolean booleanFromByte(byte b) {
        return (b != 0);
    }

    default void memCpy(byte[] dest, byte[] src, short destOffset, short srcOffset, short n) {
        // We don't use "if (n >= 0) System.arraycopy(src, offset + 0, dest, 0, n);"
        // because we're not sure if a smartcard supports this library operation
        // (ByteBuffer, although a library class as well, should be different, as
        // it _should_ be translated directly into JVM bytecode without any class
        // overhead. The same _probably_ applies to System.arraycopy but we didn't
        // confirmed that, so we opted for this manual implementation.)
        // We are aware that ByteBuffer uses arraycopy internally.
        for(short i=0;i<n;i++){
            dest[destOffset + i] = src[srcOffset + i];
        }
    }

    default void memCpy(byte[] dest, byte[] src, short offset, short n){
        memCpy(dest, src, (short) 0, offset, n);
    }

    default void memCpy(byte[] dest, byte[] src, int destOffset, int srcOffset, int n){
        memCpy(dest, src, (short) destOffset, (short) srcOffset, (short) n);
    }

    default void memCpy(byte[] dest, byte[] src, int offset, int n){
        memCpy(dest, src, (short) offset, (short) n);
    }

    default byte[] clearBuf(APDU apdu){
        byte[] b = apdu.getBuffer();
        int apduLen = threeBytesToInt(b,4)+10;
        return clearBuf(b, apduLen);
    }

    default byte[] clearBuf(byte[] b, int len){
        for (int i = 0;i<len;i++) {
            b[i] = 0;
        }
        return b;
    }

}
