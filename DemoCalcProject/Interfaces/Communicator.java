package Interfaces;

import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

import javacard.framework.JCSystem;
import javacard.security.*;
import javacard.framework.APDU;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

import static utility.Util.print;

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

    //make a byte buffer with length len
    default ByteBuffer newBB(int len) {
        return ByteBuffer.wrap(newB(len));
    }

    default PublicKey bytesToPubkey(byte[] bytes) {
        RSAPublicKey pk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        ByteBuffer b = ByteBuffer.wrap(bytes);
        short expLength = getShort(bytes,0);//b.getShort();
        byte[] exp = newB(expLength);
        memCpy(exp,bytes,2,expLength);
        //b.get(exp, 0, expLength);
        short modLength = getShort(bytes,2+expLength);//b.getShort(2+expLength);
        byte[] mod = newB(modLength);
        memCpy(mod,bytes,expLength+4,modLength);
        //b.get(mod,0, modLength);
        pk.setExponent(exp, (short) 0, expLength);
        pk.setModulus(mod, (short) 0, modLength);
        return pk;
        /*try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }*/
    }

    default PrivateKey bytesToPrivkey(byte[] bytes) {
        RSAPrivateKey pk = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        ByteBuffer b = ByteBuffer.wrap(bytes);
        short expLength = getShort(bytes,0);//b.getShort();
        byte[] exp = newB(expLength);
        memCpy(exp,bytes,2,expLength);
        //b.get(exp, 0, expLength);
        short modLength = getShort(bytes,2+expLength);//b.getShort(2+expLength);
        byte[] mod = newB(modLength);
        memCpy(mod,bytes,expLength+4,modLength);
        //b.get(mod, 0, modLength);
        pk.setExponent(exp, (short) 0, expLength);
        pk.setModulus(mod, (short) 0, modLength);
        return pk;
        /*try {
            return KeyFactory.getInstance("RSA").generatePrivate(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }*/
    }

    default byte[] pubkToBytes(PublicKey pubk){
        //Crash if we reduce length. Actual lengths trimmed with memCpy
        ByteBuffer b = newBB(KEY_LEN);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) pubk;
        short expLength = rsaPublicKey.getExponent(b.array(),(short) 2);
        b.putShort(0,expLength);
        short modLength = rsaPublicKey.getModulus(b.array(),(short) (4+expLength));
        b.putShort(2+expLength, modLength);
        //byte[] bb = JCSystem.makeTransientByteArray((short) (expLength+modLength+4),JCSystem.CLEAR_ON_RESET);
        //System.out.println(Arrays.toString(b.array()));
        //memCpy(bb,b.array(),b.arrayOffset(),expLength+modLength+4);
        //print(bb.length);
        return b.array();
        //return bb;
    }

    default byte[] privkToBytes(PrivateKey privk){
        //Crash if we reduce length. Actual lengthz trimmed with memCpy
        ByteBuffer b = newBB(KEY_LEN);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privk;
        short expLength = rsaPrivateKey.getExponent(b.array(),(short) 2);
        b.putShort(0,expLength);
        short modLength = rsaPrivateKey.getModulus(b.array(),(short) (4+expLength));
        b.putShort(2+expLength, modLength);
        //byte[] bb = JCSystem.makeTransientByteArray((short) (expLength+modLength+4),JCSystem.CLEAR_ON_RESET);
        //System.out.println(Arrays.toString(b.array()));
        //memCpy(bb,b.array(),b.arrayOffset(),expLength+modLength+4);
        return b.array();
        //return bb;
    }


    default byte[] concatBytes(byte[] a, byte[] b){
        byte[] c = new byte[a.length + b.length];

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
        byte[] c = new byte[total_length];
        for (byte[] b : byteArrays) {
            //System.arraycopy(b, 0, c, curr, b.length);
            memCpy(c, b, curr, 0, b.length);
            curr += b.length;
        }
        return c;
    }


    default byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value};
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
        return intFromByteArray(new byte[]{0,b[offset],b[offset+1],b[offset+2]});
    }

    default int getInt(byte[] b, int offset){
        return intFromByteArray(new byte[]{b[offset],b[offset+1],b[offset+2],b[offset+3]});
    }

    default int intFromByteArray(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8 ) |
                ((bytes[3] & 0xFF));
    }

    default byte[] shortToByteArray(short value) {
        return new byte[] {
                (byte)(value >>> 8),
                (byte)value};
    }

    // Take first two bytes of b at the offset and turn them into a short
    default short getShort(byte[] b, int offset){
        return shortFromByteArray(new byte[]{b[offset],b[offset+1]});
    }

    default short shortFromByteArray(byte[] bytes) {
        return (short) (((bytes[0] & 0xFF) << 8 ) |
                ((bytes[1] & 0xFF)));
    }

    default byte[] booleanToByteArray(boolean b) {
        return new byte[]{b ? Byte.MAX_VALUE : 0x00};
    }

    default boolean booleanFromByte(byte b) {
        return (b != 0);
    }

    default void memCpy(byte[] dest, byte[] src, short destOffset, short srcOffset, short n) {
        //We don't use "if (n >= 0) System.arraycopy(src, offset + 0, dest, 0, n);"
        //because we're not sure if a smartcard supports this library operation
        //(ByteBuffer, although a library class as well, should be different, as
        // it _should_ be translated directly into JVM bytecode without any class
        // overhead. The same _probably_ applies to System.arraycopy but we didn't
        // confirmed that, so we opted for this manual implementation.)
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
        for (int i = 0;i<apduLen;i++) {
            b[i] = 0;
        }
        return b;
    }

}
