package test.interfaces;

import Interfaces.Communicator;
import db.Database;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.stream.IntStream;

import static utility.Util.print;

public class CommunicatorTest {

    private static class CommunicatorTester implements Communicator {}

    Database db;
    CommunicatorTester cm;
    RSAPublicKey pk;
    RSAPrivateKey sk;

    @BeforeEach
    void setUp() {
        db = new Database();
        cm = new CommunicatorTester();
        Object[] kp = db.generateKeyPair();
        pk = (RSAPublicKey) kp[0];
        sk = (RSAPrivateKey) kp[1];
    }

    @Test
    void pubkToBytesAndFromBytesAreInversesTest() {
        byte[] pkBytes = cm.pubkToBytes(pk);
        RSAPublicKey testKey = (RSAPublicKey) cm.bytesToPubkey(pkBytes);
        byte[] expOriginal = new byte[64];
        byte[] expTest = new byte[64];
        pk.getExponent(expOriginal, (short) 0);
        testKey.getExponent(expTest, (short) 0);
        byte[] modOriginal = new byte[64];
        byte[] modTest = new byte[64];
        pk.getModulus(modOriginal, (short) 0);
        testKey.getModulus(modTest, (short) 0);
        assertArrayEquals(expOriginal, expTest);
        assertArrayEquals(modOriginal, modTest);
    }

    @Test
    void privkToBytesAndFromBytesAreInversesTest() {
        byte[] skBytes = cm.privkToBytes(sk);
        RSAPrivateKey testKey = (RSAPrivateKey) cm.bytesToPrivkey(skBytes);
        byte[] expOriginal = new byte[64];
        byte[] expTest = new byte[64];
        sk.getExponent(expOriginal, (short) 0);
        testKey.getExponent(expTest, (short) 0);
        byte[] modOriginal = new byte[64];
        byte[] modTest = new byte[64];
        sk.getModulus(modOriginal, (short) 0);
        testKey.getModulus(modTest, (short) 0);
        assertArrayEquals(expOriginal, expTest);
        assertArrayEquals(modOriginal, modTest);
    }

    @Test
    void concatBytesTwoTest() {
        byte[] a = {0, 1, 2, 3, 4, 5, 6, 7, 8};
        byte[] b = {9, 10, 11, 12, 13, 14, 15, 16};
        byte[] concat = cm.concatBytes(a, b);
        byte[] exp = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        assertArrayEquals(exp, concat);
    }

    @Test
    void concatBytesMultipleTest() {
        byte[] a = {0, 4, 56};
        byte[] b = {1, 3, 3, 7};
        byte[] c = {69, 4, 20};
        byte[] d = {19, 84, 20, 22};
        byte[] concat = cm.concatBytes(a, b, c, d);
        byte[] exp = {0, 4, 56, 1, 3, 3, 7, 69, 4, 20, 19, 84, 20, 22};
        assertArrayEquals(exp, concat);
    }

    @Test
    void intToByteArrayAndFromByteArrayAreInversesTest() {
        int i = 48;
        int j = 987234;
        int k = -90183274;
        int l = Integer.MAX_VALUE;
        int m = Integer.MIN_VALUE;
        int n = 0;
        int i_a = cm.intFromByteArray(cm.intToByteArray(i));
        int j_a = cm.intFromByteArray(cm.intToByteArray(j));
        int k_a = cm.intFromByteArray(cm.intToByteArray(k));
        int l_a = cm.intFromByteArray(cm.intToByteArray(l));
        int m_a = cm.intFromByteArray(cm.intToByteArray(m));
        int n_a = cm.intFromByteArray(cm.intToByteArray(n));
        assertEquals(i, i_a);
        assertEquals(j, j_a);
        assertEquals(k, k_a);
        assertEquals(l, l_a);
        assertEquals(m, m_a);
        assertEquals(n, n_a);
    }

    @Test
    void shortToByteArrayAndFromByteArrayAreInversesTest() {
        short i = 48;
        short j = 9872;
        short k = -9018;
        short l = Short.MAX_VALUE;
        short m = Short.MIN_VALUE;
        short n = 0;
        short i_a = cm.shortFromByteArray(cm.shortToByteArray(i));
        short j_a = cm.shortFromByteArray(cm.shortToByteArray(j));
        short k_a = cm.shortFromByteArray(cm.shortToByteArray(k));
        short l_a = cm.shortFromByteArray(cm.shortToByteArray(l));
        short m_a = cm.shortFromByteArray(cm.shortToByteArray(m));
        short n_a = cm.shortFromByteArray(cm.shortToByteArray(n));
        assertEquals(i, i_a);
        assertEquals(j, j_a);
        assertEquals(k, k_a);
        assertEquals(l, l_a);
        assertEquals(m, m_a);
        assertEquals(n, n_a);
    }

    @Test
    void booleanToByteArrayAndFromByteArrayAreInversesTest() {
        byte[] t_b = cm.booleanToByteArray(true);
        byte[] f_b = cm.booleanToByteArray(false);
        assertEquals(1, t_b.length);
        assertEquals(1, f_b.length);
        assertTrue( cm.booleanFromByte(t_b[0]));
        assertFalse(cm.booleanFromByte(f_b[0]));
    }

    @Test
    void threeBytesToIntTest() {
        byte[] i_b = new byte[] {0, 0, 0};
        byte[] j_b = new byte[] {0, 0, 1};
        byte[] k_b = new byte[] {-128, -128, -128};
        byte[] l_b = new byte[] {127, 127, 127};
        byte[] m_b = new byte[] {6, 0, 93};
        byte[] m_offset_front_b = new byte[] {23, 124, 6, 0, 93};
        byte[] m_offset_back_b = new byte[] {6, 0, 93, 93, 12, 4, 0};
        byte[] m_offset_both_b = new byte[] {23, 44, 124, 7, 6, 0, 93, 93, 12, 4, 0};
        assertEquals(0,       cm.threeBytesToInt(i_b, 0));
        assertEquals(1,       cm.threeBytesToInt(j_b, 0));
        assertEquals(8421504, cm.threeBytesToInt(k_b, 0));
        assertEquals(8355711, cm.threeBytesToInt(l_b, 0));
        assertEquals(393309,  cm.threeBytesToInt(m_b, 0));
        assertEquals(393309,  cm.threeBytesToInt(m_offset_front_b, 2));
        assertEquals(393309,  cm.threeBytesToInt(m_offset_back_b, 0));
        assertEquals(393309,  cm.threeBytesToInt(m_offset_both_b, 4));
    }

    @Test
    void memCpyOneByteTest() {
        byte[] src  = new byte[] {3, 5, 1, -8, 0, 3};
        byte[] dest = new byte[] {5, 6, 4, 3, 3, 0};
        for(int dest_offset = 0; dest_offset < dest.length; dest_offset++) {
            for(int src_offset = 0; src_offset < src.length; src_offset++) {
                cm.memCpy(dest, src, (short) dest_offset, (short) src_offset, (short) 1);
                assertEquals(dest[dest_offset], src[src_offset]);
            }
        }
    }

    @Test
    void memCpyAllLengthsTest() {
        byte[] src  = new byte[] {3, 5, 1, -8, 0, 3};
        byte[] dest = new byte[] {5, 6, 4, 3, 3, 0};
        for (int length = 0; length < src.length; length++) {
            for(int dest_offset = 0; dest_offset < (dest.length - length); dest_offset++) {
                for(int src_offset = 0; src_offset < (src.length - length); src_offset++) {
                    cm.memCpy(dest, src, (short) dest_offset, (short) src_offset, (short) length);
                    for (int i = 0; i < length; i++) {
                        assertEquals(dest[dest_offset+i], src[src_offset+i]);
                    }
                }
            }
        }
    }

    @Test
    void clearBufTest() {
        byte[] b_orig  = new byte[] {3, 5, 1, -8, 0, 3, Byte.MAX_VALUE, Byte.MIN_VALUE};
        byte[] b  = new byte[] {3, 5, 1, -8, 0, 3, Byte.MAX_VALUE, Byte.MIN_VALUE};
        cm.clearBuf(b, 0);
        assertArrayEquals(b_orig, b);
        for (int i = 0; i < b_orig.length; i++) {
            cm.clearBuf(b, i);
            for (int j = 0; j < i; j++) {
                assertEquals(0, b[j]);
            }
        }
    }

    @Test
    void putAndGetShortTest() {
        byte[] b  = new byte[8];
        cm.putShort(b, Short.MIN_VALUE, 0);
        cm.putShort(b, (short) 0, 2);
        cm.putShort(b, Short.MAX_VALUE, 6);
        cm.putShort(b, (short) 13, 4);
        short s = cm.getShort(b, 0);
        short t = cm.getShort(b, 2);
        short v = cm.getShort(b, 6);
        short u = cm.getShort(b, 4);
        assertEquals(Short.MIN_VALUE, s);
        assertEquals((short) 0, t);
        assertEquals(Short.MAX_VALUE, v);
        assertEquals((short) 13, u);
        cm.putShort(b, (short) 42, 1);
        cm.putShort(b, (short) 66, 5);
        short[] shorts = new short[7];
        for (int i = 0; i < 7; i++) {
            shorts[i] = cm.getShort(b, i);
        }
        short[] exp = new short[] {Short.MIN_VALUE, 42, 10752, 0, 0, 66, 17151};
        assertArrayEquals(exp, shorts);
    }

    @Test
    void putAndGetIntTest() {
        byte[] b  = new byte[16];
        cm.putInt(b, Integer.MIN_VALUE, 0);
        cm.putInt(b, 0, 4);
        cm.putInt(b, Integer.MAX_VALUE, 8);
        cm.putInt(b, 13, 12);
        int s = cm.getInt(b, 0);
        int t = cm.getInt(b, 4);
        int v = cm.getInt(b, 8);
        int u = cm.getInt(b, 12);
        assertEquals(Integer.MIN_VALUE, s);
        assertEquals(0, t);
        assertEquals(Integer.MAX_VALUE, v);
        assertEquals(13, u);
        cm.putInt(b, 2, 1);
        cm.putInt(b, -666666666, 7);
        int i = cm.getInt(b, 1);
        int j = cm.getInt(b, 7);
        assertEquals(2, i);
        assertEquals(-666666666, j);
    }
}
