package rsa;

import Interfaces.ProtocolComponentLengths;
import javacard.security.PublicKey;
import javacard.security.RandomData;

import java.nio.ByteBuffer;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 */
public abstract class CryptoImplementation implements ProtocolComponentLengths {
    protected byte[] ID;
    protected byte[] certificate;
    protected RSACrypto rc;
    protected RandomData rd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM); //DEPRECATED: Change to KEYGENERATION?

    public short generateNonce() {
        byte[] bytes = new byte[NONCE_LEN];
        rd.generateData(bytes, (short) 0, NONCE_LEN); //CHANGE TO nextBytes in next version
        return (short) (((bytes[0] & 0xFF) << BYTE_BIT_LEN) | (bytes[1] & 0xFF));

    }

    public byte[] generateID() {
        //Could technically also use ALG_FAST, but performance improvement isn't worth having another
        //RandomData instance
        byte[] bytes = new byte[ID_LEN];
        rd.generateData(bytes, (short) 0, ID_LEN); //CHANGE TO nextBytes in next version
        return bytes;
    }

    public byte[] getID() {
        return ID;
    }

    /*public short generateNonceAsShort() {
        byte[] bytes = generateNonce();
        return (short)(((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF));
    }*/

    public boolean areSubsequentNonces(short a, short aPlus1) {
        return (aPlus1 == (short) (a + 1));
    }

    public boolean areSubsequentNonces(short a, short aPlusX, int x) {
        return (aPlusX == (short) (a + ((short) x)));
    }

    /*
        short s = Short.MAX_VALUE;
        short p = (short) (s + 1);
        System.out.println(s + 1 == p); // false
        System.out.println((short) (s + 1) == p); // true
     */

    public byte[] getCertificate() {
        return this.certificate;
    }


    /*public byte[] createHash(byte[] toHash){
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        digest.update(toHash);
        byte[] messageDigest = digest.digest();
        BigInteger hash = new BigInteger(1, messageDigest);
        return hash.toString(16).getBytes(StandardCharsets.UTF_8);
    }*/

    /*public byte[] hashAndSign(byte[] message){
        return sign(createHash(message));
    }*/

    public byte[] sign(byte[] message) {
        return rc.sign(message);
    }

    public boolean verify(ByteBuffer msgComponents, byte[] signature, PublicKey pubSK) {
        return rc.verify(msgComponents.array(), signature, pubSK);
    }

    public boolean verify(byte[] msgComponents, byte[] signature, PublicKey pubSK) {
        return rc.verify(msgComponents, signature, pubSK);
    }

}
