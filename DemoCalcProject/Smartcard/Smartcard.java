package Smartcard;

import Auto.Auto;
import Interfaces.KeyWallet;
import Interfaces.Receivable;
import rsa.RSADecrypt;
import rsa.RSAEncrypt;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class Smartcard implements Receivable {
    private SmartcardCrypto sc;
    private Queue<byte[]> inputQueue = new LinkedList<byte[]>();
    public PublicKey dbPubSK;

    public Smartcard(byte[] cardID, byte[] cardCertificate) {
        sc = new SmartcardCrypto(cardID, cardCertificate);
    }

    public void send(Receivable receiver, Object... msgComponents){
        receiver.receive(prepareMessage(msgComponents));
    }

    public byte[] waitForInput(){
        while (inputQueue.isEmpty()){
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return inputQueue.remove();
    }

    public void insert(Auto auto){
        UUID nonceCard = sc.generateNonce();
        send(auto, sc.cardCertificate, nonceCard);
        byte[] msg2b = waitForInput();
        Object[] msg2o = processMessage(msg2b);
        PublicKey autoPubSK = (PublicKey) msg2o[0];
        byte[] autoID = (byte[]) msg2o[1];
        byte[] autoCertHashSign = (byte[]) msg2o[2];
        byte[] autoCertHash = sc.unsign(autoCertHashSign, dbPubSK);
        //TODO: create and validate hash
        UUID nonceCardResponse = (UUID) msg2o[3];
        if (nonceCard != nonceCardResponse){
            return; //Placeholder
        }
        byte[] nonceCardResponseHashSign = (byte[]) msg2o[4];
        byte[] nonceCardResponseHash = sc.unsign(nonceCardResponseHashSign, autoPubSK);
        //TODO: create and validate hash
        UUID nonceAuto = (UUID) msg2o[5];
        byte[] msg3tmp = prepareMessage(nonceAuto);
        byte[] nonceAutoHashSign = sc.signAndHash(msg3tmp);
        send(auto, nonceAuto, nonceAutoHashSign);
    }

    public byte[] prepareMessage(Object ... objects){
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(bos);
        oos.writeObject(objects);
        oos.flush();
        oos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }

    public Object[] processMessage(byte[] message){
        ByteArrayInputStream bis = new ByteArrayInputStream(message);
        Object o = null;
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            o = ois.readObject();
            ois.close();
            bis.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return (Object[]) o;
    }

    @Override
    public void receive(byte[] message) {
        inputQueue.add(message);
    }

    private class SmartcardCrypto{

        private byte[] cardID;
        private byte[] cardCertificate;
        private SmartCardWallet scw = new SmartCardWallet();

        public UUID generateNonce(){
            UUID nonce = UUID.randomUUID();
            return nonce;
        }

        public SmartcardCrypto(byte[] cardID, byte[] cardCertificate) {
            this.cardID = cardID;
            this.cardCertificate = cardCertificate;
        }

        public byte[] createHash(byte[] toHash){
            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance("SHA-512");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            }
            digest.update(toHash);
            byte[] messageDigest = digest.digest();
            BigInteger hash = new BigInteger(1, messageDigest);
            System.out.println(hash.toString(16));
            return messageDigest;
        }

        public byte[] signAndHash(byte[] message){
            return sign(createHash(message), scw.getPrivateKey());
        }

        public byte[] sign(byte[] message, PrivateKey privSK){
            return RSADecrypt.decrypt(message, privSK);
        }

        public byte[] unsign(byte[] signature, PublicKey pubSK){
            return RSAEncrypt.encrypt(pubSK, signature);
        }

        private class SmartCardWallet extends KeyWallet{

            private PrivateKey privk;
            private PublicKey pubk;

            @Override
            public void storePublicKey() {
                //TODO: Make sure only database is able to set key
            }

            @Override
            public void storePrivateKey() {
                //TODO: Make sure only database is able to set key
            }

            @Override
            public PublicKey getPublicKey() {
                return pubk;
            }

            @Override
            public PrivateKey getPrivateKey() {
                //TODO: Make sure only smartcard is able to retrieve key
                return privk;
            }
        }
    }


}