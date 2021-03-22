/*
 * Copyright (c) 2016 CardContact Systems GmbH, Minden, Germany.
 *
 * Redistribution and use in source (source code) and binary (object code)
 * forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributed source code must retain the above copyright notice, this
 * list of conditions and the disclaimer below.
 * 2. Redistributed object code must reproduce the above copyright notice,
 * this list of conditions and the disclaimer below in the documentation
 * and/or other materials provided with the distribution.
 * 3. The name of CardContact may not be used to endorse or promote products derived
 * from this software or in any other form without specific prior written
 * permission from CardContact.
 * 4. Redistribution of any modified code must be labeled "Code derived from
 * the original OpenCard Framework".
 *
 * THIS SOFTWARE IS PROVIDED BY CardContact "AS IS" FREE OF CHARGE. CardContact SHALL NOT BE
 * LIABLE FOR INFRINGEMENTS OF THIRD PARTIES RIGHTS BASED ON THIS SOFTWARE.  ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  CardContact DOES NOT WARRANT THAT THE FUNCTIONS CONTAINED IN THIS
 * SOFTWARE WILL MEET THE USER'S REQUIREMENTS OR THAT THE OPERATION OF IT WILL
 * BE UNINTERRUPTED OR ERROR-FREE.  IN NO EVENT, UNLESS REQUIRED BY APPLICABLE
 * LAW, SHALL CardContact BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  ALSO, CardContact IS UNDER NO OBLIGATION
 * TO MAINTAIN, CORRECT, UPDATE, CHANGE, MODIFY, OR OTHERWISE SUPPORT THIS
 * SOFTWARE.
 */

package de.cardcontact.opencard.service.eac20;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.opencard.security.IsoCredentialStore;
import de.cardcontact.opencard.security.IsoSecureChannel;
import de.cardcontact.opencard.security.IsoSecureChannel.SSCPolicyEnum;
import de.cardcontact.opencard.security.IsoSecureChannelCredential;
import de.cardcontact.opencard.security.SecureChannel;
import de.cardcontact.opencard.security.SecureChannelCredential;
import de.cardcontact.opencard.service.CardServiceUnexpectedStatusWordException;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService;
import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.Tag;
import opencard.core.service.CardServiceException;
import opencard.core.terminal.CardTerminalException;
import opencard.opt.iso.fs.CardFilePath;
import opencard.opt.security.CredentialStore;



/**
 * Class implementing an EAC2.0 service.
 * At this time only the SmartCardHSMCardService is supported.
 *
 * @author lew
 *
 */
public class EAC20 {

	final Logger log = LoggerFactory.getLogger(EAC20.class);

	private SmartCardHSMCardService hsms;

	private ECPrivateKey prkCA;

	private ECPublicKey pukCA;

	private byte[] ephemeralPublicKeyIfd;

	private ECPublicKey devAuthPK;

	private SecretKey kenc;

	private SecretKey kmac;

	private IsoSecureChannel sc;

	private IsoSecureChannelCredential credential;

	private CredentialStore store;

	/**
	 * for SmartCardHSM
	 */
	private CardFilePath securityDomain = new CardFilePath("#E82B0601040181C31F0201");

	private byte[] protocol;



	/**
	 * Fixed ECParameterSpec for BrainpoolP256r1
	 */
	private static ECParameterSpec eCParameterSpecBrainpoolP256r1 = null;

	public static ECParameterSpec getECParameterSpecforBrainpoolP256r1() {
		if (eCParameterSpecBrainpoolP256r1 == null) {
			BigInteger prime = new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16);
			ECField field = new ECFieldFp(prime);
			BigInteger a, b;
			a = new BigInteger("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16);
			b = new BigInteger("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16);
			EllipticCurve curve = new EllipticCurve(field, a, b);

			BigInteger x = new BigInteger("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16);
			BigInteger y = new BigInteger("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16);
			ECPoint g = new ECPoint(x, y);
			BigInteger n = new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16);
			int h = 1;
			eCParameterSpecBrainpoolP256r1 = new ECParameterSpec(curve, g, n, h);
		}
		return eCParameterSpecBrainpoolP256r1;
	}



	/**
	 * @param hsms SmartCardHSMCardService
	 * @param devAuthPK device authentication public key
	 */
	public EAC20(SmartCardHSMCardService hsms, ECPublicKey devAuthPK) {
		this.hsms = hsms;
		this.devAuthPK = devAuthPK;
	}



	/**
	 * Perform chip authentication and establish a secure channel
	 *
	 * @return IsoSecureChannelCredential
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public SecureChannelCredential performChipAuthentication() throws CardServiceException, CardTerminalException {

		generateEphemeralCAKeyPair();

		protocol =  new byte[] {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02};
		try	{
			byte[] cdata = (new PrimitiveTLV(new Tag(0, Tag.CONTEXT, false), protocol)).getBytes();
			hsms.manageSE(cdata);
		}
		catch(CardServiceUnexpectedStatusWordException e) {
			if (e.getSW() != 0x6A80) {
				throw e;
			}
			protocol =  new byte[] {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x01};
			byte[] cdata = (new PrimitiveTLV(new Tag(0, Tag.CONTEXT, false), protocol)).getBytes();
			hsms.manageSE(cdata);
		}

		byte[] dadobin = doGeneralAuthenticate();

		ConstructedTLV dado = null;
		try {
			dado = new ConstructedTLV(dadobin);
		} catch (TLVEncodingException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		PrimitiveTLV nonceDO = (PrimitiveTLV) dado.get(0);
		PrimitiveTLV authTokenDO = (PrimitiveTLV) dado.get(1);

		byte[] nonce = nonceDO.getValue();
		byte[] authToken = authTokenDO.getValue();

		ECPoint q = devAuthPK.getW();
		ECParameterSpec ecParameterSpec = prkCA.getParams();
		ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(q, ecParameterSpec);

		Key otherKey = null;
		try {
			otherKey = KeyFactory.getInstance("EC").generatePublic(ecPublicKeySpec);
		} catch (GeneralSecurityException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		byte[] k = null;
		try {
			KeyAgreement ka = KeyAgreement.getInstance("ECDH");
			ka.init(prkCA);
			ka.doPhase(otherKey, true);
			k = ka.generateSecret();
		} catch (GeneralSecurityException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		kenc = deriveKey(protocol[protocol.length - 1], k, 1, nonce);
		kmac = deriveKey(protocol[protocol.length - 1], k, 2, nonce);

		if (!verifyAuthenticationToken(authToken)) {
			log.error("Authentication token failed verification");
			throw new CardServiceException("Authentication token failed");
		}

		sc = new IsoSecureChannel();
		sc.setEncKey(kenc);
		sc.setMacKey(kmac);
		if (protocol[protocol.length - 1] == 1) {
			sc.setMACSendSequenceCounter(new byte[8]);
		} else {
			sc.setMACSendSequenceCounter(new byte[16]);
			sc.setSendSequenceCounterPolicy(SSCPolicyEnum.SYNC_AND_ENCRYPT);
		}
		credential = new IsoSecureChannelCredential(SecureChannel.ALL, sc);
		store = new IsoCredentialStore();
		((IsoCredentialStore)store).setSecureChannelCredential(securityDomain, credential);

		return credential;
	}



	/**
	 * Generate ephemeral private and public CA keys.
	 */
	private void generateEphemeralCAKeyPair() {
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		try {
			keyGen.initialize(getECParameterSpecforBrainpoolP256r1());
		} catch (InvalidAlgorithmParameterException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}
		KeyPair kp = keyGen.generateKeyPair();

		prkCA = (ECPrivateKey) kp.getPrivate();
		pukCA = (ECPublicKey) kp.getPublic();
	}



	/**
	 * Build the authentication template consisting of
	 * the public point (qx, qy) of the public key. <br>
	 * In a previous step, the public key has to be generated with generateEphemeralCAKeyPair()
	 *
	 * @return dadobin, the authentication template from the card containing nonce and token
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	private byte[] doGeneralAuthenticate() throws CardTerminalException, CardServiceException {

		byte[] qx = unsignedBigIntegerToByteArray(pukCA.getW().getAffineX(), 256);
		byte[] qy = unsignedBigIntegerToByteArray(pukCA.getW().getAffineY(), 256);

		ephemeralPublicKeyIfd = new byte[(qx.length * 2) + 1];

		ephemeralPublicKeyIfd[0] = 0x04;
		System.arraycopy(qx, 0, ephemeralPublicKeyIfd, 1, qx.length);
		System.arraycopy(qy, 0, ephemeralPublicKeyIfd, 1 + qx.length, qy.length);


		byte[] authTemplate = null;
		try {
			ConstructedTLV dado = new ConstructedTLV(0x7C);
			PrimitiveTLV tmp = new PrimitiveTLV(0x80, ephemeralPublicKeyIfd);
			dado.add(tmp);

			authTemplate = dado.getBytes();
		} catch (TLVEncodingException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		return hsms.generalAuthenticate(authTemplate);
	}



	public SecureChannelCredential getCredential() {
		return credential;
	}



	/**
	 * Derive symmetric key from secret and nonce
	 *
	 * @param k
	 * @param counter
	 * @param nonce
	 * @return SecretKey
	 * @throws NoSuchAlgorithmException
	 */
	private SecretKey deriveKey(byte alg, byte[] k, int counter, byte[] nonce) {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			bos.write(k);
			bos.write(nonce);
		} catch (IOException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		bos.write(0);
		bos.write(0);
		bos.write(0);
		bos.write(counter);

		byte[] input = bos.toByteArray();

		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}
		digest.update(input);
		byte[] md = digest.digest();

		SecretKey key = null;
		if (alg == 1) {
			byte[] keyBin = new byte[24];
			System.arraycopy(md, 0, keyBin, 0, 16);
			System.arraycopy(md, 0, keyBin, 16, 8);

			DESedeKeySpec desedeKeySpec = null;
			try {
				desedeKeySpec = new DESedeKeySpec(keyBin);
			} catch (InvalidKeyException e) {
				log.error(e.getLocalizedMessage(), e);
				throw new RuntimeException(e);
			}

			SecretKeyFactory skf = null;
			try {
				skf = SecretKeyFactory.getInstance("DESede");
				key = skf.generateSecret(desedeKeySpec);
			} catch (GeneralSecurityException e) {
				log.error(e.getLocalizedMessage(), e);
				throw new RuntimeException(e);
			}
		} else {
			byte[] keyBin = new byte[16];
			System.arraycopy(md, 0, keyBin, 0, 16);
			key = new SecretKeySpec(keyBin, "AES");
		}

		return key;
	}



	/**
	 * Calculate and verify the authentication token over the public key received from
	 * the other side
	 * @param authToken the MAC over the authentication data
	 * @return true if the MAC is valid
	 */
	public boolean verifyAuthenticationToken(byte[] authToken) {
		byte[] at = null;

		byte[] t = encodePublicKey();

		try {
			Mac mac;
			if (((SecretKeySpec)kmac).getAlgorithm() == "AES") {
				mac = Mac.getInstance("AESCMAC");
			} else {
				mac = Mac.getInstance("ISO9797ALG3Mac");
			}
			mac.init(kmac);
			mac.update(t);
			at = mac.doFinal();
			if (at.length > 8) {
				byte[] stripped = new byte[8];
				System.arraycopy(at, 0, stripped, 0, 8);
				at = stripped;
			}
		} catch (GeneralSecurityException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		return Arrays.equals(at, authToken);
	}



	/**
	 * Encode public key to EAC 2.0 format
	 *
	 * @return the encoded public key
	 * @throws TLVEncodingException
	 */
	public byte[] encodePublicKey() {
		ConstructedTLV t = null;
		try {
			t = new ConstructedTLV(0x7F49);
			t.add(new PrimitiveTLV(0x06, protocol));
			t.add(new PrimitiveTLV(0x86, ephemeralPublicKeyIfd));
		} catch (TLVEncodingException e) {
			log.error(e.getLocalizedMessage(), e);
			throw new RuntimeException(e);
		}

		return t.getBytes();
	}



	/**
	 * Convert unsigned big integer into byte array, stripping of a
	 * leading 00 byte
	 *
	 * This conversion is required, because the Java BigInteger is a signed
	 * value, whereas the byte arrays containing key components are unsigned by default
	 *
	 * @param bi    BigInteger value to be converted
	 * @param size  Number of bits
	 * @return      Byte array containing unsigned integer value
	 */
	protected static byte[] unsignedBigIntegerToByteArray(BigInteger bi, int size) {
		byte[] s = bi.toByteArray();
		size = (size >> 3) + ((size & 0x7) == 0 ? 0 : 1);
		byte[] d = new byte[size];
		int od = size - s.length;
		int os = 0;
		if (od < 0) {  // Number is longer than expected
			if ((od < -1) || s[0] != 0) {   // If it is just a leading zero, then we cut it off
				throw new IllegalArgumentException("Size mismatch converting big integer to byte array");
			}
			os = -od;
			od = 0;
		}
		size = size - od;

		System.arraycopy(s, os, d, od, size);
		return d;
	}
}
