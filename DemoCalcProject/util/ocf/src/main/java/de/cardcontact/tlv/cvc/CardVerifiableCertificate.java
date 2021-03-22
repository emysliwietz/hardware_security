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

package de.cardcontact.tlv.cvc;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.IntegerTLV;
import de.cardcontact.tlv.ObjectIdentifier;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.Sequence;
import de.cardcontact.tlv.TLV;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.Tag;

public class CardVerifiableCertificate extends Certificate{

	final Logger log = LoggerFactory.getLogger(CardVerifiableCertificate.class);

	/** Authentication Template 67 */
	private final static Tag TAG_AT = new Tag(7, Tag.APPLICATION, true);

	/** CV Certificate 7F21 */
	private final static Tag TAG_CVC = new Tag(0x21, Tag.APPLICATION, true);

	/** CV Certificate 7F4E */
	private final static Tag TAG_BODY = new Tag(0x4E, Tag.APPLICATION, true);

	/** CAR 42 */
	private final static Tag TAG_CAR = new Tag(2, Tag.APPLICATION, false);

	/** CHR 5F20 */
	private final static Tag TAG_CHR = new Tag(0x20, Tag.APPLICATION, false);

	/** Public Key 7F49 */
	private final static Tag TAG_PUK = new Tag(0x49, Tag.APPLICATION, true);

	/** Public Key Algorithm 06 */
	private final static Tag TAG_PK_ALGORITHM = new Tag(Tag.OBJECT_IDENTIFIER, Tag.UNIVERSAL, false);

	/** Prime Modulus / Modulus 81 */
	private final static Tag TAG_PK_MODULUS = new Tag(1, Tag.CONTEXT, false);

	/** Public Exponent 82 */
	private final static Tag TAG_PK_EXPONENT = new Tag(2, Tag.CONTEXT, false);

	/** First coefficient 82 a*/
	private final static Tag TAG_PK_C_A = new Tag(2, Tag.CONTEXT, false);

	/** Second coefficient b 83 */
	private final static Tag TAG_PK_C_B = new Tag(3, Tag.CONTEXT, false);

	/** Base point G 84 */
	private final static Tag TAG_PK_BASE_POINT = new Tag(4, Tag.CONTEXT, false);

	/** Order of the base point 85 */
	private final static Tag TAG_PK_ORDER = new Tag(5, Tag.CONTEXT, false);

	/** Public point y 86 */
	private final static Tag TAG_PK_PUBLIC_P = new Tag(6, Tag.CONTEXT, false);

	/** Cofactor f 87 */
	private final static Tag TAG_PK_COFACTOR = new Tag(7, Tag.CONTEXT, false);

	/** Extensions 65 */
	private final static Tag TAG_EXTENSIONS = new Tag(5, Tag.APPLICATION, true);

	/** Extension 73 */
	private final static Tag TAG_EXTENSION = new Tag(19, Tag.APPLICATION, true);

	/** TA constants */
	private static final ObjectIdentifier ID_TA_ECDSA = new ObjectIdentifier("0.4.0.127.0.7.2.2.2.2");

	/** The encoded certificate */
	private byte[] bin;

	private ConstructedTLV tlv;

	private ConstructedTLV cvc;

	private ConstructedTLV body;

	private PrimitiveTLV signature;

	private PublicKey publicKey;

	private PrimitiveTLV outerCar;

	private PrimitiveTLV outerSignature;

	/** Domain Parameter*/
	private byte[] domainParam;



	public CardVerifiableCertificate(String type, byte[] certificate) throws CertificateException {

		super(type);

		this.bin = certificate;

		try {
			tlv = new ConstructedTLV(bin);

//			log.debug(tlv.dump(4));

//			System.out.println(tlv.dump());

			if (tlv.getTag().equals(TAG_AT)) {
				cvc = (ConstructedTLV)tlv.get(0);
				body = (ConstructedTLV)cvc.get(0);
				signature = (PrimitiveTLV)cvc.get(1);
				outerCar =  (PrimitiveTLV)tlv.get(1);
				outerSignature = (PrimitiveTLV)tlv.get(2);
			} else if (tlv.getTag().equals(TAG_CVC)) {
				cvc = tlv;
				body = (ConstructedTLV)cvc.get(0);
				signature = (PrimitiveTLV) cvc.get(1);
			} else {
				throw new CertificateException("This is not a Card Verifiable Certificate");
			}
		} catch (TLVEncodingException e) {
			log.error("Decoding CVC", e);
			throw new CertificateParsingException(e);
		}
	}



	public CardVerifiableCertificate(byte[] certificate) throws CertificateException {
		this("CVC", certificate);
	}



	/**
	 * Parsing the certificate and generate the public key
	 * @throws TLVEncodingException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 */
	private void extractPublicKey(String providerName) throws CertificateException, NoSuchProviderException {
		if (isECDSA(getPublicKeyOID())) {
			try {
				publicKey = getECPublicKey(providerName);
			} catch (TLVEncodingException e) {
				log.error("Extracting public key", e);
				throw new CertificateParsingException(e);
			}
		} else {
			publicKey = getRSAPublicKey(providerName);
		}
	}



	private boolean isECDSA(ObjectIdentifier oid) {
		int[] oidArray = oid.getObjectIdentifier();
		int[] ecdsa = ID_TA_ECDSA.getObjectIdentifier();
		for (int i = 0; i < ecdsa.length; i++) {
			if (oidArray[i] != ecdsa[i]) return false;
		}
		return true;
	}



	private ObjectIdentifier getPublicKeyOID() throws CertificateException {
		ConstructedTLV pdo = (ConstructedTLV) body.findTag(TAG_PUK, null);
		PrimitiveTLV oid = null;
		try {
			oid = (PrimitiveTLV) pdo.findTag(new Tag(Tag.OBJECT_IDENTIFIER), null);
		} catch (TLVEncodingException e) {
			log.error("TLV decoding", e);
		}
		if (oid == null) {
			log.debug("No OID found.");
			throw new CertificateException("No OID found.");
		}
		return new ObjectIdentifier(oid.getValue());
	}



	public byte[] getAlgorithm() throws TLVEncodingException {
		ConstructedTLV pk = getPublicKeyFromCertificate();
		byte[] alg = ((PrimitiveTLV)pk.get(0)).getValue();
		return alg;
	}



	public BigInteger getModulus() throws TLVEncodingException {
		ConstructedTLV pk = getPublicKeyFromCertificate();
		byte[]mod = ((PrimitiveTLV)pk.get(1)).getValue();
		BigInteger modulus = byteArrayToUnsignedBigInteger(mod);

		return modulus;
	}



	public BigInteger getExponent() throws TLVEncodingException {
		ConstructedTLV pk = getPublicKeyFromCertificate();
		PrimitiveTLV exp = (PrimitiveTLV)pk.get(2);
		BigInteger exponent = byteArrayToUnsignedBigInteger(exp.getValue());

		return exponent;
	}


	private ECPublicKeySpec getECPublicKeySpecFromDomain() throws TLVEncodingException {
		ConstructedTLV pk = getPublicKeyFromCertificate();
		ConstructedTLV domain = new ConstructedTLV(domainParam);

		byte[] prime;
		TLV tlv = pk.findTag(TAG_PK_MODULUS, null);
		if (tlv == null) {
			prime = domain.findTag(TAG_PK_MODULUS, null).getValue();
		} else {
			prime = tlv.getValue();
		}

		ECField field = new ECFieldFp(byteArrayToUnsignedBigInteger(prime));

		tlv = pk.findTag(TAG_PK_C_A, null);
		BigInteger a;
		if (tlv == null) {
			a = byteArrayToUnsignedBigInteger(domain.findTag(TAG_PK_C_A, null).getValue());
		} else {
			a = byteArrayToUnsignedBigInteger(tlv.getValue());
		}

		tlv = pk.findTag(TAG_PK_C_B, null);
		BigInteger b;
		if (tlv == null) {
			b = byteArrayToUnsignedBigInteger(domain.findTag(TAG_PK_C_B, null).getValue());
		} else {
			b = byteArrayToUnsignedBigInteger(tlv.getValue());
		}

		EllipticCurve curve = new EllipticCurve(field, a, b);

		tlv = pk.findTag(TAG_PK_BASE_POINT, null);
		byte[] basePoint;
		if (tlv == null) {
			basePoint = domain.findTag(TAG_PK_BASE_POINT, null).getValue();
		} else {
			basePoint = tlv.getValue();
		}

		ECPoint g = getECPoint(basePoint);

		tlv = pk.findTag(TAG_PK_ORDER, null);
		BigInteger n;
		if (tlv == null) {
			n = byteArrayToUnsignedBigInteger(domain.findTag(TAG_PK_ORDER, null).getValue());
		} else {
			n = byteArrayToUnsignedBigInteger(tlv.getValue());
		}

		tlv = pk.findTag(TAG_PK_COFACTOR, null);
		int h;
		if (tlv == null) {
			h = domain.findTag(TAG_PK_COFACTOR, null).getValue()[0];
		} else {
			h = tlv.getValue()[0];
		}

		ECParameterSpec params = new ECParameterSpec(curve, g, n, h);

		tlv = pk.findTag(TAG_PK_PUBLIC_P, null);
		byte[] publicPoint;
		if (tlv == null) {
			publicPoint = domain.findTag(TAG_PK_PUBLIC_P, null).getValue();
		} else {
			publicPoint = tlv.getValue();
		}

		ECPoint y = getECPoint(publicPoint);

		return new ECPublicKeySpec(y, params);
	}



	private ECPublicKeySpec getECPublicKeySpec() throws TLVEncodingException {
		ConstructedTLV pk = getPublicKeyFromCertificate();

		//First create ECParameterSpec
		byte[] prime = pk.findTag(TAG_PK_MODULUS, null).getValue();
		ECField field = new ECFieldFp(byteArrayToUnsignedBigInteger(prime));
		BigInteger a = byteArrayToUnsignedBigInteger(pk.findTag(TAG_PK_C_A, null).getValue());
		BigInteger b = byteArrayToUnsignedBigInteger(pk.findTag(TAG_PK_C_B, null).getValue());
		EllipticCurve curve = new EllipticCurve(field, a, b);

		byte[] basePoint = pk.findTag(TAG_PK_BASE_POINT, null).getValue();
		ECPoint g = getECPoint(basePoint);

		BigInteger n = byteArrayToUnsignedBigInteger(pk.findTag(TAG_PK_ORDER, null).getValue());
		int h = pk.findTag(TAG_PK_COFACTOR, null).getValue()[0];

		ECParameterSpec params = new ECParameterSpec(curve, g, n, h);

		byte[] publicPoint = pk.findTag(TAG_PK_PUBLIC_P, null).getValue();
		ECPoint y = getECPoint(publicPoint);

		return new ECPublicKeySpec(y, params);
	}



	private BigInteger byteArrayToUnsignedBigInteger(byte[] data) {
		byte[] absoluteValue = new byte[data.length + 1];
		System.arraycopy(data, 0, absoluteValue, 1, data.length);
		return new BigInteger(absoluteValue);
	}



	private ECPoint getECPoint(byte[] data) {
		int length = (data.length - 1) / 2;
		byte[] x = new byte[length];
		byte[] y = new byte[length];
		System.arraycopy(data, 1, x, 0, length);
		System.arraycopy(data, 1 + length, y, 0, length);
		ECPoint g = new ECPoint(byteArrayToUnsignedBigInteger(x), byteArrayToUnsignedBigInteger(y));
		return g;
	}



	private ConstructedTLV getPublicKeyFromCertificate() throws TLVEncodingException {
		ConstructedTLV pk = (ConstructedTLV)body.get(2);

		return pk;
	}



	@Override
	public byte[] getEncoded() {
		return this.bin;
	}



	private PublicKey getECPublicKey(String providerName) throws TLVEncodingException, NoSuchProviderException {
		PublicKey key = null;
		try {
			KeyFactory fact = null;

			if (providerName != null) {
				fact = KeyFactory.getInstance("EC", providerName);
			} else {
				fact = KeyFactory.getInstance("EC");
			}
			ECPublicKeySpec spec;
			if (domainParam != null) {
				spec = getECPublicKeySpecFromDomain();
			} else {
				spec = getECPublicKeySpec();
			}
			key = fact.generatePublic(spec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			log.error("Decoding public key", e);
		}
		return key;
	}



	private PublicKey getRSAPublicKey(String providerName) throws CertificateException {
		ConstructedTLV puk = (ConstructedTLV) body.findTag(TAG_PUK, null);

		if (puk == null) {
			throw new CertificateException("Certificate doesn't contain a public key object.");
		}

		byte[]mod = ((PrimitiveTLV)puk.findTag(TAG_PK_MODULUS, null)).getValue();
		BigInteger modulus = byteArrayToUnsignedBigInteger(mod);

		PrimitiveTLV exp = (PrimitiveTLV)puk.findTag(TAG_PK_EXPONENT, null);
		BigInteger exponent = byteArrayToUnsignedBigInteger(exp.getValue());
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
		PublicKey key = null;
		try {
			KeyFactory fact = null;

			if (providerName != null) {
				fact = KeyFactory.getInstance("RSA", providerName);
			} else {
				fact = KeyFactory.getInstance("RSA");
			}
			key = fact.generatePublic(spec);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
			log.error("Decoding RSA key", e);
		}
		return key;
	}



	public PublicKey getPublicKey(byte[] domainParam) {
		this.domainParam = domainParam;
		try {
			extractPublicKey(null);
		} catch (CertificateException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return publicKey;
	}



	public PublicKey getPublicKey(String providerName) {
		try {
			extractPublicKey(providerName);
		} catch (CertificateException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return publicKey;
	}



	@Override
	public PublicKey getPublicKey() {
		try {
			extractPublicKey(null);
		} catch (CertificateException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return publicKey;
	}



	/**
	 * Set the following domain parameter:
	 * <ul>
	 * 	<li>Prime modulus</li>
	 * 	<li>First coefficient a</li>
	 * 	<li>Second coefficient b</li>
	 * 	<li>Base point G</li>
	 * 	<li>Order of the base point</li>
	 * 	<li>Cofactor f</li>
	 * </ul>
	 * Other domain parameter will be ignored
	 * @param param The domain parameter TLV encoded
	 */
	public void setDomainParameter(byte[] param) {
		ConstructedTLV tlv = null;
		try {
			tlv = new ConstructedTLV(param);
		} catch (TLVEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		ConstructedTLV publicKey = (ConstructedTLV)body.findTag(TAG_PUK, null);
		publicKey.add(tlv.findTag(TAG_PK_MODULUS, null));
		publicKey.add(tlv.findTag(TAG_PK_C_A, null));
		publicKey.add(tlv.findTag(TAG_PK_C_B, null));
		publicKey.add(tlv.findTag(TAG_PK_BASE_POINT, null));
		publicKey.add(tlv.findTag(TAG_PK_ORDER, null));
		publicKey.add(tlv.findTag(TAG_PK_COFACTOR, null));
	}



	/**
	 *
	 * @return The domain parameter
	 */
	public byte[] getDomainParameter() {
		ConstructedTLV publicKey = (ConstructedTLV)body.findTag(TAG_PUK, null);

		return publicKey.getBytes();
	}



	@Override
	public String toString() {
		return tlv.dump();
	}



	/**
	 *
	 * @return The Certification Authority Reference
	 */
	public byte[] getCAR() {
		PrimitiveTLV car = (PrimitiveTLV) this.body.findTag(TAG_CAR, null);
		return car.getValue();
	}



	/**
	 *
	 * @return the Outer Certification Authority Reference
	 */
	public byte[] getOuterCAR() {
		if (outerCar != null) {
			return outerCar.getValue();
		}
		return null;
	}



	/**
	 *
	 * @return the TLV encoded Outer Certification Authority Reference
	 * @throws CertificateException if the certificate has no Outer Certification Authority Reference
	 */
	public byte[] getOuterCARTLV() throws CertificateException {
		if (outerCar != null) {
			return outerCar.getBytes();
		}
		throw new CertificateException("Certificate has no Outer Cerification Authority Reference");
	}



	/**
	 *
	 * @return The Certificate Holder Reference
	 */
	public byte[] getCHR() {
		PrimitiveTLV chr = (PrimitiveTLV) this.body.findTag(TAG_CHR, null);
		return chr.getValue();
	}



	private byte[] getDataTBS() {
		if (this.outerCar != null) {
			byte[] cvcb = this.cvc.getBytes();
			byte[] outerCarb = this.outerCar.getBytes();
			byte[] tbs = new byte[cvcb.length + outerCarb.length];
			System.arraycopy(cvcb, 0, tbs, 0, cvcb.length);
			System.arraycopy(outerCarb, 0, tbs, cvcb.length, outerCarb.length);
			return tbs;
		} else {
			return this.body.getBytes();
		}
	}



	public TLV getExtension(ObjectIdentifier extid) {
		ConstructedTLV exts = (ConstructedTLV) this.body.findTag(TAG_EXTENSIONS, null);
		if (exts == null) {
			return null;
		}
		for (int i = 0; i < exts.getChildCount(); i++) {
			ConstructedTLV ext = (ConstructedTLV) exts.get(i);
			PrimitiveTLV oid = (PrimitiveTLV)ext.get(0);
			if (extid.equals(oid)) {
				return ext.get(1);
			}
		}

		return null;
	}



	@Override
	public void verify(PublicKey puk) throws CertificateException,
	NoSuchAlgorithmException, InvalidKeyException,
	NoSuchProviderException, SignatureException {
		verify(puk, (String)null);
	}



	@Override
	public void verify(PublicKey puk, String providerName)
			throws CertificateException, NoSuchAlgorithmException,
			InvalidKeyException, NoSuchProviderException, SignatureException {

		Signature verifier;

		if (providerName == null) {
			verifier = Signature.getInstance("SHA256withECDSA");
		} else {
			verifier = Signature.getInstance("SHA256withECDSA", providerName);
		}

		verifier.initVerify(puk);
		verifier.update(getDataTBS());

		byte[] wrappedSignature;
		if (this.outerSignature == null) {
			wrappedSignature = CardVerifiableCertificate.wrapSignature(this.signature.getValue());
		} else {
			wrappedSignature = CardVerifiableCertificate.wrapSignature(this.outerSignature.getValue());
		}

		boolean verified = verifier.verify(wrappedSignature);

		if (!verified) throw new CertificateException("Certificate verification failed.");
	}



	public byte[] getBody() {
		return this.body.getBytes();
	}



	public byte[] getCVC() {
		return this.cvc.getBytes();
	}



	public byte[] getSignature() {
		return this.signature.getBytes();
	}



	public byte[] getOuterSignature() throws CertificateException {
		if (outerSignature != null) {
			return outerSignature.getBytes();
		}
		throw new CertificateException("Certificate has no Outer Signature");
	}



	/**
	 * Return the SubjectPublicKeyIdentifier, which is the SHA-1 hash of the encoded public key
	 *
	 * @return the 20 byte SubjectPublicKeyIdentifier
	 */
	public byte[] getSubjectPublicKeyIdentifier() {

		byte[] spki = null;
		try {
			byte[] hashinp = null;

			ConstructedTLV pk = getPublicKeyFromCertificate();

			if (isECDSA(getPublicKeyOID())) {
				hashinp = pk.findTag(TAG_PK_PUBLIC_P, null).getValue();
			} else {
				byte[] mod = ((PrimitiveTLV)pk.findTag(TAG_PK_MODULUS, null)).getValue();
				BigInteger modulus = byteArrayToUnsignedBigInteger(mod);

				byte[] exp = ((PrimitiveTLV)pk.findTag(TAG_PK_EXPONENT, null)).getValue();
				BigInteger exponent = byteArrayToUnsignedBigInteger(exp);

				Sequence seq = new Sequence();
				seq.add(new IntegerTLV(modulus));
				seq.add(new IntegerTLV(exponent));
				hashinp = seq.getBytes();
			}
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(hashinp, 0, hashinp.length);
			spki = md.digest();
		} catch (Exception e) {
			throw new RuntimeException("getSubjectPublicKeyIdentifier() failed", e);
		}
		return spki;
	}



	/**
	 * Wrap an ECDSA signature in the format r || s into a TLV encoding as defined by RFC 3279
	 *
	 * @param signature containing the concatenation of r and s as unsigned integer values
	 * @return ASN.1 SEQUENCE objects containing two signed integer r and s
	 * @throws TLVEncodingException
	 */
	public static byte[] wrapSignature(byte[] signature) {
		int length = signature.length / 2;

		byte ib[] = new byte[length];
		System.arraycopy(signature, 0, ib, 0, length);
		BigInteger r = new BigInteger(1, ib);

		System.arraycopy(signature, length, ib, 0, length);
		BigInteger s = new BigInteger(1, ib);

		Sequence sequence = new Sequence();
		sequence.add(new IntegerTLV(r));
		sequence.add(new IntegerTLV(s));

		return sequence.getBytes();
	}



	/**
	 * Unwrap a ECDSA signature from the TLV encoding according to RFC3279
	 * into the concatenation of the unsigned integer r and s
	 *
	 * @param signature TLV encoded signature
	 * @param keyLength
	 * @return concatenation of r and s
	 * @throws TLVEncodingException
	 */
	public static byte[] unwrapSignature(byte[] signature, int keyLength) throws TLVEncodingException {
		ConstructedTLV sequence = new ConstructedTLV(signature);

		byte[] r = sequence.get(0).getValue();
		byte[] s = sequence.get(1).getValue();

		byte[] wrapped = new byte[keyLength * 2];

		int len = r.length > keyLength ? keyLength : r.length;
		System.arraycopy(r, r.length - len, wrapped, keyLength - len, len);

		len = s.length > keyLength ? keyLength : s.length;
		System.arraycopy(s, s.length - len, wrapped, keyLength + keyLength - len, len);

		return wrapped;
	}
}
