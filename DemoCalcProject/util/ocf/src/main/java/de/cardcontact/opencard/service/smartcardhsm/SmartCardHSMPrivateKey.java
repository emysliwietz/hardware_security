package de.cardcontact.opencard.service.smartcardhsm;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;

import opencard.opt.security.PrivateKeyRef;

public class SmartCardHSMPrivateKey extends SmartCardHSMKey implements PrivateKeyRef {

	/**
	 *
	 */
	private static final long serialVersionUID = -6946107286497965496L;



	public SmartCardHSMPrivateKey(byte keyRef, String label, short keySize, String algorithm) {
		super(keyRef, label, keySize, algorithm);
	}



	/**
	 * Derive the key size from the certificate's public key
	 *
	 * @param cert The corresponding certificate to this private key
	 */
	public void deriveKeySizeFromPublicKey(Certificate cert) {
		PublicKey pk = cert.getPublicKey();
		byte[] component;

		if (pk instanceof RSAPublicKey) {
			RSAPublicKey rsaPK = (RSAPublicKey)pk;
			component = rsaPK.getModulus().toByteArray();
		} else if (pk instanceof ECPublicKey) {
			ECPublicKey ecPK = (ECPublicKey)pk;
			ECPoint w = ecPK.getW();
			component = w.getAffineX().toByteArray();
		} else {
			return;
		}

		if (component[0] == 0) { // Remove sign bit
			setKeySize((short) ((component.length - 1) * 8));
		} else {
			setKeySize((short) (component.length * 8));
		}
	}
}
