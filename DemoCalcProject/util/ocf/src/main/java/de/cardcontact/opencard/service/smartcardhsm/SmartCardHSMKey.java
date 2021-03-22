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

package de.cardcontact.opencard.service.smartcardhsm;

import java.util.ArrayList;

import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.HexString;
import de.cardcontact.tlv.TLV;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.Tag;
import opencard.opt.security.KeyRef;



/**
 * Reference to the private key on the SmartCardHSM
 *
 * @author lew
 *
 * @see opencard.opt.security.PrivateKeyRef
 *
 */
public class SmartCardHSMKey implements KeyRef {


	/**
	 *
	 */
	private static final long serialVersionUID = -464439997111473313L;



	public static final String RSA = "RSA";
	public static final String EC = "EC";
	public static final String AES = "AES";


	private final static Tag tagUseCounter = new Tag(16, Tag.CONTEXT, false);
	private final static Tag tagAlgorithms = new Tag(17, Tag.CONTEXT, false);
	private final static Tag tagKeyDomainId = new Tag(18, Tag.CONTEXT, false);


	private byte keyRef;				// The ID which refers to the key on the card.
	private String label;				// The key label (CKA_LABEL)
	private byte[] keyId;				// The key id (CKA_ID)
	private short keySize;				// The key size in bit
	private String algorithm;			// The key's JCE algorithm name
	private byte[] algorithms;			// The key's algorithm list from the HSM
	private int useCounter = -1;		// The key use counter
	private KeyDomain keyDomain;		// The associated key domain



	public SmartCardHSMKey(byte keyRef, String label, short keySize) {
		this(keyRef, label, keySize, RSA);
	}



	public SmartCardHSMKey(byte keyRef, String label, short keySize, String algorithm) {
		this.keyRef = keyRef;
		this.label = label;
		this.keySize = keySize;
		this.algorithm = algorithm;
	}



	@Override
	public String getAlgorithm() {
		return this.algorithm;
	}



	@Override
	public byte[] getEncoded() {
		return null;
	}



	@Override
	public String getFormat() {
		return null;
	}



	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}



	public byte getKeyRef() {
		return keyRef;
	}



	public void setKeyRef(byte keyRef) {
		this.keyRef = keyRef;
	}



	public String getLabel() {
		return label;
	}



	public void setLabel(String label) {
		this.label = label;
	}



	public byte[] getKeyId() {
		return keyId;
	}



	public void setKeyId(byte[] keyId) {
		this.keyId = keyId;
	}



	public short getKeySize() {
		return keySize;
	}



	public void setKeySize(short keySize) {
		this.keySize = keySize;
	}



	public void setAlgorithms(byte[] algorithms) {
		this.algorithms = algorithms;
	}



	public byte[] getAlgorithms() {
		return algorithms;
	}



	public int getUseCounter() {
		return useCounter;
	}



	public void setKeyDomain(KeyDomain keyDomain) {
		this.keyDomain = keyDomain;
	}



	public KeyDomain getKeyDomain() {
		return keyDomain;
	}



	/**
	 * Process the content of tag A5 returned in the SELECT command applied to a key FID
	 *
	 * @param a5 the encoded tag A5
	 */
	public void processKeyInfo(ArrayList<KeyDomain> keyDomains, byte[] a5) {
		try {
			ConstructedTLV a = new ConstructedTLV(a5);
			for (int i = 0; i < a.getElements(); i++) {
				TLV t = a.get(i);
				if (t.getTag().equals(tagUseCounter)) {
					byte[] val = t.getValue();
					useCounter = (val[0] & 0xFF) << 8;
					useCounter = (useCounter | (val[1] & 0xFF)) << 8;
					useCounter = (useCounter | (val[2] & 0xFF)) << 8;
					useCounter = useCounter | (val[3] & 0xFF);
				} else if (t.getTag().equals(tagAlgorithms)) {
					algorithms = t.getValue();
				} else if (t.getTag().equals(tagKeyDomainId)) {
					keyDomain = keyDomains.get(t.getValue()[0] & 0xFF);
				}
			}
		} catch (TLVEncodingException e) {
			// Ignore
		}
	}



	public String toString() {
		String str = "Label=" + label + ", KeyID=" + keyRef + ", Size=" + keySize + " bits";

		if (useCounter != -1) {
			str += ", UseCounter=" + useCounter;
		}

		if (algorithms != null) {
			str += ", Algorithms="+ HexString.hexifyByteArray(algorithms, ':');
		}

		if (keyDomain != null) {
			str += ", KeyDomain=" + keyDomain.getId();
		}
		return str;
	}
}
