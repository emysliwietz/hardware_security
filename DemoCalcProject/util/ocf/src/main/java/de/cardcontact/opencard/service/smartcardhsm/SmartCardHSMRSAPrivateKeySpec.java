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

import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.IntegerTLV;
import de.cardcontact.tlv.ObjectIdentifier;
import de.cardcontact.tlv.Tag;



/**
 * This class contains the data for RSA key pair generation.
 *
 * @author lew
 *
 */
public class SmartCardHSMRSAPrivateKeySpec extends SmartCardHSMPrivateKeySpec {

	public static final byte[] TA_RSA_V15_SHA_256 = new byte[] { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02 };

	private int exponent;
	private int modulusSize;



	/**
	 * SmartCardHSMRSAPrivateKeySpec constructor
	 *
	 * @param car The Certificate Authority Reference
	 * @param chr The Certificate Holder Reference
	 * @param exponent The private exponent
	 * @param size the key size in bits
	 */
	public SmartCardHSMRSAPrivateKeySpec(String car, String chr, int exponent, int size) {
		super(car, chr);
		this.algorithm = TA_RSA_V15_SHA_256;
		this.exponent = exponent;
		this.modulusSize = size;
	}



	/**
	 * SmartCardHSMRSAPrivateKeySpec constructor
	 *
	 * Using default public exponent 2^16+1 and CHR/CAR "UT-00000"
	 *
	 * @param size the key size in bits
	 */
	public SmartCardHSMRSAPrivateKeySpec(int size) {
		this("UT-00000", "UT-00000", 0x010001, size);
	}



	protected ConstructedTLV encodeKeyParams() {
		//Public Key
		ConstructedTLV puk = new ConstructedTLV(new Tag(0x49, Tag.APPLICATION, true));

		//Public Key Algorithm
		puk.add(new ObjectIdentifier(getAlgorithm()));

		//Public exponent
		IntegerTLV exp = new IntegerTLV(exponent);
		exp.setTag(new Tag(0x02, Tag.CONTEXT, false));
		puk.add(exp);

		//Key size
		puk.add(new IntegerTLV(modulusSize));

		return puk;
	}



	/**
	 * @return The size of the modulus
	 */
	public int getModulusSize() {
		return modulusSize;
	}



	/**
	 * Set public exponent
	 *
	 * @param exponent
	 */
	public void setExponent(int exponent) {
		this.exponent = exponent;
	}
}
