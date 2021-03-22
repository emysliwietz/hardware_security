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

import java.math.BigInteger;

import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.Sequence;
import de.cardcontact.tlv.Tag;



/**
 * This class contains data for key pair generation.
 *
 * @author lew
 *
 * @see java.security.spec.KeySpec
 */
public abstract class SmartCardHSMPrivateKeySpec extends SmartCardHSMKeySpec {

	byte[] algorithm;
	private String chr;
	private String car;
	private String outerCar;
	private boolean storePublicKey = true;



	/**
	 *
	 * @param car Certificate Authority Reference
	 * @param chr Certificate Holder Reference
	 * @param algorithm The key algorithm
	 */
	public SmartCardHSMPrivateKeySpec(String car, String chr) {
		setCAR(car);
		setCHR(chr);
	}



	public byte[] getCHR() {
		return chr.getBytes();
	}



	public void setCHR(String certificateHolderReference) {
		this.chr = certificateHolderReference;
	}



	public byte[] getAlgorithm() {
		return this.algorithm;
	}



	public void setAlgorithm(byte[] algorithm) {
		this.algorithm = algorithm;
	}



	public void setCAR(String car) {
		this.car = car;
	}



	public void setOuterCAR(String outerCar) {
		this.outerCar = outerCar;
	}



	public void setStorePublicKey(boolean storePublicKey) {
		this.storePublicKey = storePublicKey;
	}



	public boolean storePublicKey() {
		return storePublicKey;
	}



	protected abstract ConstructedTLV encodeKeyParams();



	protected void encodeSpecParams(Sequence cdata) {
		//CPI
		cdata.add(new PrimitiveTLV(new Tag(0x29, Tag.APPLICATION, false), new byte[] { 0x00 }));

		//CAR
		if (this.car != null) {
			cdata.add(new PrimitiveTLV(new Tag(0x02, Tag.APPLICATION, false), this.car.getBytes()));
		}

		cdata.add(encodeKeyParams());

		cdata.add(new PrimitiveTLV(new Tag(0x20, Tag.APPLICATION, false), getCHR()));

		//Outer Certificate Authority Reference for authentication signature if P2 != '00'
		if (this.outerCar != null) {
			cdata.add(new PrimitiveTLV(new Tag(0x02, Tag.APPLICATION, false), outerCar.getBytes()));
		}
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
