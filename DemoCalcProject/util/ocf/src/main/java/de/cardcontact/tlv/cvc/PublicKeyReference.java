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

import java.util.Arrays;

public class PublicKeyReference {

	private byte[] pkr;

	public PublicKeyReference(String pkrstr) {
		if (pkrstr.length() < 8) {
			throw new IllegalArgumentException("Public Key Reference must be at least 8 byte long");
		}
		this.pkr = pkrstr.getBytes();
	}



	public PublicKeyReference(byte[] pkr) {
		if (pkr.length < 8) {
			throw new IllegalArgumentException("Public Key Reference must be at least 8 byte long");
		}
		this.pkr = pkr;
	}



	public String getCountryCode() {
		byte[] cc = new byte[2];
		System.arraycopy(pkr, 0, cc, 0, 2);
		return new String(cc);
	}



	public String getMnemonic() {
		int len = pkr.length - 7;
		byte[] mne = new byte[len];
		System.arraycopy(pkr, 2, mne, 0, len);
		return new String(mne);
	}



	public String getSequenceNo() {
		byte[] seq = new byte[5];
		System.arraycopy(pkr, pkr.length - 5, seq, 0, 5);
		return new String(seq);
	}



	public String getHolder() {
		int len = pkr.length - 5;
		byte[] hol = new byte[len];
		System.arraycopy(pkr, 0, hol, 0, len);
		return new String(hol);
	}



	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null) return false;
		if (!(o instanceof PublicKeyReference)) return false;

		PublicKeyReference ref = (PublicKeyReference)o;
		return Arrays.equals(this.pkr, ref.pkr);
	}



	public String toString() {
		return new String(pkr);
	}
}
