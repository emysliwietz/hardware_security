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

import javax.crypto.SecretKey;

import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.Sequence;
import de.cardcontact.tlv.Tag;

/**
 * Specification for secret keys
 *
 * @author asc
 */
public class SmartCardHSMSecretKeySpec extends SmartCardHSMKeySpec {

	private int keysize;
	private SmartCardHSMSecretKey wrappingKey = null;


	public SmartCardHSMSecretKeySpec(int keysize) {
		if ((keysize != 128) && (keysize != 192) && (keysize != 256)) {
			throw new IllegalArgumentException("Key size must be 128, 192 or 256");
		}
		this.keysize = keysize;
	}



	public void setWrappingKey(SecretKey wrappingKey) {
		this.wrappingKey = (SmartCardHSMSecretKey)wrappingKey;
	}



	protected void encodeKeyParams(Sequence cdata) {
		super.encodeKeyParams(cdata);
		if (this.wrappingKey != null) {
			cdata.add(new PrimitiveTLV(new Tag(0x13, Tag.CONTEXT, false), new byte[] { wrappingKey.getKeyRef() } ));
		}
	}



	public int getKeySize() {
		return keysize;
	}
}
