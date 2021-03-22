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

import java.security.spec.KeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.Sequence;
import de.cardcontact.tlv.Tag;

/**
 * Base class for all key specifications
 *
 * @author asc
 *
 */
public abstract class SmartCardHSMKeySpec implements KeySpec {

	Logger logger = LoggerFactory.getLogger(SmartCardHSMKeySpec.class);

	private long keyUseCounter = -1;
	private byte[] algorithmList;
	private KeyDomain keyDomain = null;



	public boolean hasKeyUseCounter() {
		return this.keyUseCounter != -1;
	}



	public void setKeyUseCounter(int counter) {
		this.keyUseCounter = counter;
	}



	public long getKeyUseCounter() {
		return this.keyUseCounter;
	}



	public boolean hasAlgorithmList() {
		return this.algorithmList != null;
	}



	public void setAlgorithmList(byte[] list) {
		this.algorithmList = list;
	}



	public byte[] getAlgorithmList() {
		return this.algorithmList;
	}



	public boolean hasKeyDomain() {
		return this.keyDomain != null;
	}



	public void setKeyDomain(KeyDomain keyDomain) {
		this.keyDomain = keyDomain;
	}



	public KeyDomain getKeyDomain() {
		return this.keyDomain;
	}



	/**
	 * Encode key specification for asymmetric keys
	 *
	 * Overwritten in derived classes
	 *
	 * @param cdata the TLV structure to which objects are added
	 */
	protected void encodeSpecParams(Sequence cdata) {
		// Overwrite in derived classes
	}



	/**
	 * Encode key parameter
	 *
	 * @param cdata the TLV structure to which objects are added
	 */
	protected void encodeKeyParams(Sequence cdata) {
		if (hasKeyUseCounter()) {
			byte[] bytes = new byte[4];
			bytes[0] = (byte)((this.keyUseCounter & 0xFF000000) >> 24);
			bytes[1] = (byte)((this.keyUseCounter & 0x00FF0000) >> 16);
			bytes[2] = (byte)((this.keyUseCounter & 0x0000FF00) >> 8);
			bytes[3] = (byte) (this.keyUseCounter & 0x000000FF);

			cdata.add(new PrimitiveTLV(new Tag(0x10, Tag.CONTEXT, false), bytes));
		}

		if (hasAlgorithmList()) {
			cdata.add(new PrimitiveTLV(new Tag(0x11, Tag.CONTEXT, false), getAlgorithmList()));
		}

		if (hasKeyDomain()) {
			cdata.add(new PrimitiveTLV(new Tag(0x12, Tag.CONTEXT, false), new byte[] { getKeyDomain().getId() } ));
		}
	}



	/**
	 * Return the encoded CDATA for GENERATE ASYMMETRIC KEY PAIR oder GENERATE KEY APDU
	 *
	 * @return the encoded TLV structure
	 */
	public byte[] getCData() {
		Sequence cdata = new Sequence();

		encodeSpecParams(cdata);
		encodeKeyParams(cdata);

		logger.debug(cdata.dump());
		return cdata.getValue();
	}
}
