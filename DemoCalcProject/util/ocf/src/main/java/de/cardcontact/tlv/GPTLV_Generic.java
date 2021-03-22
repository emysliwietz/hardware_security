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

package de.cardcontact.tlv;

import de.cardcontact.tlv.Tag;

/**
 * Abstract base class for EMV, DGI and L16 encoded TLV objects
 * 
 * @author Andreas Schwier (www.cardcontact.de)
 */
public abstract class GPTLV_Generic {

	public final static int INVALID_SIZE = -1;

	/**
	 * Tag of the TLV object
	 */
	protected int tag;

	/**
	 * Data block of the TLV object
	 */
	protected byte[] data;



	public GPTLV_Generic(int tag, byte[] data) {
		this.tag = tag;
		this.data = data;
	}



	/**
	 * Return the encoded length field of the TLV object
	 * @return Encoded length field
	 */
	public byte[] getL() {
		return encodeLength();
	}



	/**
	 * Return the encoded length and value field of the TLV object
	 * @return Encoded length and value field
	 */
	public byte[] getLV() {
		byte[] encodedLength = encodeLength();

		byte[] tmp = new byte[encodedLength.length + data.length];

		System.arraycopy(encodedLength, 0, tmp, 0, encodedLength.length);
		System.arraycopy(data, 0, tmp, encodedLength.length, data.length);

		return tmp;
	}



	/**
	 * Return the tag of the TLV object
	 * @return Tag
	 */
	public int getTag() {
		return tag;
	}



	/**
	 * Return the encoded TLV structure of the object
	 * @return TLV structure
	 */
	public byte[] getTLV() {

		byte[] encodedTag = encodeTag();
		byte[] encodedLength = encodeLength();

		byte[] tmp = new byte[encodedTag.length + encodedLength.length + data.length];

		System.arraycopy(encodedTag, 0, tmp, 0, encodedTag.length);
		System.arraycopy(encodedLength, 0, tmp, encodedTag.length,
				encodedLength.length);
		System.arraycopy(data, 0, tmp,
				encodedTag.length + encodedLength.length, data.length);

		return tmp;
	}



	/**
	 * Return the encoded tag and length field of the TLV object
	 * @return Encoded tag and length field
	 */
	public byte[] getTV() {
		byte[] encodedTag = encodeTag();

		byte[] tmp = new byte[encodedTag.length + data.length];

		System.arraycopy(encodedTag, 0, tmp, 0, encodedTag.length);
		System.arraycopy(data, 0, tmp, encodedTag.length, data.length);

		return tmp;
	}



	/**
	 * Return the value field of the TLV object
	 * @return Value field
	 */
	public byte[] getValue() {
		return data;
	}



	/**
	 * Helper function to determine bytes required to store the tag
	 * 
	 * @return Number of bytes required to store tag
	 */
	public abstract int getTagFieldSizeHelper();



	/**
	 * Encode tag field in byte array
	 * @return
	 */
	public abstract byte[] encodeTag();



	/**
	 * Helper function for getSize() and getLengthFieldSize()
	 * @return Size of length field in bytes
	 */
	public abstract int getLengthFieldSizeHelper();



	/**
	 * Encode length field in byte array
	 * @return Encoded length field
	 */
	public abstract byte[] encodeLength();
}
