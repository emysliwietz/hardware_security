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

/**
 * Class implementing EMV encoded TLV objects
 * 
 * @author Andreas Schwier (www.cardcontact.de)
 */
public class GPTLV_EMV extends GPTLV_Generic {

	public GPTLV_EMV(int tag, byte[] data) throws TagSizeException, TLVDataSizeException {
		super(tag, data);

		if (getLengthFieldSizeHelper() == GPTLV_Generic.INVALID_SIZE) {
			throw new TLVDataSizeException("Illegal data size! EMV supports only up to 4 byte length fields !");
		}		
	}



	@Override
	public int getLengthFieldSizeHelper() {
		int size = 1;

		if (data.length >= 0x80)
			size++;
		if (data.length >= 0x100)
			size++;
		if (data.length >= 0x10000)
			size++;
		if (data.length >= 0x1000000) {
			return GPTLV_Generic.INVALID_SIZE;
		}
		return size;
	}



	@Override
	public byte[] encodeLength() {
		int length = data.length;
		int size = getLengthFieldSizeHelper();
		int i = 0;
		byte[] encodedLength = new byte[size];
		int offset = 0;

		if (size > 1) {
			encodedLength[offset++] = (byte) (0x80 | (size - 1));
			i = (size - 2) * 8;
		}

		for (; i >= 0; i -= 8) {
			encodedLength[offset++] = (byte) (length >> i);
		}

		return encodedLength;
	}



	@Override
	public byte[] encodeTag() {
		byte[] t = new byte[getTagFieldSizeHelper()];
		int akku = tag;
		for (int i = t.length - 1; i >= 0; i--) {
			t[i] = (byte)(akku & 0xFF);
			akku >>= 8;
		}
		return t;
	}



	@Override
	public int getTagFieldSizeHelper() {
		if (tag >= 0x01000000)
			return 4;
		else if (tag >= 0x010000)
			return 3;
		else if (tag >= 0x0100)
			return 2;
		return 1;
	}
}
