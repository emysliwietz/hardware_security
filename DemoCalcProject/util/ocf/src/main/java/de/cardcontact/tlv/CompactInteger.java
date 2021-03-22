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
 * Support for compact integer storage format
 *  
 * @author Andreas Schwier (info@cardcontact.de)
 */
public class CompactInteger  {
	protected int value;
	protected int sizeof;

	public CompactInteger(int newValue) {
		if (newValue < 0) 
			throw new NumberFormatException("Negative compact integer");

		value = newValue;

		if (value < 0x80)
			sizeof = 1;
		else if (value < 0x4000)
			sizeof = 2;
		else if (value < 0x200000)
			sizeof = 3;
		else
			sizeof = 4;
	}


	public CompactInteger(byte[] bytes, int ofs) {
		byte t;

		value = 0;
		sizeof = 0;
		do	{
			t = bytes[ofs];
			value <<= 7;
			value |= t & 0x7F;
			ofs++;
			sizeof++;
		} while (((t & 0x80) == 0x80) && (sizeof < 4));

		if ((t & 0x80) == 0x80)
			throw new NumberFormatException("Compact integer too long");
	}


	public CompactInteger(byte[] bytes) {
		this(bytes, 0);
	}


	public int sizeOf() {
		return sizeof;
	}


	public int intValue() {
		return value;
	}


	public byte[] getBytes() {
		byte[] bytes = new byte[sizeof];
		int i = sizeof - 1;
		int v = value;

		bytes[i--] = (byte)(v & 0x7F);

		while (i >= 0) {
			v >>= 7;
			bytes[i--] = (byte)((v & 0x7F) | 0x80);
		}
		return bytes;
	}
}
