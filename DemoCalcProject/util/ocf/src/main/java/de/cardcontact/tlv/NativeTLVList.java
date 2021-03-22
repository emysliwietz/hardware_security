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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import de.cardcontact.tlv.ParseBuffer;
import de.cardcontact.tlv.TLVEncodingException;



/**
 * TLVList
 * 
 * @author lew
 */
public class NativeTLVList {

	private List<GPTLV_Generic> entries = new ArrayList<GPTLV_Generic>();


	/**
	 * Create a new TLVList
	 * 
	 * @param tlv
	 */
	public NativeTLVList(GPTLV_Generic tlv) {
		entries.add(tlv);
	}



	/**
	 * Create a new TLVList from a given
	 * EMV encoded byte array.
	 * 
	 * @param data The EMV encoded data
	 * @throws TLVEncodingException
	 * @throws TagSizeException
	 * @throws TLVDataSizeException
	 */
	public NativeTLVList(byte[] data) throws TLVEncodingException, TagSizeException, TLVDataSizeException {
		ParseBuffer pb = new ParseBuffer(data);

		while(pb.hasRemaining()) {
			int tag = pb.getTag();
			int length = pb.getDERLength();
			byte[] value = new byte[length];
			pb.get(value, 0, length);

			GPTLV_EMV emv = new GPTLV_EMV(tag, value);
			entries.add(emv);
		}
	}



	/**
	 * Get the element at the specified position
	 * @param i the position
	 * @return tlv entrie
	 */
	public GPTLV_Generic get(int i) {
		return entries.get(i);
	}



	/**
	 * The number of entries
	 * @return
	 */
	public int getLength() {
		return entries.size();
	}



	/**
	 * Get the TLV encoded byte array
	 * 	
	 * @return tlv byte array
	 */
	public byte[] getBytes() {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		for (GPTLV_Generic tlv : entries) {
			try {
				bos.write(tlv.getTLV());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return bos.toByteArray();
	}
}
