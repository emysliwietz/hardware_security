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

package de.cardcontact.opencard.service.isocard;

import opencard.opt.iso.fs.CardFileInfo;
import opencard.opt.util.TLV;
import opencard.opt.util.Tag;

/**
 * Parser to TLV-encoded file control information returned in SELECT APDU
 *
 * @author Andreas Schwier
 */
public class IsoFileControlInformation implements CardFileInfo {
	private static final Tag tagFCPUSED = new Tag(0x00, (byte)2, false);
	private static final Tag tagFCPSTRUCTURAL = new Tag(0x01, (byte)2, false);
	private static final Tag tagFCPFILETYPE = new Tag(0x02, (byte)2, false);
	private static final Tag tagFCPFID = new Tag(0x03, (byte)2, false);
	private static final Tag tagFCPPROPRIETARY = new Tag(0x05, (byte)2, false);

	byte[] fci = null;
	int filelength = -1;
	short fileid = -1;
	int filetype = 8;
	int recordsize = -1;
	byte[] proprietary = null;

	/**
	 *
	 */
	public IsoFileControlInformation() {
	}

	/**
	 * Create file control information from TLV coded byte array
	 *
	 * @param newfci File control information obtained from the card
	 */
	public IsoFileControlInformation(byte[] newfci) {
		fci = newfci;
		TLV fcp, cursor;

		try {
			fcp = new TLV(fci);
			cursor = null;
			while ((cursor = fcp.findTag(null, cursor)) != null) {
				if (cursor.tag().isConstructed()) {
					if (cursor.tag().equals(tagFCPPROPRIETARY)) {
						proprietary = cursor.toBinary();
					}
				} else if (cursor.tag().equals(tagFCPUSED)) {
					filelength = cursor.valueAsNumber();
				} else if (cursor.tag().equals(tagFCPFILETYPE)) {
					byte tb[] = cursor.valueAsByteArray();

					filetype = tb[0] & 0x07;
					if (tb.length >= 3) {
						recordsize = tb[2];
					}
					if (tb.length >= 4) {
						recordsize = (recordsize << 8) + tb[3];
					}
				} else if (cursor.tag().equals(tagFCPSTRUCTURAL)) {
					if (filelength == -1)
						filelength = cursor.valueAsNumber();
				} else if (cursor.tag().equals(tagFCPFID)) {
					fileid = (short)cursor.valueAsNumber();
				} else if (cursor.tag().equals(tagFCPPROPRIETARY)) {
					proprietary = cursor.valueAsByteArray();
				}
			}
		}
		catch(Exception e) {
			// Silently ignore problems decoding TLV structure
		}
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#getFileID()
	 */
	public short getFileID() {
		return fileid;
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#isDirectory()
	 */
	public boolean isDirectory() {
		return filetype == 0;
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#isTransparent()
	 */
	public boolean isTransparent() {
		return filetype == 1;
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#isCyclic()
	 */
	public boolean isCyclic() {
		return (filetype & 6) == 6;
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#isVariable()
	 */
	public boolean isVariable() {
		return (filetype & 6) == 4;
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#getLength()
	 */
	public int getLength() {
		return filelength;
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#getRecordSize()
	 */
	public int getRecordSize() {
		return recordsize;
	}

	/* (non-Javadoc)
	 * @see opencard.opt.iso.fs.CardFileInfo#getHeader()
	 */
	public byte[] getHeader() {
		return fci;
	}

	/**
	 * Return proprietary data
	 */
	public byte[] getProprietary() {
		return proprietary;
	}
}
