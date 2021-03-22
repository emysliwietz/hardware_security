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
 * Class representing a tag that is part of a TLV structure.
 *
 * This implementation supports invalid encodings which are common in EMV and
 * ICAO specifications. Such tags encode a tag number in the range 0 to 30 in a two
 * byte tag (e.g. 9F02).
 *
 * @author Andreas Schwier (www.cardcontact.de)
 */
public class Tag {
	int tagNumber;							// The tag number (lower 5 bits)
	byte tagClass;							// The tag class (upper 2 bits)
	boolean constructed;					// The constructed indicator
	boolean invalidTagNumber = false;		// Two byte tag has tagNumber < 31

	public final static byte CONSTRUCTED = (byte)0x20;	// Constructed flag mask
	public final static byte CLASS		 = (byte)0xC0;	// Class mask
	public final static byte TAG	     = (byte)0x1F;	// Tagnumber mask

	public final static byte UNIVERSAL   = (byte)0x00;	// Universal class
	public final static byte APPLICATION = (byte)0x40;	// Application class
	public final static byte CONTEXT     = (byte)0x80;	// Context specific class
	public final static byte PRIVATE     = (byte)0xC0;	// Private class

	// Universal tags
	public final static int END_OF_CONTENTS = 0;
	public final static int BOOLEAN = 1;
	public final static int INTEGER = 2;
	public final static int BIT_STRING = 3;
	public final static int OCTET_STRING = 4;
	public final static int NULL = 5;
	public final static int OBJECT_IDENTIFIER = 6;
	public final static int OBJECT_DESCRIPTOR = 7;
	public final static int EXTERNAL_TYPE = 8;
	public final static int REAL = 9;
	public final static int ENUMERATED = 10;
	public final static int EMBEDDED_PDV = 11;
	public final static int UTF8String = 12;
	public final static int RELATIVE_OID = 13;
	public final static int SEQUENCE = 16;
	public final static int SET = 17;
	public final static int NumericString = 18;
	public final static int PrintableString = 19;
	public final static int T61String = 20;
	public final static int IA5String = 22;
	public final static int UTCTime = 23;
	public final static int GeneralizedTime = 24;
	public final static int GeneralString = 27;
	public final static int UniversalString = 28;
	public final static int BMPString = 30;

	public final static Tag TAG_INTEGER = new Tag(Tag.INTEGER, Tag.UNIVERSAL, false);
	public final static Tag TAG_BIT_STRING = new Tag(Tag.BIT_STRING, Tag.UNIVERSAL, false);
	public final static Tag TAG_OCTET_STRING = new Tag(Tag.OCTET_STRING, Tag.UNIVERSAL, false);
	public final static Tag TAG_OBJECT_IDENTIFIER = new Tag(Tag.OBJECT_IDENTIFIER, Tag.UNIVERSAL, false);
	public final static Tag TAG_SEQUENCE = new Tag(Tag.SEQUENCE, Tag.UNIVERSAL, true);
	public final static Tag TAG_UTF8String = new Tag(Tag.UTF8String, Tag.UNIVERSAL, false);
	public final static Tag TAG_PrintableString = new Tag(Tag.PrintableString, Tag.UNIVERSAL, false);



	final static String[] ClassText = {
		"UNIVERSAL",
		"APPLICATION",
		"CONTEXT",
		"PRIVATE" };

	final static String[] UniversalText = {
		"END-OF-CONTENTS",
		"BOOLEAN",
		"INTEGER",
		"BIT-STRING",
		"OCTET-STRING",
		"NULL",
		"OBJECT-IDENTIFIER",
		"OBJECT-DESCRIPTOR",
		"EXTERNAL-TYPE/INSTANCE-OF",
		"REAL",
		"ENUMERATED",
		"EMBEDDED-PDV",
		"UTF8-STRING",
		"RFU",
		"RFU",
		"RFU",
		"SEQUENCE",
		"SET",
		"NUMERIC-STRING",
		"PRINTABLE-STRING",
		"TELETEXT-STRING",
		"VIDEOTEXT-STRING",
		"IA5-STRING",
		"UTC",
		"GENERALIZED-TIME",
		"GRAPHIC-STRING",
		"VISIBLE-STRING",
		"GENERAL-STRING",
		"UNIVERSAL-STRING",
		"RFU",
		"BMP-STRING" };



	/**
	 * Create tag from given components
	 *
	 * @param newTag
	 * 		Tag number. Range 0 to 30 are single byte tags, Range 31 to 127
	 *      are double byte tags, Range 128 to 16383 are triple byte tags
	 * @param newClass
	 * 		Class of tag. Must be one of Tag.UNIVERSAL, Tag.APPLICATION,
	 *      Tag.CONTEXT oder Tag.PRIVATE
	 * @param newConstructed
	 * 		Boolean flag indicating if TLV object is contructed or primitive
	 */
	public Tag(int newTag, byte newClass, boolean newConstructed) {
		tagNumber = newTag;
		tagClass = newClass;
		constructed = newConstructed;
	}



	/**
	 * Create tag from binary presentation in ParseBuffer
	 *
	 * @param pb
	 * 		ParseBuffer
	 */
	public Tag(ParseBuffer pb) throws TLVEncodingException {
		byte temp;
		int i;

		temp = pb.get();

		tagClass = (byte)(temp & CLASS);

		constructed = ((temp & CONSTRUCTED) == CONSTRUCTED);

		tagNumber = temp & TAG;

		if (tagNumber == TAG) {
			tagNumber = 0;      // reset tag number

			i = 4;
			do	{
				temp = pb.get();
				tagNumber <<= 7;
				tagNumber |= (temp & 0x7F);
				i--;
			} while (((temp & 0x80) == 0x80) && (i > 0));
			invalidTagNumber = (tagNumber < 31);
		}
	}



	/**
	 * Create tag from binary presentation
	 *
	 * @param value
	 * 		Byte array containing binary tag
	 * @param offset
	 * 		Offset in byte array to look at
	 */
	public Tag(byte[] value, int offset) {
		byte temp;
		int i;

		temp = value[offset];

		tagClass = (byte)(temp & CLASS);

		constructed = ((temp & CONSTRUCTED) == CONSTRUCTED);

		tagNumber = temp & TAG;

		if (tagNumber == TAG) {
			tagNumber = 0;      // reset tag number
			offset++;

			i = 4;
			do	{
				temp = value[offset];
				tagNumber <<= 7;
				tagNumber |= (temp & 0x7F);
				offset++;
				i--;
			} while (((temp & 0x80) == 0x80) && (i > 0));
			invalidTagNumber = (tagNumber < 31);
		}
	}



	/**
	 * Create tag from binary presentation
	 *
	 * @param value
	 * 		Byte array containing binary tag
	 */
	public Tag(byte[] value) {
		this(value, 0);
	}



	/**
	 * Create tag from integer representation
	 *
	 * @param newTag
	 * 		Integer tag value (e.g. 0x5F32)
	 * @throws TLVEncodingException
	 */
	public Tag(int newTag) throws TLVEncodingException {
		int size, temp;

		if ((newTag >= 0x01000000) || (newTag < 0))
			size = 24;
		else if (newTag >= 0x010000)
			size = 16;
		else if (newTag >= 0x0100)
			size = 8;
		else
			size = 0;

		temp = newTag >> size;
			tagClass = (byte)(temp & CLASS);

			constructed = ((temp & CONSTRUCTED) == CONSTRUCTED);

			tagNumber = temp & TAG;

			if (tagNumber == TAG) {	// Multibyte tag found
				tagNumber = 0;

				do	{
					size -= 8;
					temp = (newTag >> size) & 0xFF;
					tagNumber <<= 7;
					tagNumber |= (temp & 0x7F);
				} while (size > 0);
				invalidTagNumber = (tagNumber < 31);
			} else {
				if (size > 0) {
					throw new TLVEncodingException("Multi-byte tag does not have all bits b5 to b1 set 1");
				}
			}
	}



	/**
	 * Test if Tags are equal
	 *
	 */
	public boolean equals(Object object) {
		if (!(object instanceof Tag))
			return false;

		Tag t = (Tag)object;

		if ((tagNumber != t.tagNumber) ||
				(tagClass != t.tagClass) ||
				(constructed != t.constructed) ||
				(invalidTagNumber != t.invalidTagNumber))
			return false;
		return true;
	}



	/**
	 * Test if Tag has constructed flag set
	 *
	 * @return
	 * 		true if constructed
	 */
	public boolean isConstructed() {
		return constructed;
	}



	/**
	 * Tag number getter
	 *
	 * @return
	 * 		tag number
	 */
	public int getNumber() {
		return tagNumber;
	}



	/**
	 * Tag class getter
	 *
	 * @return
	 * 		class number
	 */
	public byte getClazz() {
		return tagClass;
	}



	/**
	 * Fill byte array at given position with binary representation
	 * of tag and return new offset.
	 *
	 * @param buffer
	 * 		Byte arrays to receive binary tag
	 * @param offset
	 * 		Offset in byte array that receives the bytes
	 * @return
	 * 		New offset after storing the tag
	 */
	public int toByteArray(byte[] buffer, int offset) {
		int i = 0;

		buffer[offset] = tagClass;

		if (constructed)
			buffer[offset] |= CONSTRUCTED;

		/* serialize a one byte tag */
		if ((tagNumber < 0x1F) && !invalidTagNumber) {
			buffer[offset] |= (byte)tagNumber;
			offset++;
		}
		/* serialize multi tag */
		else {
			buffer[offset] |= (byte) 0x1F;
			offset++;

			for (i = (getSize() - 2) * 7; i > 0; i -= 7) {
				buffer[offset] = (byte) ( 0x80 | (( tagNumber >> i) & 0x7f));
				offset++;
			}

			buffer[offset] = (byte) (tagNumber & 0x7f);
			offset++;
		}

		return offset;
	}



	/**
	 * Get byte array containing binary representation of tag
	 *
	 * @return
	 * 		Binary data for tag
	 */
	public byte[] getBytes() {
		byte[] buffer = new byte[getSize()];

		toByteArray(buffer, 0);

		return buffer;
	}



	/**
	 * Get size of tag in number of bytes
	 *
	 * @return
	 * 		Number of bytes
	 */
	public int getSize()  {
		if      ((tagNumber < 0x1F) && !invalidTagNumber)	return 1;
		else if (tagNumber < 0x80)							return 2;
		else if (tagNumber < 0x4000)						return 3;
		else if (tagNumber < 0x200000)						return 4;
		return 5;
	}



	/**
	 * Dump tag to string
	 *
	 */
	public String toString() {
		if ((tagClass == UNIVERSAL) && (tagNumber < 0x1F)) {
			return(UniversalText[tagNumber] + (constructed && (tagNumber != SEQUENCE) && (tagNumber != SET) ? "*" : ""));
		} else {
			String tagStr = HexString.hexifyByteArray(getBytes());
			return(tagStr + " [ " + ClassText[(tagClass >> 6) & 3] + " " + tagNumber + (constructed ? " ] IMPLICIT SEQUENCE" : " ]"));
		}
	}
}
