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
 * Class to represent a TLV encoded data object
 *
 * Follows the composite design pattern.
 *
 * @author Andreas Schwier (info@cardcontact.de)
 */
public abstract class TLV implements TreeNode {
	protected Tag tag = null;
	protected String name = null;
	protected boolean alternateLengthFormat = false;



	protected TLV() {
	}



	/**
	 * Copy constructor
	 *
	 * @param p
	 */
	protected TLV(TLV p) {
		tag = p.tag;
		name = p.name;
		alternateLengthFormat = p.alternateLengthFormat;
	}



	/**
	 * Store TLV object to binary buffer
	 *
	 * Abstract method must be overwritten
	 *
	 * @param buffer
	 * 		Byte array that received the binary data
	 * @param offset
	 * 		Offset in byte array
	 * @return
	 * 		New offset behind the stored object
	 */
	protected abstract int toByteArray(byte[] buffer, int offset);



	/**
	 * Store value to binary buffer
	 *
	 * Abtract method must be overwritten
	 *
	 * @param buffer
	 * 		Byte array that received the binary data
	 * @param offset
	 * 		Offset in byte array
	 * @return
	 * 		New offset behind the stored object
	 */
	protected abstract int valueToByteArray(byte[] buffer, int offset);



	/**
	 * Returns the value field
	 *
	 * @return the encoded TLV object
	 */
	public byte[] getValue() {
		byte[] buffer = new byte[getLength()];
		valueToByteArray(buffer, 0);
		return buffer;
	}



	/**
	 * Return binary presentation of TLV object
	 *
	 * @return
	 * 		Binary data containing TLV structure
	 */
	public byte[] getBytes() {
		byte[] buffer = new byte[getSize()];
		toByteArray(buffer, 0);
		return buffer;
	}



	/**
	 * Replace tag, e.g. for implicit encoding
	 *
	 * @param tag the new tag
	 */
	public void setTag(Tag tag) {
		this.tag = tag;
	}



	/**
	 * Returns the tag object
	 *
	 * @return the tag
	 */
	public Tag getTag() {
		return tag;
	}



	/**
	 * Return length of value field
	 *
	 * @return the length in bytes
	 */
	public abstract int getLength();


	/**
	 * Enable alternate encoding of length field.
	 *
	 * If enabled then the length field is encoded in 1 or
	 * 3 bytes. Length values in the range 0 - 254 are encoded
	 * in one byte. Length values in the range 255 - 65535 are
	 * encoded on 3 bytes with the first byte set to 0xFF
	 *
	 */
	public void useAlternateLengthEncoding() {
		alternateLengthFormat = true;
	}


	/**
	 * Return the size of the TLV object in bytes
	 *
	 * @return
	 * 		Size of TLV object in bytes
	 */
	public int getSize() {
		int size;

		size = getLength();
		size += getLengthFieldSizeHelper(size, alternateLengthFormat);
		size += tag.getSize();
		return size;
	}



	/**
	 * Return size of length field by calling overloaded
	 * getLength() and determining the number of bytes
	 * required to store the length in DER oder DGI coding
	 *
	 * @return length
	 */
	public int getLengthFieldSize() {
		return getLengthFieldSizeHelper(getLength(), alternateLengthFormat);
	}



	/**
	 * Helper function for getSize() and getLengthFieldSize()
	 *
	 * @param length
	 * @param altFormat
	 * @return
	 */
	protected static int getLengthFieldSizeHelper(int length, boolean altFormat) {
		int size = 1;

		if (!altFormat) {
			if (length >= 0x80)
				size++;
			if (length >= 0x100)
				size++;
			if (length >= 0x10000)
				size++;
			if (length >= 0x1000000)
				size++;
		} else {
			if (length >= 0xFF)
				size = 3;
		}
		return size;
	}



	/**
	 * Encode length field in byte array
	 *
	 * @param length
	 * 		Length to be encoded
	 * @param buffer
	 * 		Byte arrays to copy length into
	 * @param offset
	 * 		Offset in byte array to which length shall be stored
	 * @param altFormat
	 * 		True if DGI format shall be used
	 * @return
	 * 		New offset behind the length value
	 */
	protected static int lengthToByteArray(int length, byte[] buffer, int offset, boolean altFormat) {
		int size = getLengthFieldSizeHelper(length, altFormat);
		int i = 0;

		if (!altFormat) {
			if (size > 1) {
				buffer[offset++] = (byte)(0x80 | (size - 1));
				i = (size - 2) * 8;
			}
		} else {
			if (size > 1) {
				buffer[offset++] = (byte)0xFF;
				i = 8;
			}
		}

		for (; i >= 0; i -= 8) {
			buffer[offset++] = (byte)(length >> i);
		}

		return offset;
	}



	/**
	 * Return length field as byte array
	 *
	 * @param length Length to encode
	 * @param altFormat DER or DGI format
	 * @return Length field as byte array
	 */
	public static byte[] getLengthFieldAsByteArray(int length, boolean altFormat) {
		byte[] v = new byte[getLengthFieldSizeHelper(length, altFormat)];
		lengthToByteArray(length, v, 0, altFormat);
		return v;
	}



	/**
	 * Helper function to decode the length field
	 *
	 * @param buffer
	 * 			Binary buffer
	 * @param offset
	 * 			Offset in buffer
	 * @param altFormat
	 * 			User alternative length encoding (DGI)
	 * @return
	 * @throws TLVEncodingException
	 */
	protected static int lengthFromByteArray(byte[] buffer, int offset, boolean altFormat) throws TLVEncodingException {
		int length;
		int i = 1;

		if (!altFormat) {
			if ((buffer[offset] & 0x80) == 0x80) {
				i = buffer[offset] & 0x07;
				if (i > 3) {
					throw new TLVEncodingException("Length field exceeds 24 bits. Probably not a TLV encoding.");
				}
				offset++;
			}
		} else {
			if (buffer[offset] == (byte)0xFF) {
				i = 2;
				offset++;
			}
		}

		length = 0;
		for (; i > 0; i--) {
			length = (length << 8) | (buffer[offset++] & 0xFF);
		}

		return length;
	}



	/**
	 * Factory method to create proper TLV objects determined by their tag value
	 *
	 * @param pb
	 * 			ParseBuffer containing binary data
	 * @return
	 * 			Newly created TLV object
	 * @throws TLVEncodingException
	 *			Error decoding binary data into TLV structure
	 *
	 */
	public static TLV factory(ParseBuffer pb) throws TLVEncodingException {
		TLV newTLV = null;
		Tag newTag = null;

		// Remember position and try to decode a Tag. Reset to saved position afterwards.
		pb.mark();
		newTag = new Tag(pb);
		pb.reset();

		if (newTag.getClazz() == Tag.UNIVERSAL) {
			switch (newTag.getNumber()) {
			case Tag.SEQUENCE :
				newTLV = new Sequence(pb);
				break;
			case Tag.INTEGER :
				newTLV = new IntegerTLV(pb);
				break;
			case Tag.PrintableString :
				newTLV = new PrintableString(pb);
				break;
			case Tag.UTF8String :
				newTLV = new UTF8String(pb);
				break;
			case Tag.OCTET_STRING :
				if (!newTag.isConstructed()) {
					newTLV = new OctetString(pb);
				}
				break;
			case Tag.OBJECT_IDENTIFIER :
				newTLV = new ObjectIdentifier(pb);
				break;
			}
		}

		if (newTLV == null) {
			if (newTag.isConstructed()) {
				newTLV = new ConstructedTLV(pb);
			} else {
				newTLV = new PrimitiveTLV(pb);
			}
		}

		return newTLV;
	}



	/**
	 * Factory method to create proper TLV objects determined by their tag value
	 *
	 * @param buffer
	 * 			Buffer containing binary data
	 * @param offset
	 * 			Offset in buffer to start decoding
	 * @param length
	 * 			Maximum number of bytes to decode
	 * @return
	 * 			Newly created TLV object
	 * @throws TLVEncodingException
	 *			Error decoding binary data into TLV structure
	 *
	 */
	public static TLV factory(byte[] buffer, int offset, int length) throws TLVEncodingException {
		return factory(new ParseBuffer(buffer, offset, length));
	}



	/**
	 * Factory method to create proper TLV objects determined by their tag value
	 *
	 * @param buffer
	 * 			Buffer containing binary data
	 * @return
	 * 			Newly created TLV object
	 * @throws TLVEncodingException
	 *			Error decoding binary data into TLV structure
	 *
	 */
	public static TLV factory(byte[] buffer) throws TLVEncodingException {
		return factory(new ParseBuffer(buffer));
	}



	/**
	 * Return name assigned to TLV object or null
	 *
	 * @return Name of TLV object
	 */
	public String getName() {
		return name;
	}



	/**
	 * Assign a name to the TLV object
	 *
	 * @param name Name to assign
	 */
	public void setName(String name) {
		this.name = name;
	}



	/**
	 * Convert TLV object to string presentation using a given left indentation
	 *
	 * @param indent
	 * 			Left indentation
	 * @return
	 * 			String containing TLV object information
	 */
	public abstract String dump(int indent);



	/**
	 * Convert object indentifier to ASN.1 string syntax
	 *
	 * Used by subclasses to overwrite dump() when the output
	 * fit on a single line.
	 *
	 * @param indent
	 * 		Left indentation
	 * @return
	 * 		String containing the ASN.1 representation
	 */
	protected String dumpSingleLine(int indent) {
		StringBuffer buffer = new StringBuffer(80);
		int i;

		for (i = 0; i < indent; i++) {
			buffer.append(' ');
		}

		buffer.append(toString());
		buffer.append('\n');
		return buffer.toString();
	}



	/**
	 * Dump TLV object as string
	 *
	 * @return
	 * 		String containing dump of TLV object
	 */
	public String dump() {
		return dump(0);
	}



	/**
	 * Return Tag of TLV object as string
	 *
	 * @return
	 * 		String containing name of TLV object
	 */
	public String toString() {
		if (name == null)
			return tag.toString();
		else
			return name + " " + tag.toString();
	}
}
