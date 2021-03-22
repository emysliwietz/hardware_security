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

import java.io.UnsupportedEncodingException;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.SimpleTimeZone;



/**
 * Base class for all primitive TLV objects
 *
 * @author Andreas Schwier (info@cardcontact.de)
 */

public class PrimitiveTLV extends TLV {
	protected byte[] value = null;



	/**
	 * Create a primitive TLV object with tag and value
	 *
	 * @param newtag
	 * 		Tag as object
	 * @param newvalue
	 * 		Byte array containing value
	 */
	public PrimitiveTLV(Tag newtag, byte[] newvalue) {
		tag = newtag;
		value = newvalue;
	}



	/**
	 * Create a primitive TLV object with tag given as integer value
	 *
	 * @param newTagValue
	 * 		Tag as integer value
	 * @param newvalue
	 * 		Byte array containing value
	 * @throws TLVEncodingException
	 */
	public PrimitiveTLV(int newTagValue, byte[] newvalue) throws TLVEncodingException {
		tag = new Tag(newTagValue);
		value = newvalue;
	}



	/**
	 * Create a primitive TLV object from binary data in
	 * buffer at given offset
	 *
	 * @param buffer
	 * 		Buffer containing TLV object
	 * @param offset
	 * 		Offset in buffer
	 * @throws TLVEncodingException
	 */
	public PrimitiveTLV(byte[] buffer, int offset) throws TLVEncodingException {
		int length;

		tag = new Tag(buffer, offset);
		offset += tag.getSize();

		length = lengthFromByteArray(buffer, offset, alternateLengthFormat);
		offset += getLengthFieldSizeHelper(length, alternateLengthFormat);

		value = new byte[length];
		System.arraycopy(buffer, offset, value, 0, length);
	}



	/**
	 * Create a primitive TLV object or structure from binary
	 *
	 * @param buffer
	 * 		Binary data containing TLV structure
	 * @throws TLVEncodingException
	 */
	public PrimitiveTLV(byte[] buffer) throws TLVEncodingException {
		this(buffer, 0);
	}



	/**
	 * Create a primitive TLV object from binary in parse buffer
	 *
	 * @param pb
	 * 		Binary data containing TLV structure
	 * @throws TLVEncodingException
	 */
	public PrimitiveTLV(ParseBuffer pb) throws TLVEncodingException {
		int length;

		tag = new Tag(pb);

		if (alternateLengthFormat)
			length = pb.getDGILength();
		else
			length = pb.getDERLength();

		if (length > pb.remaining()) {
			throw new TLVEncodingException("Length field (" + length + ") exceeds value field (" + pb.remaining() + ").");
		}
		value = new byte[length];
		pb.get(value, 0, length);
	}



	/**
	 * Copy constructor
	 *
	 * Initialize with existing PrimitiveTLV object. Does not perform
	 * a deep copy. The tag and value are reassigned.
	 *
	 * Caution: If applied to a TLV object embedded in a complex structure
	 * remember to update the reference to this object in the parent node.
	 *
	 * @param tlv
	 * 		PrimitiveTLV
	 *
	 * @throws UnsupportedOperationException
	 *
	 */
	public PrimitiveTLV(TLV tlv) throws TLVEncodingException {
		super(tlv);
		if (!(tlv instanceof PrimitiveTLV))
			throw new UnsupportedOperationException("Can not clone from other than primitive TLV");

		value = ((PrimitiveTLV)tlv).value;
	}



	/**
	 * Store value in binary buffer
	 *
	 * @param buffer
	 * 		Byte array that received the binary data
	 * @param offset
	 * 		Offset in byte array
	 * @return
	 * 		New offset behind the stored object
	 */
	protected int valueToByteArray(byte[] buffer, int offset) {
		if (value != null) {
			System.arraycopy(value, 0, buffer, offset, value.length);
			offset += value.length;
		}
		return offset;
	}



	/**
	 * Store primitive object to binary buffer
	 *
	 * @param buffer
	 * 		Byte array that received the binary data
	 * @param offset
	 * 		Offset in byte array
	 * @return
	 * 		New offset behind the stored object
	 */
	protected int toByteArray(byte[] buffer, int offset) {
		int length = value == null ? 0 : value.length;

		offset = tag.toByteArray(buffer, offset);
		offset = lengthToByteArray(length, buffer, offset, alternateLengthFormat);
		if (value != null) {
			System.arraycopy(value, 0, buffer, offset, value.length);
			offset += value.length;
		}
		return offset;
	}



	/**
	 * Return length of value field
	 *
	 * @return
	 * 		Length in bytes
	 */
	public int getLength() {
		return (value == null) ? 0 : value.length;
	}



	/**
	 * Return the value
	 * @return
	 * 		Byte array containing the value
	 */
	public byte[] getValue() {
		return value;
	}



	/**
	 * Return value as date
	 *
	 * @return Date
	 * @throws UnsupportedEncodingException
	 */
	public Date getDate() throws UnsupportedEncodingException {
		Date date = null;
		boolean utc = false;

		String str = new String(value, "8859_1");
		String format;

		if (str.length() == 11) {
			format = "yyMMddHHmm";
		} else if (str.length() == 13) {
			format = "yyMMddHHmmss";
		} else {
			format = "yyyyMMddHHmmss";
		}

		if (str.length() > 14) {
			if ((str.charAt(14) == '.') || (str.charAt(14) == ',')) {
				format += ".SSS";
			}
		}

		if (str.endsWith("Z")) {
			utc = true;
		} else if ((str.charAt(str.length() - 5) == '-') || (str.charAt(str.length() - 5) == '+')) {
			format += "Z";
		}

		SimpleDateFormat formatter = new SimpleDateFormat(format);

		if (utc) {
			formatter.setTimeZone(new SimpleTimeZone(0,"Z"));
		}

		ParsePosition pp = new ParsePosition(0);
		date = formatter.parse(str, pp);
		if (date == null) {
			throw new UnsupportedEncodingException("Date " + str + " parse error at position " + pp.getErrorIndex());
		}

		return date;
	}



	/**
	 * Test for equality
	 *
	 * @param testtlv
	 * 		Object to test for
	 * @return
	 * 		True if object identifiers are equal
	 */
	public boolean equals(Object testtlv) {
		if (!(testtlv instanceof PrimitiveTLV))
			return false;

		return Arrays.equals(value, ((PrimitiveTLV)testtlv).value);
	}



	/**
	 * Return dump of primitive TLV object using a given left indentation
	 * @param indent
	 * 		Left indentation to be used
	 * @return
	 * 		String containing dump of primitive TLV object
	 */
	public String dump(int indent) {
		StringBuffer buffer = new StringBuffer(80);

		for (int i = 0; i < indent; i++) {
			buffer.append(' ');
		}
		if (name != null) {
			buffer.append(name);
			buffer.append(' ');
		}
		buffer.append(tag.toString());
		buffer.append(" SIZE( "+ value.length + " )");
		buffer.append('\n');
		buffer.append(HexString.dump(value, 0, value.length, 16, indent + 2));
		return buffer.toString();
	}



	/**
	 * Return Tag of TLV object as string
	 *
	 * @return
	 * 		String containing name of TLV object
	 */
	public String toString() {
		StringBuffer buffer = new StringBuffer(80);

		if (name != null) {
			buffer.append(name);
			buffer.append(' ');
		}

		buffer.append(tag.toString());
		if (tag.getClazz() == Tag.UNIVERSAL) {
			try	{
				switch(tag.getNumber()) {
				case Tag.UTF8String:
					buffer.append(" \"");
					buffer.append(new String(value, "UTF-8"));
					buffer.append('"');
					break;
				case Tag.PrintableString:
				case Tag.NumericString:
				case Tag.BMPString:
				case Tag.T61String:
				case Tag.GeneralString:
				case Tag.UniversalString:
				case Tag.UTCTime:
				case Tag.GeneralizedTime:
					buffer.append(" \"");
					buffer.append(new String(value, "8859_1"));
					buffer.append('"');
					break;
				default:
					buffer.append(' ');
					buffer.append(HexString.hexifyByteArray(value));
				}
			}
			catch(UnsupportedEncodingException e) {
				buffer.append(' ');
				buffer.append(HexString.hexifyByteArray(value));
			}
		} else {
			buffer.append(' ');
			buffer.append(HexString.hexifyByteArray(value));
		}

		return buffer.toString();
	}



	/**
	 * Return number of childs, of object is constructed
	 *
	 * @see de.cardcontact.tlv.TreeNode#getChildCount()
	 */
	public int getChildCount() {
		return 0;
	}



	/**
	 * Return true
	 * @see de.cardcontact.tlv.TreeNode#isLeaf()
	 */
	public boolean isLeaf() {
		return true;
	}



	/**
	 * Return parent - This we don't know
	 *
	 * @see de.cardcontact.tlv.TreeNode#getParent()
	 */
	public TreeNode getParent() {
		return null; // Not known
	}



	/**
	 * Return child at index - No childs for PrimitiveTLV
	 *
	 * @see de.cardcontact.tlv.TreeNode#getChildAt(int)
	 */
	public TreeNode getChildAt(int index) {
		return null; // Not supported
	}



	/**
	 * Return index of child - No childs for PrimitiveTLV
	 *
	 * @see de.cardcontact.tlv.TreeNode#getIndex(de.cardcontact.tlv.TreeNode)
	 */
	public int getIndex(TreeNode child) {
		return -1; // Not supported
	}
}
