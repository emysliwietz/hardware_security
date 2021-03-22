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

import java.util.StringTokenizer;


/**
 * Class to implement TLV encoded Object Identifier according to ASN.1
 *
 * @author Andreas Schwier (info@cardcontact.de)
 */
public class ObjectIdentifier extends PrimitiveTLV {


	/**
	 * Create object identifier
	 * @param oid
	 * 		Integer array with identifier
	 */
	public ObjectIdentifier(int[] oid) {
		super(new Tag(Tag.OBJECT_IDENTIFIER, Tag.UNIVERSAL, false), null);
		fromIntArray(oid);
	}



	/**
	 * Create object identifier from binary presentation
	 *
	 * @param pb
	 * 		Buffer with binary presentation
	 */
	public ObjectIdentifier(ParseBuffer pb) throws TLVEncodingException {
		super(pb);
	}



	/**
	 * Create object identifier from binary presentation
	 *
	 * @param pb
	 * 		Buffer with binary presentation
	 */
	public ObjectIdentifier(byte[] value) {
		super(new Tag(Tag.OBJECT_IDENTIFIER, Tag.UNIVERSAL, false), value);
	}



	/**
	 * Create object identifier from string
	 *
	 * @param oid
	 * 		Dottet or blank separated object identifier
	 */
	public ObjectIdentifier(String oid) {
		super(new Tag(Tag.OBJECT_IDENTIFIER, Tag.UNIVERSAL, false), null);
		fromString(oid);
	}



	/**
	 * Create object identifier from base and extension
	 *
	 * @param baseoid
	 * 		Base object identifier
	 * @param extoid
	 * 		Extension added to base object identifier
	 */
	public ObjectIdentifier(int[] baseoid, int[] extoid) {
		super(new Tag(Tag.OBJECT_IDENTIFIER, Tag.UNIVERSAL, false), null);
		int[] oid = new int[baseoid.length + extoid.length];
		System.arraycopy(baseoid, 0, oid, 0, baseoid.length);
		System.arraycopy(extoid, 0, oid, baseoid.length, extoid.length);
		fromIntArray(oid);
	}



	/**
	 * Copy constructor to convert PrimitiveTLV to typed object
	 *
	 * Make sure, that the parent is updated with the new reference
	 *
	 * @param tlv the PrimitiveTLV object
	 */
	public ObjectIdentifier(TLV tlv) throws TLVEncodingException {
		super(tlv);
	}



	/**
	 * Check tag and convert - if needed - the PrimitiveTLV to a ObjectIdentifier
	 *
	 * @param tlv
	 * @param et et tag used in implicit encoding
	 * @throws TLVEncodingException
	 */
	public static ObjectIdentifier getInstance(TLV tlv, Tag et)  throws TLVEncodingException {
		if (!tlv.getTag().equals(et)) {
			throw new TLVEncodingException("Tag must be " + et);
		}
		if (tlv instanceof ObjectIdentifier) {
			return (ObjectIdentifier)tlv;
		}
		return new ObjectIdentifier(tlv);
	}



	/**
	 * Convert - if needed - the PrimitiveTLV to a ObjectIdentifier
	 *
	 * @param tlv
	 * @return
	 * @throws TLVEncodingException
	 */
	public static ObjectIdentifier getInstance(TLV tlv)  throws TLVEncodingException {
		return getInstance(tlv, Tag.TAG_OBJECT_IDENTIFIER);
	}



	/**
	 * Helper to create value field from array of object identifier elements
	 *
	 * @param oid
	 * 		Array containing object identifier elements
	 */
	protected void fromIntArray(int oid[]) {
		int i, j, size, val;

		if ((oid.length < 2) || (oid[0] < 0) || (oid[0] > 2) || (oid[1] < 0) || (oid[1] > 39))
			throw new IllegalArgumentException("Object identifier out of range");

		size = 1;

		for (i = 2; i < oid.length; i++) {
			val = oid[i];
			do	{
				size++;
				val >>= 7;
			} while (val > 0);
		}

		value = new byte[size];

		value[0] = (byte)(40 * oid[0] + oid[1]);

		j = 1;
		for (i = 2; i < oid.length; i++) {
			val = oid[i];
			size = -7;
			do	{
				size += 7;
				val >>= 7;
			} while (val > 0);

			val = oid[i];
			for (; size >= 0; size -= 7) {
				value[j++] = (byte)((val >> size) & 0x7F | 0x80);
			}
			value[j - 1] &= 0x7F;
		}
	}



	/**
	 * Helper to create byte array from string
	 *
	 * @param oid
	 */
	protected void fromString(String oid) {
		try {
			StringTokenizer sp = new StringTokenizer(oid, " .");

			int[] elements = new int[sp.countTokens()];
			int i = 0;

			while (sp.hasMoreTokens()) {

				String temp = sp.nextToken();

				elements[i++] = Integer.parseInt(temp);
			}

			// Call the helper function to create the actual byte buffer
			fromIntArray(elements);
		}
		catch(NumberFormatException nfe) {
			throw new IllegalArgumentException("Object identifier string is invalid");
		}
	}



	/**
	 * Return object identifier
	 *
	 * @return
	 * 		Object identifier as int[]
	 */
	public int[] getObjectIdentifier() {
		return convertBytesToOID(value);
	}



	/**
	 * Helper to convert binary data into list of object identifier components
	 *
	 * @param value Binary data
	 * @return Array of object identifiers
	 */
	public static int[] convertBytesToOID(byte[] value) {
		int i, j, size;

		if (value.length == 0) {
			return new int[0];
		}

		size = 2;
		for (i = 1; i < value.length; i++) {
			if ((value[i] & 0x80) != 0x80)
				size++;
		}

		int objectIdentifier[] = new int[size];
		objectIdentifier[0] = value[0] / 40;
		objectIdentifier[1] = value[0] % 40;
		j = 2;
		for (i = 1; i < value.length; i++) {
			objectIdentifier[j] = (objectIdentifier[j] << 7) | (value[i] & 0x7F);
			if ((value[i] & 0x80) != 0x80) {
				 j++;
			}
		}
		return objectIdentifier;
	}



	/**
	 * Convert list of object identifier into dotted string format
	 *
	 * @param oid Array of object identifier
	 *
	 * @return String in dotted format
	 */
	public static String getObjectIdentifierAsString(int[] oid) {
		StringBuffer buffer = new StringBuffer(80);

		buffer.append(oid[0]);

		for (int i = 1; i < oid.length; i++) {
			buffer.append("." + oid[i]);
		}
		return buffer.toString();
	}



	/**
	 * Convert object identifier to ASN.1 string syntax
	 *
	 * @param indent
	 * 		Left indentation
	 * @return
	 * 		String containing the ASN.1 representation
	 */
	public String dump(int indent) {
		return dumpSingleLine(indent);
	}



	/**
	 * Return object identifier as ASN.1 string
	 *
	 * @return
	 * 		String in ASN.1 notation
	 */
	public String toString() {
		StringBuffer buffer = new StringBuffer(80);

		if (name != null) {
			buffer.append(name);
			buffer.append(' ');
		}

		buffer.append("OBJECT IDENTIFIER = {");

		ObjectIdentifierRegistry reg = ObjectIdentifierRegistry.getInstance();
		String name = reg.getNameFor(value);

		if (name != null) {
			buffer.append(" " + name);
		} else {
			int oid[] = getObjectIdentifier();

			for (int i = 0; i < oid.length; i++) {
				buffer.append(" " + oid[i]);
			}
		}
		buffer.append(" }");

		return buffer.toString();
	}
}
