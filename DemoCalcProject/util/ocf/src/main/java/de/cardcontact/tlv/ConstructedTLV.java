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
import java.util.ArrayList;
import java.util.Iterator;


/**
 * Base class for all constructed TLV objects
 *
 * @author Andreas Schwier (info@cardcontact.de)
 */
public class ConstructedTLV extends TLV {
	protected ArrayList<TLV> childs = null;


	/**
	 * Create empty constructed tlv object with given Tag object
	 *
	 * @param newtag
	 * 		Tag for constructed TLV object
	 */
	public ConstructedTLV(Tag newtag) {
		tag = newtag;
		childs = new ArrayList<TLV>();
	}



	/**
	 * Create empty constructed tlv object and given Tag value
	 *
	 * @param tagValue
	 * 		Tag value for constructed TLV object
	 * @throws TLVEncodingException
	 */

	public ConstructedTLV(int tagValue) throws TLVEncodingException {
		tag = new Tag(tagValue);
		childs = new ArrayList<TLV>();
	}



	/**
	 * Create a constructed tlv object from binary data
	 *
	 * @param buffer
	 * 		Byte array containing TLV structure
	 * @param offset
	 * 		Offset to start from
	 * @throws TLVEncodingException
	 */
	private ConstructedTLV(byte[] buffer, int offset) throws TLVEncodingException {
		int length, limit;
		Tag subTag = null;

		childs = new ArrayList<TLV>();

		tag = new Tag(buffer, offset);
		offset += tag.getSize();

		length = lengthFromByteArray(buffer, offset, alternateLengthFormat);
		offset += getLengthFieldSizeHelper(length, alternateLengthFormat);

		limit = offset + length;

		while (offset < limit) {
			subTag = new Tag(buffer, offset);
			if (subTag.isConstructed()) {
				ConstructedTLV ct = new ConstructedTLV(buffer, offset);
				offset += ct.getSize();
				add(ct);
			} else {
				PrimitiveTLV pt = new PrimitiveTLV(buffer, offset);
				offset += pt.getSize();
				add(pt);
			}
		}
	}



	/**
	 * Create a constructed tlv object from binary data in ParseBuffer
	 *
	 * @param pb
	 * 		Byte array containing TLV structure
	 */
	public ConstructedTLV(ParseBuffer pb) throws TLVEncodingException {
		int length, limit;

		childs = new ArrayList<TLV>();

		tag = new Tag(pb);

		if (alternateLengthFormat)
			length = pb.getDGILength();
		else
			length = pb.getDERLength();

		// We are calling this constructor recursively if nested TLV
		// structures are instantiated. All recursive calls share
		// the same ParseBuffer, but the length that can be parsed
		// is always shorter than for the surounding TLV object.
		// So we save the current length remaining in a local variable,
		// limit the new length to the length of the constructed
		// value field and restore the length after the value field
		// is completely parsed

		//		limit = pb.remaining();
		limit = pb.getLimit();
		if (length >= 0) {			// Fixed length encoding
			pb.setLength(length);

			while (pb.hasRemaining()) {
				add(TLV.factory(pb));
			}
		} else {					// Variable length encoding
			TLV t;					// Collect all elements until the null object ('00' '00') is found
			do	{
				t = TLV.factory(pb);
				if ((t.tag.getNumber() == 0) && (t.getLength() == 0)) {
					break;
				}
				add(t);
			} while (true);
		}

		// Restore length
		//		pb.setLength(limit - length);
		pb.setLimit(limit);
	}



	/**
	 * Create constructed TLV object from byte array
	 *
	 * @param buffer
	 * 		Byte array containing data object
	 * @throws TLVEncodingException
	 */
	public ConstructedTLV(byte[] buffer) throws TLVEncodingException {
		//		this(buffer, 0);
		this(new ParseBuffer(buffer));
	}



	/**
	 * Copy constructor
	 *
	 * Initialize with existing ConstructedTLV object. Does not perform
	 * a deep copy. The tag and list of contained objects are reassigned.
	 *
	 * Caution: If applied to a TLV object embedded in a complex structure
	 * remember to update the reference to this object in the parent node.
	 *
	 * @param tlv
	 * 		ConstructedTLV
	 *
	 * @throws UnsupportedOperationException
	 *
	 */
	public ConstructedTLV(TLV tlv) throws UnsupportedOperationException {
		super(tlv);
		if (!(tlv instanceof ConstructedTLV))
			throw new UnsupportedOperationException("Can not clone from other than constructed TLV");

		childs = ((ConstructedTLV)tlv).childs;
	}



	/**
	 * Store value from constructed object to binary buffer
	 *
	 * @param buffer
	 * 		Byte array that received the binary data
	 * @param offset
	 * 		Offset in byte array
	 * @return
	 * 		New offset behind the stored object
	 */
	protected int valueToByteArray(byte[] buffer, int offset) {
		Iterator<TLV> iter = childs.iterator();

		while (iter.hasNext()) {
			offset = ((TLV)iter.next()).toByteArray(buffer, offset);
		}

		return offset;
	}



	/**
	 * Store constructed object to binary buffer
	 *
	 * @param buffer
	 * 		Byte array that received the binary data
	 * @param offset
	 * 		Offset in byte array
	 * @return
	 * 		New offset behind the stored object
	 */
	protected int toByteArray(byte[] buffer, int offset) {
		int length = getLength();

		offset = tag.toByteArray(buffer, offset);
		offset = lengthToByteArray(length, buffer, offset, alternateLengthFormat);

		Iterator<TLV> iter = childs.iterator();

		while (iter.hasNext()) {
			offset = ((TLV)iter.next()).toByteArray(buffer, offset);
		}

		return offset;
	}



	/**
	 * Determine length of value field
	 *
	 * @return
	 * 		Length in bytes
	 */
	public int getLength() {
		Iterator<TLV> iter = childs.iterator();
		int length = 0;

		while (iter.hasNext()) {
			length += ((TLV)iter.next()).getSize();
		}
		return length;
	}



	/**
	 * Add tlv object to constructed TLV
	 *
	 * @param tlv
	 * 		TLV object to be added
	 */
	public ConstructedTLV add(TLV tlv) {
		childs.add(tlv);
		return this;
	}



	/**
	 * Add tlv object to constructed TLV at index
	 *
	 * @param index the zero based index for insertion
	 * @param tlv the TLV object to be added
	 */
	public ConstructedTLV add(int index, TLV tlv) {
		childs.add(index, tlv);
		return this;
	}



	/**
	 * >Remove tlv element at index
	 *
	 * @param index the index of the element to be removed
	 */
	public void remove(int index) {
		childs.remove(index);
	}



	/**
	 * Return tlv object at index
	 *
	 * @param index
	 * @return tlv object
	 */
	public TLV get(int index) {
		return (TLV)childs.get(index);
	}



	/**
	 * Return number of child elements
	 *
	 * @return number of child elements
	 *
	 */
	public int getElements() {
		return childs.size();
	}



	/**
	 * Find matching tag in constructed TLV
	 *
	 * @param tag
	 * 		Tag to search
	 * @param cursor
	 * 		null to start at the beginning or result of last search
	 * 		to continue
	 * @return
	 * 		null if tag not found or TLV object
	 */
	public TLV findTag(Tag tag, TLV cursor) {
		int index, size;

		if (cursor == null) {
			index = 0;
		} else {
			index = childs.indexOf(cursor);
			if (index == -1)
				return null;
			index++;
		}

		size = childs.size();
		while (index < size) {
			cursor = (TLV)childs.get(index);
			if (tag.equals(cursor.getTag()))
				return cursor;
			index++;
		}

		return null;
	}



	/**
	 * Return dump of constructed TLV object using a given left indentation
	 * @param indent
	 * 		Left indentation to be used
	 * @return
	 * 		String containing dump of primitive TLV object
	 */
	public String dump(int indent) {
		StringBuffer buffer = new StringBuffer(100);

		for (int i = 0; i < indent; i++) {
			buffer.append(' ');
		}
		if (name != null) {
			buffer.append(name);
			buffer.append(' ');
		}
		buffer.append(tag.toString());
		buffer.append(" SIZE( "+ getLength() + " )");
		buffer.append('\n');

		Iterator<TLV> iter = childs.iterator();

		while (iter.hasNext()) {
			buffer.append(((TLV)iter.next()).dump(indent + 2));
		}
		return buffer.toString();
	}



	/**
	 * Return number of childs, of object is constructed
	 *
	 * @see de.cardcontact.tlv.TreeNode#getChildCount()
	 */
	public int getChildCount() {
		return childs.size();
	}



	/**
	 * Return true
	 * @see de.cardcontact.tlv.TreeNode#isLeaf()
	 */
	public boolean isLeaf() {
		return false;
	}



	/**
	 * Get parent if it is known
	 * @see de.cardcontact.tlv.TreeNode#getParent()
	 */
	public TreeNode getParent() {
		return null; // Not implemented
	}



	/**
	 * Get Child at index position
	 *
	 * @see de.cardcontact.tlv.TreeNode#getChildAt(int)
	 */
	public TreeNode getChildAt(int index) {
		return (TreeNode)childs.get(index);
	}



	/**
	 * Get index position for child
	 *
	 * @see de.cardcontact.tlv.TreeNode#getIndex(de.cardcontact.tlv.TreeNode)
	 */
	public int getIndex(TreeNode child) {
		return childs.indexOf(child);
	}
}
