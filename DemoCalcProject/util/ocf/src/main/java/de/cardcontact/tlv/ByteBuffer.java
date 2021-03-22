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
 * Implements a mutable byte buffer similar to StringBuffer.
 * 
 * @author Andreas Schwier (info@cardcontact.de)
 */
public class ByteBuffer {
	byte[] buffer = null;
	int length = 0;

	/**
	 * Create empty ByteBuffer with initial capacity of 16 bytes
	 */
	public ByteBuffer() {
		this(16);
	}

	/**
	 * Create empty ByteBuffer with initial capacity as defined by parameter
	 * length
	 * 
	 * @param length
	 *            Initial capacity of ByteBuffer
	 */
	public ByteBuffer(int length) {
		buffer = new byte[length];
	}

	/**
	 * Create ByteBuffer which contains a exact copy of the byte array passed as
	 * parameter
	 * 
	 * @param bytes
	 *            Byte array to create ByteBuffer from
	 */
	public ByteBuffer(byte[] bytes) {
		buffer = bytes;
		length = bytes.length;
	}

	/**
	 * Append single byte
	 * 
	 * @param _byte
	 * @return this
	 */
	public ByteBuffer append(byte _byte) {
		return insert(length, _byte);
	}

	/**
	 * Append byte array
	 * 
	 * @param bytes
	 * @return this
	 */
	public ByteBuffer append(byte[] bytes) {
		return insert(length, bytes);
	}

	/**
	 * Append ByteBuffer
	 * 
	 * @param bb
	 * @return this
	 */
	public ByteBuffer append(ByteBuffer bb) {
		return insert(length, bb);
	}

	/**
	 * Ensure that the internal buffer can hold the requested number of bytes
	 * 
	 * If newCapacity is less than the current capacity, then the meth
	 * 
	 * @param newCapacity
	 */
	void ensureCapacity(int newCapacity) {
		if (newCapacity > buffer.length) {
			int newSize = (buffer.length << 1) + 2;
			if (newCapacity > newSize)
				newSize = newCapacity;

			byte[] newbuffer = new byte[newSize];
			System.arraycopy(buffer, 0, newbuffer, 0, length);
			buffer = newbuffer;
		}
	}

	/**
	 * Insert bytes at offset
	 * 
	 * @param offset
	 * @param bytes
	 * @param length
	 * @return
	 * @throws IndexOutOfBoundsException
	 */
	public ByteBuffer insert(int offset, byte[] bytes, int length)
			throws IndexOutOfBoundsException {

		if ((offset > this.length) || (offset < 0))
			throw new IndexOutOfBoundsException();

		ensureCapacity(this.length + length);
		System.arraycopy(buffer, offset, buffer, offset + length, this.length
				- offset);
		System.arraycopy(bytes, 0, buffer, offset, length);
		this.length += length;
		return this;
	}

	/**
	 * Insert byte at offset
	 * 
	 * @param offset
	 *            Position at which to insert the bytes
	 * @param _byte
	 *            Byte to insert
	 * @return this
	 * @throws IndexOutOfBoundsException
	 *             If offset is not in range
	 */
	public ByteBuffer insert(int offset, byte _byte)
			throws IndexOutOfBoundsException {
		return insert(offset, new byte[] { _byte }, 1);
	}

	/**
	 * Insert contents of byte array at offset
	 * 
	 * @param offset
	 *            Position at which to insert the bytes
	 * @param bytes
	 *            Byte array to insert
	 * @return this
	 * @throws IndexOutOfBoundsException
	 *             If offset is not in range
	 */
	public ByteBuffer insert(int offset, byte[] bytes)
			throws IndexOutOfBoundsException {
		return insert(offset, bytes, bytes.length);
	}

	/**
	 * Insert contents of ByteBuffer at offset
	 * 
	 * @param offset
	 *            Position at which to insert the ByteBuffer
	 * @param bb
	 *            ByteBuffer to insert
	 * @return this
	 * @throws IndexOutOfBoundsException
	 *             If offset is not in range
	 */
	public ByteBuffer insert(int offset, ByteBuffer bb)
			throws IndexOutOfBoundsException {
		return insert(offset, bb.buffer, bb.length);
	}

	/**
	 * Return length of ByteBuffer
	 * 
	 * @return Length of ByteBuffer
	 */
	public int length() {
		return length;
	}

	/**
	 * Return byte at zero based offset
	 * 
	 * @param offset
	 * @return byte at offset
	 * @throws IndexOutOfBoundsException
	 */
	public byte getByteAt(int offset) throws IndexOutOfBoundsException {
		if ((offset < 0) || (offset >= length))
			throw new IndexOutOfBoundsException();
		return buffer[offset];
	}

	/**
	 * Clear buffer in specified range and move trailing data behind offset +
	 * count
	 * 
	 * @param offset
	 * @param count
	 * @return this
	 */
	public ByteBuffer clear(int offset, int count)
			throws IndexOutOfBoundsException {
		if ((offset < 0) || (count < 0) || (offset + count > length))
			throw new IndexOutOfBoundsException();

		System.arraycopy(buffer, offset + count, buffer, offset, length
				- (offset + count));
		length -= count;
		return this;
	}

	/**
	 * Copy source into buffer at offset
	 * 
	 * @param offset
	 * @param source
	 * @return this
	 */
	public ByteBuffer copy(int offset, byte[] source) {
		if ((offset < 0) || (offset + source.length > length))
			throw new IndexOutOfBoundsException();

		System.arraycopy(source, 0, buffer, offset, source.length);
		return this;
	}

	/**
	 * Search byte arrays for matching search string and return zero based
	 * offset.
	 * 
	 * Start search at given offset. An empty search string is always found.
	 * 
	 * @param source
	 *            Byte array to search in
	 * @param length
	 *            Range in source to search in
	 * @param search
	 *            Byte array to search for
	 * @param offset
	 *            Offset to start at
	 * @return Zero based offset of match or -1
	 */
	public static int find(byte[] source, int length, byte[] search, int offset) {
		while (offset + search.length <= length) {
			int i;
			for (i = 0; (i < search.length)
					&& (source[offset + i] == search[i]); i++)
				;
			if (i == search.length)
				return offset;
			offset++;
		}
		return -1;
	}

	/**
	 * Search byte arrays for matching search string and return zero based
	 * offset.
	 * 
	 * Start search at given offset. An empty search string is always found.
	 * 
	 * @param source
	 *            Byte array to search in
	 * @param search
	 *            Byte array to search for
	 * @param offset
	 *            Offset to start at
	 * @return Zero based offset of match or -1
	 */
	public static int find(byte[] source, byte[] search, int offset) {
		return find(source, source.length, search, offset);
	}

	/**
	 * Search ByteBuffer for matching search string and return zero based
	 * offset.
	 * 
	 * Start search at given offset. An empty search string is always found.
	 * 
	 * @param search
	 *            Byte array to search for
	 * @param offset
	 *            Offset to start at
	 * @return Zero based offset of match or -1
	 */
	public int find(byte[] search, int offset) {
		return find(buffer, length, search, offset);
	}

	/**
	 * Return ByteBuffer as byte arrays
	 * 
	 * @return Array of bytes
	 */
	public byte[] getBytes() {
		byte[] response = new byte[length];
		System.arraycopy(buffer, 0, response, 0, length);
		return response;
	}

	/**
	 * Return part of ByteBuffer as byte arrays
	 * 
	 * @param offset
	 *            Zero based offset in buffer
	 * @param count
	 *            Number of bytes to extract
	 * @return Array of bytes
	 */
	public byte[] getBytes(int offset, int count) {
		byte[] response = new byte[count];
		System.arraycopy(buffer, offset, response, 0, count);
		return response;
	}

	/**
	 * Return hexadecimal string for content of ByteBuffer
	 * 
	 * @return Hexadecimal string
	 */
	public String toString() {
		return HexString.hexifyByteArray(buffer, ' ', length);
	}
}
