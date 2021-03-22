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

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;



/**
 * Global registry of namend object identifier
 * 
 * @author asc
 *
 */
public class ObjectIdentifierRegistry {
	
	private static ObjectIdentifierRegistry instance = null;
	
	private HashMap<String, String> nameMap;
	private HashMap<ByteStringWrapper, String> oidMap;
	
	
	
	private ObjectIdentifierRegistry() {
		nameMap = new HashMap<String, String>();
		oidMap = new HashMap<ByteStringWrapper, String>();
	}
	
	
	
	/**
	 * Gets the singleton instance of the registry
	 * @return
	 */
	public static ObjectIdentifierRegistry getInstance() {
		if (instance == null) {
			instance = new ObjectIdentifierRegistry();
		}
		return instance;
	}
	
	
	
	/**
	 * Helper to create value field from array of object identifier elements
	 * 
	 * @param oid
	 * 		List containing object identifier elements
	 */	
	protected static byte[] encodeOID(List <Integer> oid) {
		int i, j, size, val;
		
		if ((oid.size() < 2) || (oid.get(0).intValue() < 0) || (oid.get(0).intValue() > 2) || (oid.get(1).intValue() < 0) || (oid.get(1).intValue() > 39))
			throw new IllegalArgumentException("Object identifier out of range");
			
		size = 1;
		
		// Determine size
		for (i = 2; i < oid.size(); i++) {
			val = oid.get(i).intValue();
			if (val < 0) {
				throw new IllegalArgumentException("Object identifier out of range");
			}
			do	{
				size++;
				val >>= 7;
			} while (val > 0);
		}

		byte[] value = new byte[size];

		value[0] = (byte)(40 * oid.get(0).intValue() + oid.get(1).intValue());
		
		j = 1;
		for (i = 2; i < oid.size(); i++) {
			val = oid.get(i).intValue();
			size = -7;
			do	{
				size += 7;
				val >>= 7;
			} while (val > 0);
			
			val = oid.get(i).intValue();
			for (; size >= 0; size -= 7) {
				value[j++] = (byte)((val >> size) & 0x7F | 0x80);
			}
			value[j - 1] &= 0x7F;
		}
		return value;
	}



	/**
	 * Parse a string into an object identifier.
	 * <p>The parser supports a dotted notation as well as a comma separated notation.
	 * The string may contain pre-defined names from the registry and local names like test(1).
	 * </p>
	 * @param oid the string to be parsed
	 * @return a list of object identifier elements
	 */
	private static ArrayList<Integer> parseObjectIdentifierString(String oid, int recursioncount) {
		if (recursioncount < 0) {
			throw new IllegalArgumentException("Recursive definition of " + oid);
		}
		StringTokenizer sp = new StringTokenizer(oid, " .");

		ArrayList<Integer> elements = new ArrayList<Integer>(sp.countTokens());
		
		while (sp.hasMoreTokens()) {
			String temp = sp.nextToken();
			
			Integer i;
			
			try	{
				i = new Integer(temp);
				elements.add(i);
			}
			catch(NumberFormatException nfe) {
				if (temp.matches("^[\\w-]+\\(\\d+\\)$")) {
					String nstr = temp.substring(temp.indexOf('(') + 1, temp.indexOf(')'));
					i = new Integer(nstr);
					elements.add(i);
				} else {
					String str = instance.getOIDFor(temp);
					
					if (str == null) {
						throw new IllegalArgumentException("'" + temp + "' is an unknown identifier");
					}
					elements.addAll(parseObjectIdentifierString(str, recursioncount - 1));
				}
			}
		}
		return elements;
	}
	
	
	
	/**
	 * Parse a string into an object identifier.
	 * <p>The parser supports a dotted notation as well as a comma separated notation.
	 * The string may contain pre-defined names from the registry and local names like test(1).
	 * </p>
	 * @param oid the string to be parsed
	 * @return the encoded object identifier
	 */
	public static byte[] parseObjectIdentifier(String oid) {
		ArrayList<Integer> elements = parseObjectIdentifierString(oid, 100);
		return encodeOID(elements);
	}
	
	
	
	/**
	 * Add a name and object identifier to the internal registry
	 * 
	 * @param name the object identifiers symbolic name
	 * @param oid the object identifiers definition
	 */
	public void addIdentifier(String name, String oid) {
		String c = nameMap.get(name);
		
		if ((c != null) && !c.equals(oid)) {
			throw new IllegalArgumentException("'" + name + "' already defined as " + c);
		}
		
		byte[] encoded = parseObjectIdentifier(oid);
		ByteStringWrapper bsw = new ByteStringWrapper(encoded);
		
		c = oidMap.get(bsw);
		
		if ((c != null) && !c.equals(name)) {
			throw new IllegalArgumentException("'" + name + "' already defined by " + c);
		}
		
		nameMap.put(name, oid);
		oidMap.put(new ByteStringWrapper(encoded), name);
	}
	
	
	
	/**
	 * Return the object identifier for a given name.
	 * 
	 * @param name the name to search for
	 * @return the object identifier for the given name or null
	 */
	public String getOIDFor(String name) {
		return nameMap.get(name);
	}
	
	
	
	/**
	 * Return a name, if any, that matches the given encoded object identifier.
	 * 
	 * @param oid the encoded object identifier
	 * @return the name or null
	 */
	public String getNameFor(byte[] oid) {
		return oidMap.get(new ByteStringWrapper(oid));
	}
	
	
	
	/**
	 * Wraps a byte array implementing the equals() and hashCode() methods.
	 * 
	 */
	private class ByteStringWrapper {
		
		private final byte[] bs;
		
		public ByteStringWrapper(byte[] bs) {
			this.bs = bs;
		}
		
		public int hashCode() {
			return Arrays.hashCode(bs);
		}
		
		public boolean equals(Object o) {
			if (!(o instanceof ByteStringWrapper)) {
				return false;
			}
			return Arrays.equals(bs, ((ByteStringWrapper)o).bs);
		}
	}
}
