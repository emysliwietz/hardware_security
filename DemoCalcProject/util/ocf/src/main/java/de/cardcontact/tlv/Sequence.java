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
 * Class to implement ASN.1 SEQUENCE object
 *
 * @author Andreas Schwier (info@cardcontact.de)
 */
public class Sequence extends ConstructedTLV {

	/**
	 * Create constructed TLV with Tag set to ASN.1 SEQUENCE
	 *
	 */
	public Sequence() {
		super(new Tag(Tag.SEQUENCE, Tag.UNIVERSAL, true));
	}



	/**
	 * Create object from parse buffer
	 *
	 * This should not be called directly. Use TLV.factory() methods instead
	 *
	 * @param pb
	 */
	public Sequence(ParseBuffer pb) throws TLVEncodingException {
		super(pb);

		if ((tag.getNumber() != Tag.SEQUENCE) || !(tag.isConstructed())) {
			throw new TLVEncodingException("Invalid tag for SEQUENCE");
		}
	}



	/**
	 * Copy constructor
	 *
	 * Initialize with existing ConstructedTLV object. Does not perform
	 * a deep copy. The tag and list of contained objects is reassigned.
	 *
	 * Caution: If applied to a TLV object embedded in a complex structure
	 * remember to update the reference to this object in the parent node.
	 *
	 * @param tlv
	 * 		ConstructedTLV
	 *
	 * @throws TLVEncodingException
	 *
	 */
	public Sequence(TLV tlv) throws TLVEncodingException {
		super(tlv);
	}



	/**
	 * Check tag and convert - if needed - the ConstructedTLV to a Sequence
	 *
	 * @param tlv
	 * @param et et tag used in implicit encoding
	 * @throws TLVEncodingException
	 */
	public static Sequence getInstance(TLV tlv, Tag et)  throws TLVEncodingException {
		if (!tlv.getTag().equals(et)) {
			throw new TLVEncodingException("Tag must be " + et);
		}
		if (tlv instanceof Sequence) {
			return (Sequence)tlv;
		}
		return new Sequence(tlv);
	}



	/**
	 * Convert - if needed - the ConstructedTLV to a Sequence
	 *
	 * @param tlv
	 * @return
	 * @throws TLVEncodingException
	 */
	public static Sequence getInstance(TLV tlv)  throws TLVEncodingException {
		return getInstance(tlv, Tag.TAG_SEQUENCE);
	}
}
