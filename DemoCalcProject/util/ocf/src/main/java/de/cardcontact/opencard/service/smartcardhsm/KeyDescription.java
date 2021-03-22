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

package de.cardcontact.opencard.service.smartcardhsm;

import java.util.StringTokenizer;

import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.HexString;
import de.cardcontact.tlv.IntegerTLV;
import de.cardcontact.tlv.OctetString;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.Sequence;
import de.cardcontact.tlv.TLV;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.Tag;
import de.cardcontact.tlv.UTF8String;

/**
 * PKCS#15 key description for RSA, EC and AES keys
 *
 * @author lew
 */
public class KeyDescription {

	public enum KeyTypes { RSA, EC, AES };

	private byte[] keyid;

	private String label;

	private int size;

	private KeyTypes type;

	private int keyref = -1;

	private byte[] encoded;

	private Tag TagA0 = new Tag(0, Tag.CONTEXT, true);
	private Tag TagA1 = new Tag(1, Tag.CONTEXT, true);
	private Tag ecTag = new Tag(0, Tag.CONTEXT, true);
	private Tag aesTag = new Tag(8, Tag.CONTEXT, true);



	public KeyDescription(byte[] keyid, String label, int size, KeyTypes type) {
		this.keyid = keyid;
		this.label = label;
		this.size = size;
		this.type = type;

		switch(type) {
		case RSA:
			makeForRSA();
			break;
		case EC:
			makeForEC();
			break;
		case AES:
			makeForAES();
		}
	}



	public KeyDescription(byte[] prkd) throws TLVEncodingException {
		this.encoded = prkd;
		parseEncoded();
	}



	private void makeForEC() {
		ConstructedTLV desc = new ConstructedTLV(ecTag)
			.add(new Sequence()
				.add(new UTF8String(label)))
			.add(new Sequence()
				.add(new OctetString(keyid))
				.add(new PrimitiveTLV(Tag.TAG_BIT_STRING, new byte[] {0x07, 0x20, (byte) 0x80})))
			.add(new ConstructedTLV(new Tag(1, Tag.CONTEXT, true))
				.add(new Sequence()
					.add(new Sequence()
						.add(new OctetString(new byte[0])))
					.add(new IntegerTLV(size))));

		encoded = desc.getBytes();
	}



	private void makeForRSA() {
		ConstructedTLV desc = new Sequence()
				.add(new Sequence()
						.add(new UTF8String(label)))
				.add(new Sequence()
					.add(new OctetString(keyid))
					.add(new PrimitiveTLV(Tag.TAG_BIT_STRING, new byte[] {0x02, 0x74})))
				.add(new ConstructedTLV(new Tag(1, Tag.CONTEXT, true))
					.add(new Sequence()
						.add(new Sequence()
							.add(new OctetString(new byte[0])))
						.add(new IntegerTLV(size))));

		encoded = desc.getBytes();
	}



	private void makeForAES() {
		ConstructedTLV desc = new ConstructedTLV(aesTag)
				.add(new Sequence()
						.add(new UTF8String(label)))
				.add(new Sequence()
					.add(new OctetString(keyid))
					.add(new PrimitiveTLV(Tag.TAG_BIT_STRING, new byte[] {0x07, (byte)0xC0, 0x10})))
				.add(new ConstructedTLV(new Tag(0, Tag.CONTEXT, true))
						.add(new Sequence()
							.add(new IntegerTLV(size))))
				.add(new ConstructedTLV(new Tag(1, Tag.CONTEXT, true))
					.add(new Sequence()
						.add(new Sequence()
							.add(new OctetString(new byte[0])))));

		encoded = desc.getBytes();
	}



	private void parseEncoded() throws TLVEncodingException {
		ConstructedTLV tlv = (ConstructedTLV)TLV.factory(encoded);

		// Get Label
		Sequence seq = Sequence.getInstance(tlv.get(0));
		label = UTF8String.getInstance(seq.get(0)).toString();

		// Get Key ID
		seq = Sequence.getInstance(tlv.get(1));
		keyid = OctetString.getInstance(seq.get(0)).getValue();

		int i = 2;
		// Get key size and return new PRKD
		if (tlv.getTag().equals(Tag.TAG_SEQUENCE)) {
			type = KeyTypes.RSA;
			if (tlv.get(i).getTag().equals(TagA0)) {
				i++;
			}
			seq = Sequence.getInstance(tlv.get(i), TagA1);
			seq = Sequence.getInstance(seq.get(0));
			size = (int)IntegerTLV.getInstance(seq.get(1)).getLong();
		} else if (tlv.getTag().equals(ecTag)) {
			type = KeyTypes.EC;
			if (tlv.get(i).getTag().equals(TagA0)) {
				i++;
			}
			seq = Sequence.getInstance(tlv.get(i), TagA1);
			seq = Sequence.getInstance(seq.get(0));
			if (seq.getElements() > 1) {
				size = (int)IntegerTLV.getInstance(seq.get(1)).getLong();
			} else {
				size = 0;
			}
		} else if (tlv.getTag().equals(aesTag)) {
			type = KeyTypes.AES;
			seq = Sequence.getInstance(tlv.get(2), TagA0);
			if (seq.get(0).getTag().equals(Tag.TAG_SEQUENCE)) {
				seq = Sequence.getInstance(seq.get(0));			// Fix bug with wrong indirection
			}
			size = (int)IntegerTLV.getInstance(seq.get(0)).getLong();
			if (size < 0) {
				size = -size;
			}
		} else {
			throw new TLVEncodingException("Unknown key description format");
		}
	}



	public byte[] getKeyID() {
		return keyid;
	}



	public String getLabel() {
		return label;
	}



	public void setKeyRef(byte ref) {
		this.keyref = ref & 0xFF;
	}



	/**
	 * Return the label with placeholders replaced by actual values
	 *
	 * @return
	 */
	public String getTranslatedLabel() {
		StringBuffer str = new StringBuffer();
		String label = getLabel();

		StringTokenizer tokenizer = new StringTokenizer(label, "%");
		if (tokenizer.hasMoreElements() && (label.charAt(0) != '%')) {
			str.append(tokenizer.nextToken());
		}
		while(tokenizer.hasMoreElements()) {
			String token = tokenizer.nextToken();
			switch(token.charAt(0)) {
			case 'i':
				if (keyid != null) {
					str.append(HexString.hexifyByteArray(keyid));
				}
				str.append(token.substring(1));
				break;
			case 'r':
				if (keyref != -1) {
					str.append(keyref);
				}
				str.append(token.substring(1));
				break;
			case 't':
				switch(type) {
				case RSA: str.append("RSA"); break;
				case EC: str.append("EC"); break;
				case AES: str.append("AES"); break;
				}
				str.append(token.substring(1));
				break;
			default:
				str.append(token);
			}
		}
		return str.toString();
	}



	public int getSize() {
		return size;
	}



	public KeyTypes getType() {
		return type;
	}



	public byte[] getEncoded() {
		return encoded;
	}
}
