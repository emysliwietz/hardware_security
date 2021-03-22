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

import java.security.MessageDigest;
import java.security.PublicKey;

import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.Sequence;
import de.cardcontact.tlv.TLV;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.Tag;

public class CertificateDescription {

	public static byte[] buildCertDescription(String label, PublicKey subjectPublicKey, byte[] certEF) throws TLVEncodingException {
		return buildCertDescription(label, null, subjectPublicKey, certEF);
	}

	public static byte[] computeSubjectKeyID(PublicKey key) {
		byte[] sha1 = null;
		try {
			Sequence pk = (Sequence)TLV.factory(key.getEncoded());
			byte[] hashinp = pk.get(1).getValue();

			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(hashinp, 1, hashinp.length - 1);
			sha1 = md.digest();
		} catch (Exception e) {
			// ignore
		}
		return sha1;
	}

	public static byte[] buildCertDescription(String label, byte[] commonObjectFlags, PublicKey subjectPublicKey, byte[] certEF) throws TLVEncodingException {
		ConstructedTLV tlv = new ConstructedTLV(0x30);
		ConstructedTLV commonObjectAttributes = new ConstructedTLV(0x30);
		commonObjectAttributes.add(new PrimitiveTLV(Tag.UTF8String, label.getBytes()));

		if (commonObjectFlags == null) {
			commonObjectFlags = new byte[] {0x06, 0x40};
		}
		commonObjectAttributes.add(new PrimitiveTLV(Tag.BIT_STRING, commonObjectFlags));

		ConstructedTLV commonCertificateAttributes = new ConstructedTLV(0x30);
		commonCertificateAttributes.add(new PrimitiveTLV(Tag.OCTET_STRING, computeSubjectKeyID(subjectPublicKey)));

		ConstructedTLV typeAttributes = new ConstructedTLV(0xA1);
		ConstructedTLV x509CertificateAttributes = new ConstructedTLV(0x30);
		ConstructedTLV path = new ConstructedTLV(0x30);
		path.add(new PrimitiveTLV(Tag.OCTET_STRING, certEF));
		x509CertificateAttributes.add(path);
		typeAttributes.add(x509CertificateAttributes);

		tlv.add(commonObjectAttributes);
		tlv.add(commonCertificateAttributes);
		tlv.add(typeAttributes);

		return tlv.getBytes();
	}



	public byte[] buildCertDescription(String label) throws TLVEncodingException {
		ConstructedTLV tlv = new ConstructedTLV(0x30);
		ConstructedTLV labelSequence = new ConstructedTLV(0x30);
		labelSequence.add(new PrimitiveTLV(Tag.UTF8String, label.getBytes()));
		tlv.add(labelSequence);
		return tlv.getBytes();
	}



	public String getLabel(byte[] enc) throws TLVEncodingException {
		ConstructedTLV tlv = new ConstructedTLV(enc);
		tlv = (ConstructedTLV) tlv.get(0);
		if (tlv.getElements() < 1) {
			throw new TLVEncodingException("The description is wrong encoded");
		}
		String label = new String(tlv.get(0).getValue());
		return label;
	}
}
