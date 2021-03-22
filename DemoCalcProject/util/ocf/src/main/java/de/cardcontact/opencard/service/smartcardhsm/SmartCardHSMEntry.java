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

import java.security.cert.Certificate;



/**
 * This class gives a representation of an SmartCardHSM entry.
 * 
 * An Entry can contain either a private key reference with corresponding public key certificate,
 * or a CA certificate.
 * 
 * @author lew
 *
 */
public class SmartCardHSMEntry {



	/**
	 * The private key reference
	 */
	private SmartCardHSMKey key = null;



	/**
	 * The Certificate is either an EE certificate or a CA certificate
	 */
	private Certificate cert = null;



	/**
	 * @return true if the certificate is an EE certificate, false if it is an CA certificate
	 */
	private boolean isEECertificate;



	/**
	 * The key or certificate id
	 */
	private byte id;



	/**
	 * SmartCardHSMEntry constructor
	 * 
	 * @param key Reference to the private key on the card
	 */
	public SmartCardHSMEntry(SmartCardHSMKey key) {
		this.key = key;
		this.id = key.getKeyRef();
	}



	/**
	 * SmartCardHSMEntry constructor
	 * 
	 * @param cert Certificate
	 * @param isEECertificate true for EE certificates false for CA certificates
	 * @param id The certificate ID
	 */
	public SmartCardHSMEntry(Certificate cert, boolean isEECertificate, byte id) {
		this.cert = cert;
		this.isEECertificate = isEECertificate;
		this.setId(id);
	}



	/**
	 * @return true for EE certificates false for CA certificates
	 */
	public boolean isEECertificate() {
		return isEECertificate;
	}



	public boolean isCertificateEntry() {
		return cert != null;
	}



	public boolean isKeyEntry() {
		return key != null;
	}



	public SmartCardHSMKey getKey() {
		return key;
	}



	public void setKey(SmartCardHSMKey key) {
		this.key = key;
	}



	public void setCert(Certificate cert, boolean isEECertificate, byte id) {
		this.cert = cert;
		this.isEECertificate = isEECertificate;
		this.id = id;
	}



	public Certificate getCert() {
		return cert;
	}



	public void setId(byte id) {
		this.id = id;
	}



	public byte getId() {
		return id;
	}
}
