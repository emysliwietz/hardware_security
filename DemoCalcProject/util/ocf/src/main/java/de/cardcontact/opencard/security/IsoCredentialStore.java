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

package de.cardcontact.opencard.security;

import opencard.core.terminal.CardID;
import opencard.opt.iso.fs.CardFilePath;
import opencard.opt.security.Credential;
import opencard.opt.security.CredentialStore;
import opencard.opt.security.SecurityDomain;

/**
 * Class implementing a credential store for secure channel credentials
 *
 * Secure channel credentials are stored with the file path and access mode as index
 * 
 * @author Andreas Schwier (info@cardcontact.de)
 */

public class IsoCredentialStore extends CredentialStore {

	public final static int SELECT = 1;
	public final static int READ = 2;
	public final static int UPDATE = 4;
	public final static int APPEND = 8;
	public final static int CREATE = 16;
	public final static int DELETE = 32;
	public final static int ACTIVATE = 64;
	public final static int DEACTIVATE = 128;
	public final static int SIZE_ACCESS_MATRIX = 8;


	/**
	 * Generic store that supports any card
	 */
	public boolean supports(CardID cardID) {
		return true;
	}



	/**
	 * Set secure channel credential for a security domain
	 * 
	 * @param sd            Security domain (usually a CardFilePath object)
	 * @param scc           Secure channel credential for this domain
	 */
	public void setSecureChannelCredential(SecurityDomain sd, SecureChannelCredential scc) {
		storeCredential(sd, scc);
	}



	/**
	 * Return the credentials defined for a specific security domain
	 *
	 * @param sd            Security domain (usually a CardFilePath object)
	 * @return              Secure channel credential for this domain
	 */
	public SecureChannelCredential getSecureChannelCredential(SecurityDomain sd) {
		Credential c = fetchCredential(sd);

		if (c instanceof SecureChannelCredential) {
			SecureChannelCredential scc = (SecureChannelCredential)c;
			return scc;
		}
		return null;
	}



	/**
	 * Get a secure channel credential for a specified security domain and access mode
	 * 
	 * @param sd            Security domain (usually a CardFilePath object)
	 * @param accessMode    Access mode, one of SELECT, READ, UPDATE, APPEND
	 * @return              Secure channel credential or null if none defined
	 */
	public SecureChannelCredential getSecureChannelCredential(SecurityDomain sd, int accessMode) {
		CardFilePath path = new CardFilePath((CardFilePath)sd);

		do  {
			Credential c = fetchCredential(path.toString() + "@" + accessMode);

			if (c == null) {
				c = fetchCredential(path.toString());
			}

			if ((c != null) && (c instanceof SecureChannelCredential)) {
				SecureChannelCredential scc = (SecureChannelCredential)c;
				return scc;
			}
		} while(path.chompTail());

		CardFilePath rootPath = new CardFilePath(":3F00");

		if (!path.equals(rootPath)) {
			// Check if there is a credential defined for the MF
			Credential c = fetchCredential(rootPath.toString() + "@" + accessMode);

			if (c == null) {
				c = fetchCredential(rootPath.toString());
			}

			if ((c != null) && (c instanceof SecureChannelCredential)) {
				SecureChannelCredential scc = (SecureChannelCredential)c;
				return scc;
			}
		}

		return null;
	}



	/**
	 * Set a secure channel credential for a specified security domain and access mode
	 * 
	 * @param sd            Security domain (usually a CardFilePath object)
	 * @param accessMode    Access mode, one of SELECT, READ, UPDATE, APPEND
	 * @param scc           Secure channel credential
	 */
	public void setSecureChannelCredential(SecurityDomain sd, int accessMode, SecureChannelCredential scc) {
		for (int i = 0; i < SIZE_ACCESS_MATRIX; i++ ) {
			if ((accessMode & (1 << i)) > 0) {
				storeCredential(sd.toString() + "@" + (1 << i), scc);
			}
		}
	}
}
