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

package de.cardcontact.opencard.service.isocard;

import opencard.core.service.CardChannel;
import opencard.core.service.CardServiceException;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.terminal.SlotChannel;
import opencard.core.util.APDUTracer;
import opencard.opt.iso.fs.CardFilePath;
import opencard.opt.security.CredentialBag;
import opencard.opt.security.SecureService;
import opencard.opt.security.SecurityDomain;
import opencard.opt.util.PassThruCardService;
import de.cardcontact.opencard.security.IsoCredentialStore;
import de.cardcontact.opencard.security.SecureChannel;
import de.cardcontact.opencard.security.SecureChannelCredential;

/**
 * Transparent card service with secure messaging support
 * 
 * @author Andreas Schwier
 */
public class TransparentCardService extends PassThruCardService implements SecureService {
	private CredentialBag credentialBag;
	private SecurityDomain securityDomain;

	public TransparentCardService() {
		super();
		credentialBag = null;
	}



	/**
	 * Provide collection of credentials for secure messaging transformation
	 *  
	 * @see opencard.opt.security.SecureService#provideCredentials(opencard.opt.security.SecurityDomain, opencard.opt.security.CredentialBag)
	 */
	public void provideCredentials(SecurityDomain domain, CredentialBag creds) throws CardServiceException {
		if (domain == null) {
			this.securityDomain = new CardFilePath(":3F00");
		} else {
			this.securityDomain = domain;
		}
		this.credentialBag = creds;
	}



	/**
	 * Send command APDU and receive response APDU, possibly wrapped by secure channel
	 * 
	 * The implementation will try to fetch a secure messaging credential from the bag allocated to the MF (3F00)
	 * 
	 * @param command Command APDU
	 * @param usageQualifier Secure messaging transformation selector, a combination of SecureChannel.CPRO, .CENC, .RPRO and .RENC.
	 * @return Response APDU
	 * @throws CardTerminalException
	 */
	public ResponseAPDU sendCommandAPDU(CommandAPDU command, int usageQualifier)
			throws CardTerminalException {

		SecureChannelCredential secureChannelCredential = null;
		ResponseAPDU response; 

		if (credentialBag != null) {
			IsoCredentialStore ics = (IsoCredentialStore)credentialBag.getCredentialStore(null, IsoCredentialStore.class);

			if (ics != null) {
				secureChannelCredential = ics.getSecureChannelCredential(this.securityDomain);
			}
		}

		try {
			allocateCardChannel();
			CardChannel channel = getCardChannel();

			if (secureChannelCredential != null) {
				SlotChannel slc = channel.getSlotChannel();
				APDUTracer tracer = slc.getAPDUTracer();
				if ((tracer != null) && (command.getLength() > 5)) {
					tracer.traceCommandAPDU(slc, command);
				}

				SecureChannel secureChannel = secureChannelCredential.getSecureChannel();
				command = secureChannel.wrap(command, usageQualifier);
				response = channel.sendCommandAPDU(command);
				response = secureChannel.unwrap(response, usageQualifier);
				if ((tracer != null) && (response.getLength() > 2)) {
					tracer.traceResponseAPDU(slc, response);
				}
			} else {
				response = channel.sendCommandAPDU(command);
			}
		} finally {
			releaseCardChannel();
		}

		return response;
	}
}
