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

import opencard.core.service.CardServiceException;
import opencard.core.terminal.CHVControl;
import opencard.core.terminal.CardTerminalException;
import opencard.opt.security.CHVCardService;
import opencard.opt.security.SecurityDomain;

/**
 * Extend CHVCardService to allow an application to pass an CHVControl object
 * 
 * @author Andreas Schwier (www.cardcontact.de)
 */
public interface CHVCardServiceWithControl extends CHVCardService {

	public enum PasswordStatus {
		VERIFIED, NOTVERIFIED, BLOCKED, LASTTRY, NOTINITIALIZED, RETRYCOUNTERLOW, TRANSPORTMODE
	};

	/**
	 * Checks a password for card holder verification. Note that repeated
	 * verification of a wrong password will typically block that password on
	 * the smartcard.
	 * 
	 * @param domain
	 *            The security domain in which to verify the password.
	 *            <tt>null</tt> can be passed to refer to the root domain on the
	 *            smartcard. <br>
	 *            For file system based smartcards, the security domain is
	 *            specified as a <tt>CardFilePath</tt>. The root domain then
	 *            corresponds to the master file.
	 * @param number
	 *            The number of the password to verify. This parameter is used
	 *            to distinguish between different passwords in the same
	 *            security domain.
	 * @param cc
	 *            Control parameter defined by the application
	 * @param password
	 *            The password data that has to be verified. If the data is
	 *            supplied, it has to be padded to the length returned by
	 *            <tt>getPasswordLength</tt> for that password. <br>
	 *            <tt>null</tt> may be passed to indicate that this service
	 *            should use a protected PIN path facility, if available.
	 *            Alternatively, this service may query the password by some
	 *            other, implementation-dependend means. In any case, the
	 *            service implementation will require knowledge about the
	 *            encoding of the password data on the smartcard.
	 * 
	 * @exception CardServiceException
	 *                if this service encountered an error. In this context, it
	 *                is not considered an error if the password to be verified
	 *                is wrong. However, if the password is blocked on the
	 *                smartcard, an exception will be thrown.
	 * @exception CardTerminalException
	 *                if the underlying card terminal encountered an error when
	 *                communicating with the smartcard
	 */
	public boolean verifyPassword(SecurityDomain domain, int number,
			CHVControl cc, byte[] password) throws CardServiceException,
			CardTerminalException;

	/**
	 * Get the smartcard's password status.
	 * 
	 * @param domain
	 *            The security domain in which to verify the password.
	 *            <tt>null</tt> can be passed to refer to the root domain on the
	 *            smartcard. <br>
	 *            For file system based smartcards, the security domain is
	 *            specified as a <tt>CardFilePath</tt>. The root domain then
	 *            corresponds to the master file.
	 * @param number
	 *            The number of the password to verify. This parameter is used
	 *            to distinguish between different passwords in the same
	 *            security domain.
	 * @return The password status
	 * 
	 * @throws CardServiceException
	 *             if this service encountered an error.
	 * @throws CardTerminalException
	 *             if the underlying card terminal encountered an error when
	 *             communicating with the smartcard
	 */
	public PasswordStatus getPasswordStatus(SecurityDomain domain, int number)
			throws CardServiceException, CardTerminalException;
}
