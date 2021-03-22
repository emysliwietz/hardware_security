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

import opencard.core.service.CardServiceException;
import opencard.core.terminal.CardTerminalException;

public interface DecipherCardService {



	public static byte RSA_DECRYPTION_PLAIN = 0x21;
	public static byte RSA_DECRYPTION_V15 = 0x22;
	public static byte RSA_DECRYPTION_OAEP = 0x23;



	/**
	 * The device performs a plain rsa decryption.
	 * 
	 * @param privateKey the private SmartCardHSMKey
	 * @param cryptogram 
	 * @return the plain text
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public byte[] decipher(SmartCardHSMKey privateKey, byte[] cryptogram)
	throws  CardTerminalException, CardServiceException;



	/**
	 * The device decrypts a cryptogram and returns the plain text.
	 * 
	 * @param privateKey the private SmartCardHSMKey
	 * @param cryptogram
	 * @param algorithmID one of RSA_DECRYPTION_Plain, RSA_DECRYPTION_V15 or RSA_DECRYPTION_OAEP
	 * @return the plain text
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public byte[] decipher(SmartCardHSMKey privateKey, byte[] cryptogram, byte algorithmID)
	throws  CardTerminalException, CardServiceException;



	/**
	 * The device calculates a shared secret point using an EC Diffie-Hellman
	 * operation. The public key of the sender must be provided as input to the command.
	 * The device returns the resulting point on the curve associated with the private key.
	 * 
	 * @param privateKey Key identifier of the SmartCardHSM private key
	 * @param pkComponents Concatenation of '04' || x || y point coordinates of ECC public Key
	 * @return Concatenation of '04' || x || y point coordinates on EC curve
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public byte[] performECCDH(SmartCardHSMKey privateKey, byte[] pkComponents)
	throws  CardTerminalException, CardServiceException;
}
