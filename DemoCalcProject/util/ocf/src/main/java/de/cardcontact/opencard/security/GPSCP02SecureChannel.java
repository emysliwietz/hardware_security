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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import opencard.core.service.CardServiceInvalidParameterException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;

/**
 * Basic implementation for SCP 02 secure channel according to GP 2.1.1
 * 
 * This implementation supports the following implementation options:
 * 
 * "i" = '15': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption for C-MAC session, 
 *             3 Secure Channel Keys, unspecified card challenge generation method, no R-MAC; 
 *             
 * "i" = '55': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption for C-MAC session, 
 *             3 Secure Channel Keys, well-known pseudo-random algorithm (card challenge), no R-MAC
 * 
 * @author Frank Thater
 */

public class GPSCP02SecureChannel implements SecureChannel {

	/**
	 * Supported values for the "i" parameter ("i" = '15' and "i" = '55')
	 */
	public final static byte THREE_SECURE_CHANNEL_BASE_KEYS = 0x01;
	public final static byte CMAC_ON_MODIFIED_APDU = 0x00;
	public final static byte INITIATION_MODE_EXPLICIT = 0x04;
	public final static byte ICV_SET_TO_ZERO = 0x00;
	public final static byte ICV_ENCRYPTION_FOR_CMAC_SESSION = 0x10;
	public final static byte NO_RMAC_SUPPORT = 0x00;
	public final static byte WELL_KNOWN_PSEUDO_RANDOM_ALGORITHM = 0x40;
	public final static byte UNSPECIFIED_CARD_CHALLENGE_GENERATION = 0x00;

	/**
	 * Supported security levels
	 */

	public final static byte NONE = 0x00;
	public final static byte C_MAC = 0x01;
	public final static byte C_MAC_AND_C_ENC = 0x03;

	protected String provider;
	private Key senc;
	private Key smac;
	private Key dek;
	private byte[] iv = new byte[8];
	private byte securitylevel = NONE;    

	private Mac mac = null;
	private Cipher singleDES = null;
	private Cipher tripleDES = null;

	private final static byte[] ZERO_ICV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	private final static byte[] ISO_PADDING = {(byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	/**
	 * Create initialized secure channel object
	 * 
	 * @param provider Cryptographic service provider for JCE
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchPaddingException 
	 * 
	 */
	public GPSCP02SecureChannel(Key senc, Key smac, Key dek, byte[] iv, byte securityLevel, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		this.provider = provider;
		this.senc = senc;
		this.smac = smac;
		this.dek = dek;
		this.securitylevel = securityLevel;
		System.arraycopy(iv, 0, this.iv, 0, 8);

		mac = Mac.getInstance("ISO9797ALG3Mac", provider);
		singleDES = Cipher.getInstance("DES/CBC/NoPadding", provider);
		tripleDES = Cipher.getInstance("DESede/CBC/NoPadding", provider);		
	}



	public ResponseAPDU unwrap(ResponseAPDU apduToUnwrap, int usageQualifier) {
		return apduToUnwrap; // nothing to do - there is no R_MAC
	}



	public CommandAPDU wrap(CommandAPDU apduToWrap, int usageQualifier) {

		if (this.securitylevel == NONE) { // Do nothing
			return apduToWrap;
		}

		if (apduToWrap.getLength() >= 248) {
			throw new CardServiceInvalidParameterException("Length of C-Data must not exceed 247 in C_MAC mode");
		}

		byte[] raw_apdu = apduToWrap.getBytes();

		byte le = -1;
		short lc = 0;

		// By now we only support short APDUs		
		if (raw_apdu.length == 4) { // Case 1

		} else if (raw_apdu.length == 5) { // Case 2
			le = raw_apdu[4];

		} else if (raw_apdu.length >= 6) { // Case 3
			lc = (short) (raw_apdu[4] & 0x00FF);

			if (raw_apdu.length - lc - 4 > 0) { // Case 4
				le = raw_apdu[raw_apdu.length - 1];
			}			
		}

		int paddingRequired = (8 - ((5 + lc) % 8)); // Determine the number of needed padding bytes
		if (paddingRequired == 0) { // Force ISO padding
			paddingRequired = 8;
		}

		// Allocate new buffer for patched APDU
		byte[] patched_apdu = new byte[5 + lc + paddingRequired];
		patched_apdu[0] = (byte) (raw_apdu[0] | 0x04);
		patched_apdu[1] = raw_apdu[1];
		patched_apdu[2] = raw_apdu[2];
		patched_apdu[3] = raw_apdu[3];
		patched_apdu[4] = (byte) (lc + 8); // Adjust Lc
		if (lc > (byte) 0x00) {			
			System.arraycopy(raw_apdu, 5, patched_apdu, 5, lc); // Copy the data block (if present)
			System.arraycopy(ISO_PADDING, 0, patched_apdu, 5 + lc, paddingRequired);
		} else {
			System.arraycopy(ISO_PADDING, 0, patched_apdu, 5, paddingRequired);
		}

		try {

			// Encrypt the ICV using single DES/CBC/NoPadding with the first half of SMAC			
			byte[] sessionSMACvalue = new byte[8];
			System.arraycopy(this.smac.getEncoded(), 0, sessionSMACvalue, 0, 8);

			SecretKey keySpec = new SecretKeySpec(sessionSMACvalue, "DES");

			singleDES.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(ZERO_ICV));
			byte[] enc_icv = singleDES.doFinal(this.iv);

			mac.init(this.smac, new IvParameterSpec(enc_icv));

			this.iv = mac.doFinal(patched_apdu);

		} catch (InvalidKeyException e) {
			throw new CardServiceInvalidParameterException("Wrong key for MAC calculation : " + e.getLocalizedMessage());			
		} catch (InvalidAlgorithmParameterException e) {
			throw new CardServiceInvalidParameterException("Invalid algorithm parameter for MAC calculation : " + e.getLocalizedMessage());		
		} catch (IllegalStateException e) {
			throw new CardServiceInvalidParameterException("Illegal state for MAC calculation : " + e.getLocalizedMessage());		
		} catch (IllegalBlockSizeException e) {
			throw new CardServiceInvalidParameterException("Illegal block size for MAC calculation : " + e.getLocalizedMessage());		
		} catch (BadPaddingException e) {
			throw new CardServiceInvalidParameterException("Bad padding for MAC calculation : " + e.getLocalizedMessage());		
		}

		CommandAPDU patchedApdu = new CommandAPDU(262);
		byte[] apdu = new byte[5];
		System.arraycopy(patched_apdu, 0, apdu, 0, 5);		

		if (this.securitylevel == C_MAC_AND_C_ENC) {

			if (lc > 0) {

				if (lc >= 240) {
					throw new CardServiceInvalidParameterException("Length of C-Data must not exceed 239 in C_MAC_AND_C_ENC mode");
				}

				try {
					paddingRequired = (8 - (lc % 8)); // Determine the number of needed padding bytes

					if (paddingRequired == 0) { // Force ISO padding
						paddingRequired = 8;
					}

					ByteArrayOutputStream bos = new ByteArrayOutputStream();

					tripleDES.init(Cipher.ENCRYPT_MODE, this.senc, new IvParameterSpec(ZERO_ICV));
					byte[] r = tripleDES.update(raw_apdu, 5, lc);
					if (r != null) {
						bos.write(r);
					}
					r = tripleDES.update(ISO_PADDING, 0, paddingRequired);
					if (r != null) {
						bos.write(r);
					}
					r = tripleDES.doFinal();
					if (r != null) {
						bos.write(r);
					}

					byte[] encryptedData = bos.toByteArray();

					apdu[4] = (byte) (encryptedData.length + 8);
					patchedApdu.append(apdu);
					patchedApdu.append(encryptedData);

				} catch (InvalidKeyException e) {
					throw new CardServiceInvalidParameterException("Wrong key for ENC : " + e.getLocalizedMessage());		
				} catch (IllegalBlockSizeException e) {
					throw new CardServiceInvalidParameterException("Illegal block size for ENC : " + e.getLocalizedMessage());	
				} catch (BadPaddingException e) {
					throw new CardServiceInvalidParameterException("Bad padding for ENC : " + e.getLocalizedMessage());	
				} catch (InvalidAlgorithmParameterException e) {
					throw new CardServiceInvalidParameterException("Invalid algorithm parameter for ENC : " + e.getLocalizedMessage());	
				} catch (IOException e) {
					throw new CardServiceInvalidParameterException("I/O error during encryption : " + e.getLocalizedMessage());	
				}

			} else {
				patchedApdu.append(apdu); // add APDU header
			}

		} else {
			patchedApdu.append(apdu); // add APDU header

			if (lc > 0) {
				byte[] data = new byte[lc];
				System.arraycopy(raw_apdu, 5, data, 0, lc);
				patchedApdu.append(data);
			}					
		}

		patchedApdu.append(this.iv);

		if (le != -1) {
			patchedApdu.append(le);
		}

		return patchedApdu;
	}



	public static boolean scpOptionsSupported(byte scp, byte options) {
		if (scp == 0x02 && (options == 0x15 || options == 0x55)) {
			return true;
		} 

		return false;
	}
}
