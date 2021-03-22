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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.TLVEncodingException;



/**
 * Encoder for DEVICE INITIALIZATION command data
 * 
 * @author lew
 *
 */
public class InitializeConfiguration {

	/** 
	 * Configuration Options 
	 * RESET RETRY COUNTER enabled by default
	 */
	//private short options = 0x0001;
	private byte[] options = new byte[] {0x00, 0x01};

	/** User PIN or Transport PIN */
	private byte[] initialPIN;

	/** Initialization Code */
	private byte[] initCode;

	/** Retry Counter Initial Value */
	private byte retryCounter = 3;

	/** Number of Device Key Encryption Key shares */
	private byte dkekShares = -1;

	/** Number of public keys for authentication (parameter m) */
	private byte numberOfAuthenticationKeys = 0;

	/** Threshold for public key authentication (parameter n) */
	private byte authenticationThreshold = 0;



	/**
	 * Create a new configuration with the given initialization code 
	 * and an enabled RESET RETRY COUNTER
	 * 
	 * @param initCode an 8 byte ASCII code
	 */
	public InitializeConfiguration(byte[] initCode) {
		setInitializationCode(initCode);
	}



	/**
	 * Set the initialization code
	 * 
	 * @param code an 8 byte ASCII code
	 */
	public void setInitializationCode(byte[] code) {
		if (code.length != 8) {
			throw new IllegalArgumentException("The initialization code must have a length of 8 byte");
		}

		this.initCode = code;
	}



	/**
	 * Set the user PIN or transport PIN
	 * 
	 * @param pin a 6 to 16 byte ASCII code
	 */
	public void setInitialPIN(byte[] pin) {
		if (pin.length < 6 || pin.length > 16) {
			throw new IllegalArgumentException("The initial PIN must range from 6 to 16 bytes");
		}

		this.initialPIN = pin;
	}



	/**
	 * Set the Retry Counter Initial Value.
	 * 
	 * The SmartCard-HSM enforces a retry counter <= 3 for PIN length 6
	 * The SmartCard-HSM enforces a retry counter <= 5 for PIN length 7
	 * The SmartCard-HSM enforces a retry counter <= 10 for PIN length larger than 7 
	 * 
	 * @param retryCounter in the range from 1 to 10
	 */
	public void setRetryCounterInitial(byte retryCounter) {
		if (retryCounter < 1 || retryCounter > 10) {
			throw new IllegalArgumentException("The retry counter must range from 1 to 10");
		}

		if (initialPIN != null) {
			if (initialPIN.length == 6 && retryCounter > 3) {
				throw new IllegalArgumentException("The SmartCard-HSM enforces a retry counter <= 3 for PIN length 6");
			} else if (initialPIN.length == 7 && retryCounter > 5) {
				throw new IllegalArgumentException("The SmartCard-HSM enforces a retry counter <= 5 for PIN length 7");
			} else if (initialPIN.length > 7 && retryCounter > 10) {
				throw new IllegalArgumentException("The SmartCard-HSM enforces a retry counter <= 10 for PIN length larger than 7");
			}
		}

		this.retryCounter = retryCounter;
	}



	/**
	 * Set the number of DKEK shares
	 * 
	 * @param keyshares number of DKEK shares
	 */
	public void setDKEKShares(byte keyshares) {
		this.dkekShares = keyshares;
	}



	/**
	 * Set parameter for public key authentication with n-of-m scheme, namely the values for n and m
	 * 
	 * @param requiredPublicKeysForAuthentication number of key that must be authenticated for access
	 * @param numberOfPublicKeys to register
	 */
	public void setPublicKeyAuthenticationParameter(byte requiredPublicKeysForAuthentication, byte numberOfPublicKeys) {
		if (numberOfPublicKeys < 1 || numberOfPublicKeys > 90) {
			throw new IllegalArgumentException("The value of numberOfPublicKeys must range from 1 to 90");
		}

		if (requiredPublicKeysForAuthentication < 1 || requiredPublicKeysForAuthentication > numberOfPublicKeys) {
			throw new IllegalArgumentException("The value of requiredPublicKeysForAuthentication must range from 1 to numberOfPublicKeys");
		}

		this.numberOfAuthenticationKeys = numberOfPublicKeys;
		this.authenticationThreshold = requiredPublicKeysForAuthentication;
	}



	/**
	 * Enable or disable the RESET RETRY COUNTER command.
	 * On default the RESET RETRY COUNTER is enabled.
	 * 
	 * @param enable true (default) to allow RESET RETRY COUNTER command, false otherwise.
	 */
	public void setResetRetryCounterMode(boolean enable) {
		this.options[1] = (byte) ((this.options[1] & 0xFE) + (enable ? 1 : 0));
	}



	/**
	 * Enable or disable transport PIN mode.
	 * On default transport PIN mode is disabled.
	 * 
	 * @param enable true (non-default) to set user PIN to transport state.
	 */
	public void setTransportPINMode(boolean enable) {
		this.options[1] = (byte) ((this.options[1] & 0xFD) + (enable ? 2 : 0));
	}



	/**
	 * Get C-Data for the INITIALIZE DEVICE APDU.
	 * 
	 * @return the C-Data
	 */
	public byte[] getCData() {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			bos.write(new PrimitiveTLV(0x80, this.options).getBytes());

			if (this.initialPIN != null) {
				bos.write(new PrimitiveTLV(0x81, this.initialPIN).getBytes());
			}

			bos.write(new PrimitiveTLV(0x82, this.initCode).getBytes());

			if (this.initialPIN != null) {
				bos.write(new PrimitiveTLV(0x91, new byte[] { this.retryCounter}).getBytes());
			}

			if (this.dkekShares != -1) {
				bos.write(new PrimitiveTLV(0x92, new byte[] { this.dkekShares }).getBytes());
			}

			if (this.numberOfAuthenticationKeys > 0) {
				PrimitiveTLV tlv = new PrimitiveTLV(0x93, new byte[] {this.numberOfAuthenticationKeys, this.authenticationThreshold}); 
				bos.write(tlv.getBytes());
			}
		} catch (IOException | TLVEncodingException e) {
			// ignore
		}

		return bos.toByteArray();
	}
}
