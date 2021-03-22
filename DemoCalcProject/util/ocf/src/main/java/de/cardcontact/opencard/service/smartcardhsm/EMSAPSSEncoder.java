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
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Implementation of EMSA-PSS encoding according to PKCS#1 V2.1 (RFC 3447)
 * 
 * @author Frank Thater
 */
public class EMSAPSSEncoder {

	private Random rng = new SecureRandom();
	private MessageDigest digest;
	private MGF1 mgf1;
	byte[] mHash;
	private int sLen = 0;
	public byte[] salt;
	private int hLen = 0;
	private int keySize;

	private final static byte TRAILER = (byte) 0xBC;

	public EMSAPSSEncoder(MessageDigest digest, int keySizeInBits) {
		this.hLen = digest.getDigestLength();
		this.digest = digest;
		this.mHash = new byte[(8 + hLen)];
		this.sLen = hLen;
		this.salt = new byte[sLen];
		this.mgf1 = new MGF1(digest);
		rng.nextBytes(this.salt);
		this.keySize = keySizeInBits - 1;
	}

	public byte[] encode(byte[] hash) throws IOException {

		short emLen = (short) ((short) (this.keySize + 7) >>> 3);

		byte[] H, DB;

		System.arraycopy(hash, 0, mHash, 8, hash.length);

		if (sLen > 0) {
			// Create the hash H of M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
			digest.update(mHash, (short) 0, (short) mHash.length);
			digest.update(salt, (short) 0, sLen);
			H = digest.digest();
		} else { // no salt
			// Create the hash H of M' = 0x00 00 00 00 00 00 00 00 || mHash
			digest.update(mHash, (short) 0, (short) mHash.length);
			H = digest.digest();
		}

		short maskLen = (short) (emLen - H.length - 1);
		DB = new byte[maskLen];

		// DB = PS || 0x01 || salt
		DB[(short) (maskLen - H.length - 1)] = (byte) 0x01; // Patch the byte at the correct position

		if (sLen > 0) {
			System.arraycopy(salt, (short) 0, DB, (short) (maskLen - H.length), H.length);
		}

		byte[] mask = mgf1.createMaskBuffer(H, maskLen);

		for (short i = 0; i < maskLen; i++) {
			DB[i] ^= mask[i];
		}

		// Set the leftmost bits of the leftmost octet in maskedDB to zero
		short bitmask = (short) 0x00FF;
		bitmask = (short) (bitmask >>> ((short) (emLen << 3) - keySize));
		DB[0] = (byte) (DB[0] & (byte) (bitmask & (byte) 0xFF));

		// Complete the DB buffer and create the output EM = maskedDB || H || Trailer
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(DB);
		bos.write(H);
		bos.write(TRAILER);

		return bos.toByteArray();
	}

	/**
	 * Generate a MGF1 mask according to PKCS#1 V1.5
	 * 
	 * @author fth
	 */
	private class MGF1 {

		/**
		 * Message digest to use
		 */
		MessageDigest digest;

		/**
		 * Expected length of the hash
		 */
		int hLen;

		/**
		 * Public constructor
		 * 
		 * @param digest
		 *            Instance of message digest algorithm to use
		 */
		private MGF1(MessageDigest digest) {
			this.digest = digest;
			this.hLen = digest.getDigestLength();
		}

		/**
		 * Generate the mask
		 * 
		 * @param maskLen
		 *            Length of the mask
		 * @throws IOException
		 */
		public byte[] createMaskBuffer(byte[] mgfSeed, short maskLen)
				throws IOException {

			byte[] C = new byte[4];
			byte[] tempBuffer;

			ByteArrayOutputStream bos = new ByteArrayOutputStream(maskLen);

			C[0] = 0x00;
			C[1] = 0x00;
			C[2] = 0x00;
			C[3] = 0x00;

			digest.reset();

			int counter = -1;

			short boundary = (short) ((short) (maskLen << 3) + (short) 7);
			boundary /= (short) (hLen << 3);

			// T = T || Hash (mgfSeed || C)
			while (++counter < boundary) {

				C[0] = (byte) (counter >>> 24);
				C[1] = (byte) (counter >>> 16);
				C[2] = (byte) (counter >>> 8);
				C[3] = (byte) counter;

				if (mgfSeed != null && mgfSeed.length > 0) {
					digest.update(mgfSeed, (short) 0, mgfSeed.length);
				}

				digest.update(C, (short) 0, (short) 4);
				tempBuffer = digest.digest();
				bos.write(tempBuffer);
			}

			// There are some bits left - hash again, but copy only the bytes
			// needed to fill up the mask
			boundary = (short) (maskLen - (counter * hLen));
			if (boundary > 0) {

				C[0] = (byte) (counter >>> 24);
				C[1] = (byte) (counter >>> 16);
				C[2] = (byte) (counter >>> 8);
				C[3] = (byte) counter;

				if (mgfSeed != null && mgfSeed.length > 0) {
					digest.update(mgfSeed, (short) 0, mgfSeed.length);
				}

				digest.update(C, (short) 0, (short) 4);
				tempBuffer = digest.digest();
				bos.write(tempBuffer, 0, boundary);
			}

			return bos.toByteArray();
		}
	}
}
