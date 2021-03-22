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
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

import de.cardcontact.tlv.ByteBuffer;
import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.ObjectIdentifier;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.Tag;



/**
 * This class contains the data for EC key pair generation.
 *
 * @author lew
 *
 */
public class SmartCardHSMECPrivateKeySpec extends SmartCardHSMPrivateKeySpec {

	public static final byte[] TA_ECDSA_SHA_256   = new byte[] { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03 };

	private ECParameterSpec domainParameter;
	private EllipticCurve curve;
	private ECFieldFp field;
	private int keySize;



	/**
	 * SmartCardHSMECCPrivateKeySpec constructor
	 *
	 * @param car The Certificate Authority Reference
	 * @param chr The Certificate Holder Reference
	 * @param params The domain parameter
	 */
	public SmartCardHSMECPrivateKeySpec(String car, String chr, AlgorithmParameterSpec params) {
		super(car, chr);

		if (params instanceof ECParameterSpec) {
			this.domainParameter = (ECParameterSpec)params;
		} else {
			try	{
				AlgorithmParameters parameters;
				parameters = AlgorithmParameters.getInstance("EC");
				parameters.init(params);
				this.domainParameter = parameters.getParameterSpec(ECParameterSpec.class);
			}
			catch(Exception e) {
				throw new IllegalArgumentException("Invalid domain parameter " + e.getLocalizedMessage());
			}
		}
		this.algorithm = TA_ECDSA_SHA_256;
		this.curve = this.domainParameter.getCurve();
		this.field = (ECFieldFp)curve.getField();
		this.keySize = field.getFieldSize();
	}



	/**
	 * SmartCardHSMECCPrivateKeySpec constructor
	 *
	 *
	 * @param params The domain parameter
	 */
	public SmartCardHSMECPrivateKeySpec(AlgorithmParameterSpec params) {
		this("UT-00000", "UT-00000", params);
	}



	/**
	 * @return The domain parameter
	 */
	public ECParameterSpec getECParameterSpec() {
		return this.domainParameter;
	}



	/**
	 * @return The key size
	 */
	public int getKeySize() {
		return keySize;
	}



	protected ConstructedTLV encodeKeyParams() {
		//Public Key
		ConstructedTLV puk = new ConstructedTLV(new Tag(0x49, Tag.APPLICATION, true));

		//Public Key Algorithm
		puk.add(new ObjectIdentifier(getAlgorithm()));

		//Prime modulus p
		ECField field = domainParameter.getCurve().getField();
		int keySize = field.getFieldSize();
		byte[] v = unsignedBigIntegerToByteArray(((ECFieldFp)field).getP(), keySize);
		puk.add(new PrimitiveTLV(new Tag(0x01, Tag.CONTEXT, false), v));

		//First coefficient a
		v = unsignedBigIntegerToByteArray(domainParameter.getCurve().getA(), keySize);
		puk.add(new PrimitiveTLV(new Tag(0x02, Tag.CONTEXT, false), v));

		//Second coefficient b
		v = unsignedBigIntegerToByteArray(domainParameter.getCurve().getB(), keySize);
		puk.add(new PrimitiveTLV(new Tag(0x03, Tag.CONTEXT, false), v));

		//Base point G
		ByteBuffer basePointG = new ByteBuffer();
		basePointG.append((byte)0x04);
		basePointG.append(unsignedBigIntegerToByteArray(domainParameter.getGenerator().getAffineX(), keySize));
		basePointG.append(unsignedBigIntegerToByteArray(domainParameter.getGenerator().getAffineY(), keySize));
		puk.add(new PrimitiveTLV(new Tag(0x04, Tag.CONTEXT, false), basePointG.getBytes()));

		//Order of the base point
		v = unsignedBigIntegerToByteArray(domainParameter.getOrder(), keySize);
		puk.add(new PrimitiveTLV(new Tag(0x05, Tag.CONTEXT, false), v));

		//Cofactor f
		byte [] cofactor = {(byte) domainParameter.getCofactor()};
		puk.add(new PrimitiveTLV(new Tag(0x07, Tag.CONTEXT, false), cofactor));

		return puk;
	}



	/**
	 * @return The encoded Base Point G
	 * @throws IOException
	 */
	public byte[] getBasePointG() throws IOException {
		ByteArrayOutputStream basePointG = new ByteArrayOutputStream();
		basePointG.write(0x04);
		basePointG.write(unsignedBigIntegerToByteArray(domainParameter.getGenerator().getAffineX(), keySize));
		basePointG.write(unsignedBigIntegerToByteArray(domainParameter.getGenerator().getAffineY(), keySize));
		return basePointG.toByteArray();
	}
}
