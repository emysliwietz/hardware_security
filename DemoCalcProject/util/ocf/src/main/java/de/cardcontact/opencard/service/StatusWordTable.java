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

package de.cardcontact.opencard.service;

import opencard.core.util.HexString;
import de.cardcontact.opencard.service.isocard.IsoConstants;

/**
 * List of status words and their meaning
 * 
 * @author Andreas Schwier (info@cardcontact.de)
 */
public class StatusWordTable {
	public static String StringForSW(int sw) {
		String str = null;

		if ((sw & 0xFFF0) == IsoConstants.RC_WARNINGCOUNT) {
			str = "Warning processing: Counter at " + (sw & 0xF);
		} else {
			switch (sw & 0xFF00) {
			case IsoConstants.RC_OK:
				str = "Normal processing: No error";
				break;
			case (IsoConstants.RC_OKMOREDATA << 8):
				str = "Normal processing: " + (sw & 0xFF)
				+ " additional bytes available";
			break;
			case (IsoConstants.RC_INVLE << 8):
				str = "Checking error: Invalid Le, " + (sw & 0xFF)
				+ " bytes are available";
			break;
			case (IsoConstants.RC_INVINS << 8):
				str = "Checking error: Invalid instruction (" + (sw & 0xFF)
				+ ")";
			break;
			case (IsoConstants.RC_INVLEN << 8):
				str = "Checking error: Wrong length";
			break;
			default:
				switch (sw) {

				case IsoConstants.RC_EOF:
					str = "Warning processing: End of file reached before reading Ne bytes ";
					break;
				case IsoConstants.RC_INVFILE:
					str = "Warning processing: Selected file deactivated";
					break;
				case IsoConstants.RC_WARNINGNVCHG:
					str = "Warning processing: State of non-volatile memory changed";
					break;

				case IsoConstants.RC_CLANOTSUPPORTED:
					str = "Checking error: Function in CLA byte not supported";
					break;
				case IsoConstants.RC_LCNOTSUPPORTED:
					str = "Checking error: Logical channel not supported";
					break;
				case IsoConstants.RC_SMNOTSUPPORTED:
					str = "Checking error: Secure Messaging not supported";
					break;
				case IsoConstants.RC_LASTCMDEXPECTED:
					str = "Checking error: Last command of the chain expected";
					break;
				case IsoConstants.RC_CHAINNOTSUPPORTED:
					str = "Checking error: Command chaining not supported";
					break;

				case IsoConstants.RC_COMNOTALLOWED:
					str = "Checking error: Command not allowed";
					break;
				case IsoConstants.RC_COMINCOMPATIBLE:
					str = "Checking error: Command incompatible with file structure";
					break;
				case IsoConstants.RC_SECSTATNOTSAT:
					str = "Checking error: Security condition not satisfied";
					break;
				case IsoConstants.RC_AUTHMETHLOCKED:
					str = "Checking error: Authentication method locked";
					break;
				case IsoConstants.RC_REFDATANOTUSABLE:
					str = "Checking error: Reference data not usable";
					break;
				case IsoConstants.RC_CONDOFUSENOTSAT:
					str = "Checking error: Condition of use not satisfied";
					break;
				case IsoConstants.RC_COMNOTALLOWNOEF:
					str = "Checking error: Command not allowed (no current EF)";
					break;
				case IsoConstants.RC_SMOBJMISSING:
					str = "Checking error: Expected secure messaging object missing";
					break;
				case IsoConstants.RC_INCSMDATAOBJECT:
					str = "Checking error: Incorrect secure messaging data object";
					break;

				case IsoConstants.RC_INVPARA:
					str = "Checking error: Wrong parameter P1-P2";
					break;
				case IsoConstants.RC_INVDATA:
					str = "Checking error: Incorrect parameter in the command data field";
					break;
				case IsoConstants.RC_FUNCNOTSUPPORTED:
					str = "Checking error: Function not supported";
					break;
				case IsoConstants.RC_FILENOTFOUND:
					str = "Checking error: File not found";
					break;
				case IsoConstants.RC_RECORDNOTFOUND:
					str = "Checking error: Record not found";
					break;
				case IsoConstants.RC_OUTOFMEMORY:
					str = "Checking error: Not enough memory space in the file";
					break;
				case IsoConstants.RC_INVLCTLV:
					str = "Checking error: Nc inconsistent with TLV structure";
					break;
				case IsoConstants.RC_INCP1P2:
					str = "Checking error: Incorrect P1-P2";
					break;
				case IsoConstants.RC_INVLC:
					str = "Checking error: Lc inconsistent with P1-P2";
					break;
				case IsoConstants.RC_RDNOTFOUND:
					str = "Checking error: Reference data not found";
					break;
				case IsoConstants.RC_FILEEXISTS:
					str = "Checking error: File already exists";
					break;
				case IsoConstants.RC_DFNAMEEXISTS:
					str = "Checking error: DF name already exists";
					break;

				case IsoConstants.RC_INVP1P2:
					str = "Checking error: Wrong parameter P1-P2";
					break;

				case IsoConstants.RC_INVCLA:
					str = "Checking error: Class not supported";
					break;

				case IsoConstants.RC_GENERALERROR:
					str = "Checking error: No precise diagnosis";
					break;

				}
			}
		}
		return str;
	}

	public static String MessageForSW(int sw) {
		String str = StringForSW(sw);

		if (str == null) {
			return ("SW1/SW2=" + HexString.hexifyShort((short) sw));
		} else {
			return ("SW1/SW2=" + HexString.hexifyShort((short) sw) + " (" + str + ")");
		}
	}
}
