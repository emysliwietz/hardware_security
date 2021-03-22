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

import de.cardcontact.opencard.service.isocard.IsoConstants;

/**
 * Decoder to visualize instruction codes
 * 
 * @author Andreas Schwier
 *
 */
public class InstructionCodeTable {



	/**
	 * Parse the INS byte and decode into a ISO 7816 command name
	 * 
	 * @param header Command APDU header
	 * 
	 * @return ISO 7816-4 command name
	 */
	public static String instructionNameFromHeader(byte[] header) {
		String s = "UNKNOWN_INS";

		if ((header[0] & 0xFF) == 0xFF) {		// Commands from PC/SC 2.01 Part 3 Synchronous storage cards
			switch(header[1]) {
			case IsoConstants.INS_GET_DATA:
				s = "GET DATA"; break;
			case IsoConstants.INS_LOAD_KEYS:
				s = "LOAD KEYS"; break;
			case IsoConstants.INS_INTAUTH:
				s = "AUTHENTICATE"; break;
			case IsoConstants.INS_GENERAL_AUTH1:
				s = "GENERAL AUTHENTICATE"; break;
			case IsoConstants.INS_VERIFY:
				s = "VERIFY"; break;
			case IsoConstants.INS_READ_BINARY:
				s = "READ BINARY"; break;
			case IsoConstants.INS_UPDATE_BINARY:
				s = "UPDATE BINARY"; break;
			}
		} else if ((header[0] & 0xFF) == 0x90) {
			switch(header[1]) {
			case IsoConstants.INS_CREDIT:
				s = "CREDIT"; break;
			case IsoConstants.INS_AUTHENTICATE:
				s = "AUTHENTICATE"; break;
			case IsoConstants.INS_AUTHENTICATE_ISO:
				s = "AUTHENTICATE ISO"; break;
			case IsoConstants.INS_LIMITED_CREDIT:
				s = "LIMITED CREDIT"; break;
			case IsoConstants.INS_WRITE__RECORD:
				s = "WRITE RECORD"; break;
			case IsoConstants.INS_WRITE_DATA:
				s = "WRITE DATA"; break;
			case IsoConstants.INS_GET_KEY_SETTINGS:
				s = "GET KEY SETTINGS"; break;
			case IsoConstants.INS_GET_CARD_UID:
				s = "GET CARD UID"; break;
			case IsoConstants.INS_CHANGE_KEY_SETTINGS:
				s = "CHANGE KEY SETTINGS"; break;
			case IsoConstants.INS_GET_VERSION:
				s = "GET VERSION"; break;
			case IsoConstants.INS_GET_KEY_VERSION:
				s = "GET KEY VERSION"; break;
			case IsoConstants.INS_SELECT_APPLICATION:
				s = "SELECT APPLICATION"; break;
			case IsoConstants.INS_SET_CONFIGURATION:
				s = "SET CONFIGURATION"; break;
			case IsoConstants.INS_CHANGE_FILE_SETTINGS:
				s = "CHANGE FILE SETTINGS"; break;
			case IsoConstants.INS_GET_ISO_FILE_IDS:
				s = "GET ISO FILE IDS"; break;
			case IsoConstants.INS_GET_APPLICATION_IDS:
				s = "GET APPLICATION IDS"; break;
			case IsoConstants.INS_GET_VALUE:
				s = "GET VALUE"; break;
			case IsoConstants.INS_GET_DF_NAMES:
				s = "GET DF NAMES"; break;
			case IsoConstants.INS_FREE_MEMORY:
				s = "FREE MEMORY"; break;
			case IsoConstants.INS_GET_FILE_IDS:
				s = "GET FILE IDS"; break;
			case IsoConstants.INS_ABORT_TRANSACTION:
				s = "ABORT TRANSACTION"; break;
			case IsoConstants.INS_AUTHENTICATE_AES:
				s = "AUTHENTICATE AES"; break;
			case IsoConstants.INS_NEXT_FRAME:
				s = "NEXT FRAME"; break;
			case IsoConstants.INS_READ__RECORD:
				s = "READ RECORD"; break;
			case IsoConstants.INS_READ_DATA:
				s = "READ DATA"; break;
			case IsoConstants.INS_CREATE_CYCLIC_RECORD_FILE:
				s = "CREATE CYCLIC RECORD FILE"; break;
			case IsoConstants.INS_CREATE_LINEAR_RECORD_FILE:
				s = "CREATE LINEAR RECORD FILE"; break;
			case IsoConstants.INS_CHANGE_KEY:
				s = "CHANGE KEY"; break;
			case IsoConstants.INS_COMMIT_TRANSACTION:
				s = "COMMIT TRANSACTION"; break;
			case IsoConstants.INS_CREATE_APPLICATION:
				s = "CREATE APPLICATION"; break;
			case IsoConstants.INS_CREATE_BACKUP_DATA_FILE:
				s = "CREATE BACKUP DATA FILE"; break;
			case IsoConstants.INS_CREATE_VALUE_FILE:
				s = "CREATE VALUE FILE"; break;
			case IsoConstants.INS_CREATE_STD_DATA_FILE:
				s = "CREATE STD DATA FILE"; break;
			case IsoConstants.INS_DELETE_APPLICATION:
				s = "DELETE APPLICATION"; break;
			case IsoConstants.INS_DEBIT:
				s = "DEBIT"; break;
			case IsoConstants.INS_DELETEFILE:
				s = "DELETE FILE"; break;
			case IsoConstants.INS_CLEAR_RECORD_FILE:
				s = "CLEAR RECORD FILE"; break;
			case IsoConstants.INS_GET_FILE_SETTINGS:
				s = "GET FILE SETTINGS"; break;
			case IsoConstants.INS_FORMAT:
				s = "FORMAT"; break;
			}
		} else if ((header[0] & 0x80) == 0x80) {
			switch(header[1]) {
			case IsoConstants.INS_INIT_UPDATE:
				s = "INITIALIZE UPDATE"; break;
			case IsoConstants.INS_MANAGE_PKA:
				s = "MANAGE PUBLIC KEY AUTHENTICATION"; break;
			case IsoConstants.INS_EXTAUTHENTICATE:
				s = "EXTERNAL AUTHENTICATE"; break;
			case IsoConstants.INS_PUT_KEY:
				s = "PUT KEY"; break;
			case IsoConstants.INS_STORE_DATA:
				s = "STORE DATA"; break;
			case IsoConstants.INS_DELETE:
				s = "DELETE"; break;
			case IsoConstants.INS_INSTALL:
				s = "INSTALL"; break;
			case IsoConstants.INS_LOAD:
				s = "LOAD"; break;
			case IsoConstants.INS_SET_STATUS:
				s = "SET STATUS"; break;
			case IsoConstants.INS_GET_STATUS:
				s = "GET STATUS"; break;
			case IsoConstants.INS_ENUM_OBJECTS:
				s = "ENUMERATE OBJECTS"; break;
			case IsoConstants.INS_ENCIPHER:
				s = "ENCIPHER"; break;
			case IsoConstants.INS_DECIPHER:
				s = "DECIPHER"; break;
			case IsoConstants.INS_SIGN:
				s = "SIGN"; break;
			case IsoConstants.INS_VERIFY_MAC:
				s = "VERIFY MAC"; break;
			case IsoConstants.INS_MANAGE_KEY_DOMAIN:
				s = "MANAGE KEY DOMAIN"; break;
			case IsoConstants.INS_GENERATE_SESSION_PIN:
				s = "GENERATE SESSION PIN"; break;
			case IsoConstants.INS_WRAP_KEY:
				s = "WRAP KEY"; break;
			case IsoConstants.INS_UNWRAP_KEY:
				s = "UNWRAP KEY"; break;
			case IsoConstants.INS_DERIVE_EC_KEY:
				s = "DERIVE EC KEY"; break;
			case IsoConstants.INS_DERIVE_SYMMETRIC_KEY:
				s = "DERIVE SYMMETRIC KEY"; break;
			}
		} else {
			switch(header[1] & ~1) {		// Unmask bit 0 for odd/even instruction bytes
			case IsoConstants.INS_DEACTIVATE_FILE:
				s = "DEACTIVATE FILE"; break;
			case IsoConstants.INS_DEACTIVATE_RECORD:
				s = "DEACTIVATE RECORD"; break;
			case IsoConstants.INS_ACTIVATE_RECORD:
				s = "ACTIVATE RECORD"; break;
			case IsoConstants.INS_ERASE_RECORD:
				s = "ERASE RECORD"; break;
			case IsoConstants.INS_ERASE_BINARY1:
				s = "ERASE BINARY 1"; break;
			case IsoConstants.INS_ERASE_BINARY2:
				s = "ERASE BINARY 1"; break;
			case IsoConstants.INS_PERFORM_SCQL_OP:
				s = "PERFORM SCQL OPERATION"; break;
			case IsoConstants.INS_PERFORM_TRANS_OP:
				s = "PERFORM TRANSACTION OPERATION"; break;
			case IsoConstants.INS_PERFORM_USER_OP:
				s = "PERFORM USER OPERATION"; break;
			case IsoConstants.INS_VERIFY:
				s = "VERIFY"; break;
			case IsoConstants.INS_MANAGE_SE:
				s = "MANAGE SECURITY ENVIRONMENT"; break;
			case IsoConstants.INS_CHANGE_CHV:
				s = "CHANGE REFERENCE DATA"; break;
			case IsoConstants.INS_DISABLE_CHV:
				s = "DISABLE VERIFICATION REQUIREMENT"; break;
			case IsoConstants.INS_ENABLE_CHV:
				s = "ENABLE VERIFICATION REQUIREMENT"; break;
			case IsoConstants.INS_PSO:
				switch(header[2]) {
				case IsoConstants.P1_PSO_HASH:
					s = "PSO: HASH"; break;
				case IsoConstants.P1_PSO_CDS:
					s = "PSO: COMPUTE DIGITAL SIGNATURE"; break;
					//			case IsoConstants.P1_PSO_CDS:
					//				s = "PSO: COMPUTE DIGITAL SIGNATURE"; break;
				case 0:
					switch(header[3]) {
					case IsoConstants.SM_VERIFY_CERT1:
					case IsoConstants.SM_VERIFY_CERT2:
						s = "PSO: VERIFY CERTIFICATE"; break;
					default: 
						s = "PERFORM SECURITY OPERATION"; break;
					}
					break;
				default: 
					s = "PERFORM SECURITY OPERATION"; break;
				}
				break;
			case IsoConstants.INS_UNBLOCK_CHV:
				s = "RESET RETRY COUNTER"; break;
			case IsoConstants.INS_ACTIVATE_FILE:
				s = "ACTIVATE FILE"; break;
			case IsoConstants.INS_GENERATE_KEYPAIR:
				s = "GENERATE ASYMMETRIC KEY PAIR"; break;
			case IsoConstants.INS_GENERATE_KEY:
				s = "GENERATE SYMMETRIC KEY"; break;
			case IsoConstants.INS_MANAGE_CHANNEL:
				s = "MANAGE CHANNEL"; break;
			case IsoConstants.INS_EXTAUTHENTICATE:
				s = "EXTERNAL AUTHENTICATE"; break;
			case IsoConstants.INS_GET_CHALLENGE:
				s = "GET CHALLENGE"; break;
			case IsoConstants.INS_GENERAL_AUTH1:
				s = "GENERAL AUTHENTICATE 1"; break;
			case IsoConstants.INS_GENERAL_AUTH2:
				s = "GENERAL AUTHENTICATE 2"; break;
			case IsoConstants.INS_INTAUTH:
				s = "INTERNAL AUTHENTICATE"; break;
			case IsoConstants.INS_SEARCH_BINARY1:
				s = "SEARCH BINARY 1"; break;
			case IsoConstants.INS_SEARCH_BINARY2:
				s = "SEARCH BINARY 2"; break;
			case IsoConstants.INS_SEARCH_RECORD:
				s = "SEARCH RECORD"; break;
			case IsoConstants.INS_SELECT_FILE:
				s = "SELECT"; break;
			case IsoConstants.INS_GENERATE_AC:
				s = "GENERATE AC"; break;
			case IsoConstants.INS_READ_BINARY:
				s = "READ BINARY"; break;
			case IsoConstants.INS_READ_RECORD:
				s = "READ RECORD"; break;
			case IsoConstants.INS_GET_RESPONSE:
				s = "GET RESPONSE"; break;
			case IsoConstants.INS_GET_DATA:
				s = "GET DATA"; break;
			case IsoConstants.INS_WRITE_BINARY:
				s = "WRITE BINARY"; break;
			case IsoConstants.INS_WRITE_RECORD:
				s = "WRITE RECORD"; break;
			case IsoConstants.INS_UPDATE_BINARY:
				s = "UPDATE BINARY"; break;
			case IsoConstants.INS_PUT_DATA:
				s = "PUT DATA"; break;
			case IsoConstants.INS_UPDATE_RECORD:
				s = "UPDATE RECORD"; break;
			case IsoConstants.INS_CREATE_FILE:
				s = "CREATE FILE"; break;
			case IsoConstants.INS_APPEND_RECORD:
				s = "APPEND RECORD"; break;
			case IsoConstants.INS_DELETE_FILE:
				s = "DELETE FILE"; break;
			case IsoConstants.INS_TERMINATE_DF:
				s = "TERMINATE DF"; break;
			case IsoConstants.INS_TERMINATE_EF:
				s = "TERMINATE EF"; break;
			case IsoConstants.INS_LOAD_APPLICATION:
				s = "LOAD APPLICATION"; break;
			case IsoConstants.INS_TERMINATE_CARD:
				s = "TERMINATE CARD USAGE"; break;
			}
		}
		return s;
	}
}
