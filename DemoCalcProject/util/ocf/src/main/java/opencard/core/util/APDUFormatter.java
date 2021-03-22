/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2010 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  ---------
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package opencard.core.util;

import de.cardcontact.opencard.service.InstructionCodeTable;
import de.cardcontact.opencard.service.StatusWordTable;
import de.cardcontact.tlv.HexString;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;

public class APDUFormatter {

	/**
	 * Compose a string describing the command APDU.
	 *
	 * @param capdu the command APDU
	 * @return the string describing the command APDU
	 */
	public static String commandAPDUToString(CommandAPDU capdu) {
		StringBuffer sb = new StringBuffer(80);

		try {
			boolean extended = false;
			int len = capdu.getLength();
			byte[] buf = capdu.getBuffer();

			sb.append("C: ");
			sb.append(HexString.hexifyByteArray(buf, ' ', 4));
			sb.append(" - ");
			sb.append(InstructionCodeTable.instructionNameFromHeader(capdu.getBuffer()));

			len -= 4;
			int bodyoffset = 4;

			if (len > 0) {		// Case 2s, 2e, 3s, 3e, 4s, 4e
				int n = -1;

				if ((buf[bodyoffset] == 0) && (len > 1)) { // Extended length
					if (len >= 3) {	// Case 2e, 3e, 4e
						n = ((buf[bodyoffset + 1] & 0xFF) << 8) + (buf[bodyoffset + 2] & 0xFF);
						bodyoffset += 3;
						len -= 3;
						extended = true;
					} else {
						sb.append("Invalid extended length encoding for Lc\n");
						sb.append(HexString.dump(buf, bodyoffset, len, 16, 6));
					}
				} else {	// Case 2s, 3s, 4s
					n = buf[bodyoffset] & 0xFF;
					bodyoffset += 1;
					len -= 1;
				}

				if (len > 0) {	// Case 3s, 3e, 4s, 4e
					sb.append(" Lc=" + n + " " + (extended ? "Extended" : "") + "\n");
					if (n > len) {
						n = len;
					}
					int ins = capdu.getByte(1);
					if (((capdu.getByte(0) == 0x00) && ((ins == 0x20) || (ins == 0x24) || (ins == 0x2C)))
							|| ((capdu.getByte(0) == 0x80) && (ins == 0x52) && (capdu.getByte(2) == 0x00))) {
						sb.append("      *** Sensitive Information Removed ***");
					} else {
						sb.append(HexString.dump(buf, bodyoffset, n, 16, 6));
					}
					bodyoffset += n;
					len -= n;

					n = -1;
					if (len > 0) {	// Case 4s, 4e
						if (extended) {
							if (len >= 2) {
								n = ((buf[bodyoffset] & 0xFF) << 8) + (buf[bodyoffset + 1] & 0xFF);
								bodyoffset += 2;
								len -= 2;
							} else {
								sb.append("Invalid extended length encoding for Le\n");
								sb.append(HexString.dump(buf, bodyoffset, len, 16, 6));
							}
						} else {
							n = buf[bodyoffset] & 0xFF;
							bodyoffset += 1;
							len -= 1;
						}
					}
				}

				if (n >= 0) {
					sb.append("      Le=" + n + " " + (extended ? "Extended" : "") + "\n");
				}
				if (len > 0) {
					sb.append("Unexpected bytes:\n");
					sb.append(HexString.dump(buf, bodyoffset, len, 16, 6));
				}

				// Remove very last \n if any
				int l = sb.length() - 1;
				if (sb.charAt(l) == '\n') {
					sb.deleteCharAt(l);
				}
			}
		}
		catch(Exception e) {
			return "Error decoding APDU: " + e.getMessage();
		}

		return sb.toString();
	}



	/**
	 * Compose a string describing the response APDU.
	 *
	 * @param rapdu the response APDU
	 * @return the string describing the response APDU
	 */
	public static String responseAPDUToString(ResponseAPDU rapdu) {
		try {
			StringBuffer sb = new StringBuffer(80);
			int len = rapdu.getLength();
			byte[] buf = rapdu.getBuffer();

			sb.append("   R: ");
			sb.append(StatusWordTable.MessageForSW(rapdu.sw()));
			sb.append(" Lr=" + (len - 2));
			sb.append("\n");

			if (len > 2) {
				sb.append(HexString.dump(buf, 0, len - 2, 16, 6));
			}

			// Remove very last \n if any
			int l = sb.length() - 1;
			if (sb.charAt(l) == '\n') {
				sb.deleteCharAt(l);
			}
			return sb.toString();
		}
		catch(Exception e) {
			return ("Error decoding APDU: " + e.getMessage());
		}
	}
}
