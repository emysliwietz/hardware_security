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

package de.cardcontact.opencard.terminal.ctapi4ocf;

import opencard.core.terminal.CHVControl;
import opencard.core.terminal.CHVEncoder;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.terminal.SlotChannel;
import opencard.core.terminal.VerifiedAPDUInterface;
import opencard.opt.util.TLV;
import opencard.opt.util.Tag;

public class CTAPIWithKeyboardCardTerminal extends CTAPICardTerminal implements VerifiedAPDUInterface {

	protected CTAPIWithKeyboardCardTerminal(String name, String type, String device, String libname) throws CardTerminalException {
		super(name, type, device, libname);
	}

	public ResponseAPDU sendVerifiedCommandAPDU(SlotChannel chann, CommandAPDU capdu, CHVControl vc) throws CardTerminalException {
		CommandAPDU command = new CommandAPDU(128);

		command.append((byte)0x20);   // CLA
		command.append((byte)0x18);   // INS

		int slot = chann.getSlotNumber() + 1;

		command.append((byte)slot); // P1 - Functional Unit
		command.append((byte)0x00); // P2 - User authentication by PINPad

		command.append((byte)0x00); // Lc - need to fill that later

		byte[] tmp = new byte[capdu.getLength() + 2];

		if (vc.passwordEncoding().equals(CHVEncoder.STRING_ENCODING)) {
			tmp[0] |= 0x01;
		} else if (vc.passwordEncoding().equals(CHVEncoder.F2B_ENCODING)) {
			tmp[0] |= 0x02;
		} // Default is 00, which is BCD encoding

		/*
        CardTerminalIOControl io = vc.ioControl();
        if (io != null) {
            int ics = io.maxInputChars();
            tmp[0] |= (ics << 4) & 0xF0;
        }
		 */

		tmp[1] = (byte)(vc.passwordOffset() + 6);   // Offset in OCF is 0 based offset in data field
		// Offset in MKT is 1 based offset in APDU

		System.arraycopy(capdu.getBuffer(), 0, tmp, 2, capdu.getLength());

		TLV ctpdo = new TLV(new Tag(18, (byte)1, false), tmp);
		command.append(ctpdo.toBinary());

		String prompt = vc.prompt();
		if (prompt != null) {
			TLV dspdo = new TLV(new Tag(16, (byte)1, false), prompt.getBytes());
			command.append(dspdo.toBinary());
		}

		command.setByte(4, command.getLength() - 5);

		byte[] buf = new byte[2];
		char buflen = (char)buf.length;
		int res;

		synchronized (this) {
			res = CT.CT_Data(ctn, (byte) 1, (byte) 2, command.getBuffer(), buflen, buf);
		}

		if (res < 0) {
			throw (new CardTerminalException("CTAPICardTerminal: PERFORM VERIFICATION failed, ERROR=" + res));
		}

		return new ResponseAPDU(buf);
	}
}
