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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.ctapi.CTAPI;
import de.cardcontact.ctapi.CTAPITerminal;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.Pollable;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.util.HexString;
import opencard.opt.terminal.TerminalCommand;



/**
 * Implements a CT-API card terminal for OCF.
 *
 */
public class CTAPICardTerminal extends CardTerminal implements Pollable, TerminalCommand {

	private final static Logger logger = LoggerFactory.getLogger(CTAPICardTerminal.class);

	private final static byte NOCARD = 0x00;
	private final static byte CARDIN = 0x01;
	private final static byte CARDDISCONNECTED = 0x03;
	private final static byte CARDCONNECTED = 0x05;

	public final static byte[] requestICC = { (byte) 0x20, (byte) 0x12,
		(byte) 0x01, (byte) 0x01, (byte) 0x00 };
	public final static byte[] getStatus = { (byte) 0x20, (byte) 0x13,
		(byte) 0x00, (byte) 0x80, (byte) 0x00 };

	protected boolean termopened;
	protected byte[] cardStatus;
	protected CardID[] cardIdTable;
	protected CTAPI CT;
	protected char ctn, pn;

	/** Determines if polling is used for this terminal */
	private boolean polling;
	private boolean processingAPDU = false;

	/**
	 * Create CTAPICardTerminal object
	 *
	 * @param name
	 * @param type
	 * @param device
	 * @param libname
	 * @throws CardTerminalException
	 */
	protected CTAPICardTerminal(String name, String type, String device, String libname) throws CardTerminalException {

		super(name, type, device);

		polling = !type.endsWith("-NOPOLL"); // Disable polling if type is "*-NOPOLL"

		termopened = false;
		CT = new CTAPI(libname);
		try {
			ctn = (char) Integer.decode(address).intValue();
		} catch (NumberFormatException nfe) {
			throw (new CardTerminalException(
					"CTAPICardTerminal: Invalid port address."));
		}
		pn = ctn;
	}



	/**
	 * Create CTAPICardTerminal object
	 *
	 * @param name
	 * @param type
	 * @param device
	 * @param libname
	 * @throws CardTerminalException
	 */
	protected CTAPICardTerminal(CTAPITerminal ctterm, String type) throws CardTerminalException {

		super(ctterm.getName(), type, "");

		polling = !type.endsWith("-NOPOLL"); // Disable polling if type is "*-NOPOLL"

		termopened = false;
		CT = ctterm.getCTAPI();
		ctn = pn = (char)ctterm.getPort();
	}



	/**
	 * Open card terminal connection
	 *
	 * Called from OCF during startup
	 *
	 */
	@Override
	public void open() throws CardTerminalException {
		int rc, len;
		byte[] newStatus;

		if (termopened == true)
			throw (new CardTerminalException(
					"CTAPICardTerminal: Already opened."));

		synchronized (this) {
			rc = CT.CT_Init(ctn, pn);
		}

		if (rc < 0)
			throw (new CardTerminalException(
					"CTAPICardTerminal: CT_Init failed with rc=" + rc));

		termopened = true;

		// Get status to determine number of slots
		newStatus = getStatus();

		len = newStatus.length;
		addSlots(len);
		cardStatus = new byte[len];
		cardIdTable = new CardID[len];

		if (polling) {
			CardTerminalRegistry.getRegistry().addPollable(this);
		}
	}



	/**
	 * Close used resources
	 *
	 */
	@Override
	public void close() throws CardTerminalException {

		if (termopened == false)
			throw (new CardTerminalException(
					"CTAPICardTerminal: Terminal not opened."));

		cardRemoved(0);
		if (polling) {
			CardTerminalRegistry.getRegistry().removePollable(this);
		}

		synchronized (this) {
			int rc = CT.CT_Close(ctn);
			if ((rc == 0) || (rc == -8))
				termopened = false;
		}
		if (termopened == true) {
			CardTerminalRegistry.getRegistry().addPollable(this);
			throw (new CardTerminalException(
					"CTAPICardTerminal: CT_close failed."));
		}
	}



	/**
	 * Return true is slot contains a card
	 *
	 * @param slot Slot number starting at 0
	 */
	@Override
	public boolean isCardPresent(int slot) throws CardTerminalException {
		if (termopened == false)
			throw (new CardTerminalException(
					"CTAPICardTerminal: isCardPresent(), Terminal not opened."));

		if (!polling) {
			poll();
		}
		return cardIdTable[slot] != null;
	}



	/**
	 * Return ATR for card in slot
	 *
	 */
	@Override
	public CardID getCardID(int slot) throws CardTerminalException {
		if (termopened == false)
			throw (new CardTerminalException(
					"CTAPICardTerminal: getCardID(), Terminal not opened."));

		return cardIdTable[slot];
	}



	/**
	 * Reset card in slot and return ATR
	 */
	@Override
	protected CardID internalReset(int slot, int ms)
			throws CardTerminalException {
		byte[] response;
		byte[] buf = new byte[258];
		int res;
		byte[] com = { (byte) 0x20, (byte) 0x11, (byte) (slot + 1),
				(byte) 0x01, (byte) 0x00 };
		char buflen;
		CardID cid;

		if (termopened == false)
			throw (new CardTerminalException(
					"CTAPICardTerminal: internalReset(), Terminal not opened."));

		cardIdTable[slot] = null;

		buflen = (char) buf.length;
		synchronized (this) {
			res = CT.CT_Data(ctn, (byte) 1, (byte) 2, com,
					buflen, buf);
		}

		logger.debug("[internalReset] CT_Data rc=" + res + " returns " + HexString.hexify(buf));

		if (res < 0)
			throw (new CardTerminalException(
					"CTAPICardTerminal: internalReset(), ERROR=" + res));

		if ((res < 2) || ((buf[res - 2] & 0xFF) != 0x90))
			throw (new CardTerminalException(
					"CTAPICardTerminal: internalReset(), No card inserted."));

		response = new byte[res - 2];
		System.arraycopy(buf, 0, response, 0, res - 2);

		cid = new CardID(this, slot, response);

		cardIdTable[slot] = cid;

		return cid;
	}



	/**
	 * Send APDU to card in slot
	 *
	 */
	@Override
	protected ResponseAPDU internalSendAPDU(int slot, CommandAPDU capdu, int ms)
			throws CardTerminalException {
		byte[] response;
		char resplen;
		byte fu;
		byte[] com;
		byte[] resp = new byte[16386];
		int res;

		if (termopened == false)
			throw (new CardTerminalException(
					"CTAPICardTerminal: internalSendAPDU(), Terminal not opened."));

		com = capdu.getBytes();

		resplen = (char) resp.length;

		fu = 0;
		if (slot > 0) {
			fu = (byte) (1 + slot);
		}
		synchronized (this) {
			processingAPDU = true;
			res = CT.CT_Data(ctn, fu, (byte) 2, com, resplen, resp);
			processingAPDU = false;
		}

		if (res <= 0) {
			throw (new CardTerminalException(
					"CTAPICardTerminal: internalSendAPDU(), Error=" + res));
		}

		response = new byte[res];
		System.arraycopy(resp, 0, response, 0, res);
		return new ResponseAPDU(response);
	}



	/**
	 * Poll for status change
	 *
	 * This is called from OCF every second
	 *
	 */
	@Override
	public void poll() throws CardTerminalException {

		int i;
		boolean updateStatus = false;
		byte[] newStatus;

		if (processingAPDU) {
			return;
		}

		newStatus = getStatus();

		for (i = 0; i < newStatus.length; i++) {
			//			ctracer.debug("poll", "Status " + newStatus[i] + " on slot " + i);
			if (newStatus[i] != cardStatus[i]) { // Status change
				//				ctracer.debug("poll","Status change " + newStatus[i] + " on slot " + i);
				if (newStatus[i] == NOCARD) { // Card removed
					cardIdTable[i] = null;
					cardStatus[i] = NOCARD;
					cardRemoved(i);
				} else { // Something else happend
					try {
						internalReset(i, 0);
						cardInserted(i);
					} catch (CardTerminalException e) {
						// System.out.println(e);
						// Do nothing
					}
					updateStatus = true;
				}
			}
		}
		if (updateStatus) { // Update status of all slots
			cardStatus = getStatus();
		}
	}



	/**
	 * Send a control command to the terminal
	 *
	 */
	@Override
	public byte[] sendTerminalCommand(byte[] com) throws CardTerminalException {
		byte[] response;
		byte[] resp;
		char buflen;
		int res;

		if (termopened == false)
			throw (new CardTerminalException(
					"CTAPICardTerminal: sendTerminalCommand(), Terminal not opened."));

		resp = new byte[258];
		buflen = (char) resp.length;

		synchronized (this) {
			res = CT.CT_Data(ctn, (byte) 1, (byte) 2, com,
					buflen, resp);
		}

		if (res < 2)
			throw (new CardTerminalException(
					"CTAPICardTerminal: internalSendAPDU(), ERROR!"));

		response = new byte[res];
		System.arraycopy(resp, 0, response, 0, res);

		return response;
	}



	/**
	 * Issue STATUS command to query status of card reader slots
	 *
	 * @return Byte array of slot status as returned by STATUS command
	 *
	 * @throws CardTerminalException
	 */
	public byte[] getStatus() throws CardTerminalException {
		byte[] buf = new byte[258];
		char lenbuf = (char) buf.length;
		int i, len;

		synchronized (this) {
			len = CT.CT_Data(ctn, (byte) 1, (byte) 2, getStatus, lenbuf, buf);
		}

		if (len <= 0) {
			throw (new CardTerminalException(
					"CTAPICardTerminal: GetStatus() failed"));
		}

		i = 0;
		if (buf[0] == (byte) 0x80) {
			len = buf[1];
			i += 2;
		} else {
			len -= 2;
		}

		byte[] response = new byte[len];
		System.arraycopy(buf, i, response, 0, len);
		return response;
	}
}
