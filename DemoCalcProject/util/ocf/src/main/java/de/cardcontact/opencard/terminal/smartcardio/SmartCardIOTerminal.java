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

package de.cardcontact.opencard.terminal.smartcardio;

import java.util.Arrays;
import java.util.Properties;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.opencard.utils.Util;
import opencard.core.terminal.CHVControl;
import opencard.core.terminal.CHVEncoder;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardNotPresentException;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ExtendedVerifiedAPDUInterface;
import opencard.core.terminal.Pollable;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.terminal.SlotChannel;
import opencard.opt.terminal.TerminalCommand;

/**
 * Implements a wrapper card terminal for access to smart card with the javax.smartcardio interface.
 */
public class SmartCardIOTerminal extends CardTerminal implements TerminalCommand, Pollable, ExtendedVerifiedAPDUInterface {

	private final static Logger logger = LoggerFactory.getLogger(SmartCardIOTerminal.class);

	private boolean polling;
	private javax.smartcardio.CardTerminal ct;
	private javax.smartcardio.Card card = null;

	/** The state of this card terminal. */
	private boolean closed;

	/** Is a card inserted currently? */
	private boolean cardInserted;



	public SmartCardIOTerminal(String name, String type, String address, javax.smartcardio.CardTerminal ct) throws CardTerminalException {

		super(name, type, address);

		polling = !type.endsWith("-NOPOLL");	// Disable polling if type is "*-NOPOLL"

		this.ct = ct;
		this.card = null;
		addSlots(1);
	}



	@Override
	protected Properties internalFeatures(Properties features) {
		if (this.name.startsWith("Secure Flash Card")) {
			features.put("maxCAPDUSize", "478");
			features.put("maxRAPDUSize", "506");
		} else if (this.name.startsWith("REINER SCT cyberJack")) {
			features.put("maxCAPDUSize", "1014");
			features.put("maxRAPDUSize", "1014");
		}
		return features;
	}



	@Override
	public void open() throws CardTerminalException {

		if (polling) {
			CardTerminalRegistry.getRegistry().addPollable(this);
		}
		closed = false;
		cardInserted = isCardPresent(0);
	}



	@Override
	public void close() throws CardTerminalException {

		try	{
			disconnect(false);
		}
		catch (CardTerminalException cte) {
			// Ignore, can happen if reader was removed
		}
		cardRemoved(0);
		if (polling) {
			CardTerminalRegistry.getRegistry().removePollable(this);
		}
		closed = true;
	}



	@Override
	public CardID getCardID(int slotID) throws CardTerminalException {

		if (!isCardPresent(slotID)) {
			logger.debug("[getCardID] no card in reader");
			return null;
		}
		connect();

		CardID cardid = new CardID(this, slotID, this.card.getATR().getBytes());
		logger.debug("[getCardID] CardID: " + cardid);

		return cardid;
	}



	@Override
	protected CardID internalReset(int slot, int ms) throws CardTerminalException {

		disconnect(true);
		return getCardID(slot);
	}



	@Override
	protected CardID internalReset(int slot, boolean warm) throws CardTerminalException {

		disconnect(true);
		return getCardID(slot);
	}



	@Override
	protected ResponseAPDU internalSendAPDU(int slot, CommandAPDU capdu, int ms) throws CardTerminalException {

		connect();
		byte[] apdu = capdu.getBytes();
		javax.smartcardio.CommandAPDU xcapdu = new javax.smartcardio.CommandAPDU(apdu);

		Arrays.fill(apdu, (byte)0);
		capdu.clear();			// Clear sensitive data

		CardChannel ch = this.card.getBasicChannel();
		javax.smartcardio.ResponseAPDU xrapdu;

		try	{
			xrapdu = ch.transmit(xcapdu);
		}
		catch(CardException ce) {
			logger.error("[internalSendAPDU]"+ce);
			this.card = null;

			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
			}

			if (isCardPresent(slot)) {
				throw new CardTerminalException("CardException in transmit(): " + ce.getMessage());
			} else {
				throw new CardNotPresentException("Card removed", this, slot);
			}
		}

		return new ResponseAPDU(xrapdu.getBytes());
	}



	@Override
	public boolean isCardPresent(int slotID) throws CardTerminalException {
		boolean cardPresent;

		try	{
			cardPresent = ct.isCardPresent();
		}
		catch(CardException ce) {
			logger.error("[isCardPresent]"+ce);
			return false;
		}

		if (!cardPresent) {
			card = null;
		}
		return cardPresent;
	}



	/**
	 * Send control command to terminal.
	 *
	 * The first four byte encode the PC/SC Control Code.
	 *
	 * @param cmd the command data
	 * @return the response data
	 */
	@Override
	public byte[] sendTerminalCommand(byte[] cmd) throws CardTerminalException {
		int c = 0;
		int i = 0;

		for (; (i < cmd.length) && (i < 4); i++) {
			c <<= 8;
			c |= cmd[i] & 0xFF;
		}

		byte[] cmddata = new byte[cmd.length - i];
		System.arraycopy(cmd, i, cmddata, 0, cmd.length - i);

		byte[] resdata = null;

		try	{
			resdata = this.card.transmitControlCommand(c, cmddata);
		}
		catch(CardException ce) {
			logger.error("[sendTerminalCommand]"+ce);
			throw new CardTerminalException("CardException in sendTerminalCommand(): " + ce.getMessage());
		}
		return resdata;
	}



	@Override
	public void poll() throws CardTerminalException {

		if (!closed && polling) {
			try {
				boolean newStatus = isCardPresent(0);
				if (cardInserted != newStatus) {
					logger.debug("[poll] status change");
					cardInserted = !cardInserted;
					// ... notify listeners
					if (cardInserted) {
						cardInserted(0);
					} else {
						cardRemoved(0);
					}
				}
			}
			catch (CardTerminalException cte) {
				logger.debug("[poll]"+cte);

				// make sure the CardTerminalException is
				// propagated to listeners waiting for a card
				cardInserted(0);
			}
		}
	}



	/**
	 * Connect to card, first with T=1 then with any protocol
	 *
	 */
	private void connect() throws CardTerminalException {

		if (this.card != null) {
			return;
		}
		boolean oldpolling = polling;
		try	{
			polling = false;
			this.card = ct.connect("T=1");
		}
		catch(CardException ce) {
			logger.debug("[connect] second connect due to"+ce);
			try	{
				this.card = ct.connect("*");
			}
			catch(CardException nce) {
				logger.error("[connect] final connect failed"+nce);
				throw new CardTerminalException("Error connecting to card: " + nce.getMessage());
			}
		} finally {
			polling = oldpolling;
		}
		logger.debug("[connect]"+this.card.getProtocol());
	}



	/**
	 * Disconnect from card
	 *
	 * @param reset reset card if set to true
	 * @throws CardTerminalException
	 */
	private void disconnect(boolean reset) throws CardTerminalException {

		if (this.card != null) {
			try	{
				// Up to JDK 7u72 and JDK 8u20 card.disconnect had an inverse logic bug: false means reset, true means leave card
				// https://bugs.openjdk.java.net/browse/JDK-8050495#comment-13559746
				// With the switch to JDK8, the default behaviour has changed

				String version = java.lang.System.getProperty("java.version");
				if (version.startsWith("1.7")) {
					this.card.disconnect(!reset);
				} else {
					this.card.disconnect(reset);
				}
				// Disconnect and immediate reconnect often fails. Wait to give PCSC subsystem a chance to handle disconnect
				boolean oldpolling = polling;
				try {
					polling = false;
					Thread.sleep(500);
				} catch (InterruptedException e) {
				} finally {
					polling = oldpolling;
				}
			}
			catch(CardException ce) {
				logger.error("[disconnect]"+ce);
				throw new CardTerminalException("Error disconnecting from card: " + ce.getMessage());
			}
			finally {
				this.card = null;
			}
		}
	}



	/**
	 * Send a modify PIN command to the card. A class 3 card terminal is requested for PIN modification.
	 *
	 * @param capdu	the command APDU
	 * @param vc PIN control information
	 * @return The response APDU or null if no class 3 card terminal was found.
	 * @throws CardTerminalException
	 */
	public ResponseAPDU sendModifyPINCommandAPDU(SlotChannel chann, CommandAPDU capdu, CHVControl vc) throws CardTerminalException {

		PCSCIOControl pcscio = new PCSCIOControl(this.card);
		javax.smartcardio.CommandAPDU xcapdu = new javax.smartcardio.CommandAPDU(capdu.getBytes());

		pcscio.setPinEncoding(vc.passwordEncoding());

		byte pinSize = (byte)vc.ioControl().maxInputChars();
		pcscio.setMaxPINSize(pinSize);
		pcscio.setMinPINSize((byte) 1);

		byte timeOut = (byte)vc.ioControl().timeout();
		pcscio.setTimeOut(timeOut);
		pcscio.setTimeOut2(timeOut);

		if (xcapdu.getNc() > 8) {
			pcscio.setConfirmPIN((byte)0x03);			// Prompt for old PIN and confirm new PIN
			pcscio.setInsertionOffsetNew((byte)0x08);
			pcscio.setNumberMessage((byte)0x03);
		} else {
			pcscio.setConfirmPIN((byte)0x01);			// Prompt for new PIN only
			pcscio.setInsertionOffsetNew((byte)0x00);
			pcscio.setNumberMessage((byte)0x02);
		}

		if (pcscio.hasModifyPinDirect()) {
			logger.debug("[sendVerifiedCommandAPDU] Class 3 card terminal found.");

			try {
				byte[] rsp = pcscio.modifyPINDirect(xcapdu);
				return new ResponseAPDU(rsp);
			} catch (CardException e) {
				throw new CardTerminalException("Error modifying PIN with class 3 reader: " + e.getMessage());
			}
		}
		else{
			return null;
		}
	}



	/**
	 * Send a verified command APDU to the card. The verification will be performed with a class 3 card reader.
	 * The PIN has to be entered on the PIN pad. If the password encoding is of type CHVEncoder.PACE, then a PACE
	 * channel will be established
	 *
	 * @param chann		the SlotChannel
	 * @param capdu		the CommandAPDU
	 * @param vc		the CHVControl
	 */
	@Override
	public ResponseAPDU sendVerifiedCommandAPDU(SlotChannel chann, CommandAPDU capdu, CHVControl vc) throws CardTerminalException {
		byte[] rsp;
		ResponseAPDU rapdu;

		logger.debug("[sendVerifiedCommandAPDU] PIN entry on card terminal");

		PCSCIOControl pcscio = new PCSCIOControl(this.card);

		try {
			String encoding = vc.passwordEncoding();
			if (encoding.equals(CHVEncoder.PACE_ENCODING)) {
				rsp = pcscio.establishPACEChannel(vc.chvNumber(), null, null, null);

				int result =  (int)Util.extractLongFromByteArray(rsp, 0, 4);
				rapdu = new ResponseAPDU(rsp.length + 2);
				rapdu.append(rsp);
				switch(result) {
				case 0:
					rapdu.append((byte)0x90);
					rapdu.append((byte)0x00);
					break;
				default:
					if ((result & 0xFFF00000) == 0xF0000000) {
						rapdu.append((byte)(result >> 8));
						rapdu.append((byte)(result & 0xFF));
					} else {
						rapdu.append((byte)0x6F);
						rapdu.append((byte)0x00);
					}
				}
			} else {
				javax.smartcardio.CommandAPDU xcapdu = new javax.smartcardio.CommandAPDU(capdu.getBytes());

				pcscio.setPinEncoding(vc.passwordEncoding());
				byte pinSize = (byte)vc.ioControl().maxInputChars();
				pcscio.setMaxPINSize(pinSize);
				pcscio.setMinPINSize((byte) 1);

				byte timeOut = (byte)vc.ioControl().timeout();
				pcscio.setTimeOut(timeOut);
				pcscio.setTimeOut2(timeOut);

				rsp = pcscio.verifyPINDirect(xcapdu);
				rapdu = new ResponseAPDU(rsp);
			}
		} catch (CardException e) {
			throw new CardTerminalException("Error verifying PIN with class 3 reader: " + e.getMessage());
		}

		return rapdu;
	}



	@Override
	public boolean hasSendVerifiedCommandAPDU() {
		PCSCIOControl pcscio = new PCSCIOControl(this.card);
		return pcscio.hasVerifyPinDirect();
	}
}
