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

package de.cardcontact.opencard.terminal.remoteterminal;

import java.util.Properties;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.opencard.service.isocard.IsoConstants;
import de.cardcontact.opencard.service.remoteclient.RemoteCardSpec;
import de.cardcontact.opencard.service.remoteclient.RemoteProtocolUnit;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.CommunicationErrorException;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.terminal.SlotChannel;
import opencard.core.terminal.TerminalTimeoutException;

public class RemoteTerminal extends CardTerminal {

	private final static Logger logger = LoggerFactory.getLogger(RemoteTerminal.class);

	private static final int timeoutShort = 30;
	private static final int timeoutLong = 300;
	private boolean freshConnect = true;
	private volatile boolean longPoll = false;
	private long lastPollingTimeout = -1;
	private int maxCAPDU = -1;
	private int maxRAPDU = -1;

	private CardID cardID = null;

	private LinkedBlockingQueue<RemoteProtocolUnit> comQueue = new LinkedBlockingQueue<RemoteProtocolUnit>(1);
	private LinkedBlockingQueue<RemoteProtocolUnit> resQueue = new LinkedBlockingQueue<RemoteProtocolUnit>(1);



	protected RemoteTerminal(String name, String type, String address) throws CardTerminalException {
		super(name, type, address);
		logger.debug("Created " + name);
		addSlots(1);
	}



	/**
	 * Check if the remote terminal has disappeared
	 *
	 * A connected terminal will poll for new C-APDUs using HTTP long polling with
	 * a period of 30 seconds. If the last polling sequence ended more that 5 second
	 * ago, then the reconnect in HTTP polling did not happen.
	 *
	 * @return true if long polling reconnect did not happen
	 */
	private boolean remoteDisappeared() {
		if (this.lastPollingTimeout != -1) {
			if (System.currentTimeMillis() - this.lastPollingTimeout > 5000) {
				logger.debug("Remote terminal disappeared at " + this.lastPollingTimeout);
				return true;
			}
		}
		return false;
	}



	/**
	 * Transmit a command object and wait for a response object
	 *
	 * @param cmdObject the command object (i.e. CommandAPDU, Reset, Notify)
	 * @return the response object (i.e. ResponseAPDU, CardID, Notify)
	 * @throws CardTerminalException
	 */
	protected RemoteProtocolUnit transmit(RemoteProtocolUnit cmdObject, int timeout) throws CardTerminalException {
		RemoteProtocolUnit resObject;

		try {
			if (remoteDisappeared()) {
				throw new CardTerminalException("Remote terminal disappeared");
			}
			comQueue.put(cmdObject);

			logger.debug("Waiting for R-APDU from remote terminal");

			resObject = resQueue.poll(timeout, TimeUnit.SECONDS);
			if (resObject == null) {
				throw new TerminalTimeoutException("The waiting time of " + timeout + " seconds for the response has expired.", timeout);
			}
			if (resObject.isClosing()) {
				throw new CommunicationErrorException(resObject.getMessage());
			}
		} catch (InterruptedException e) {
			throw new CardTerminalException(e.getMessage());
		}
		return resObject;
	}



	/**
	 * Poll for a command object. Used by remote connection.
	 * @return the command object (i.e. CommandAPDU, RemoteControl)
	 * @throws CardTerminalException
	 */
	public RemoteProtocolUnit poll(int timeout) throws CardTerminalException {
		RemoteProtocolUnit comObject;

		try {
			logger.debug("Remote terminal polling for C-APDU. Queue size " + comQueue.size());
			this.lastPollingTimeout = -1;
			this.longPoll = true;
			comObject = comQueue.poll(timeout, TimeUnit.SECONDS);
			if (comObject == null) {
				if (this.freshConnect) {
					throw new CommunicationErrorException("The waiting time of " + timeout + " seconds for the initial command apdu has expired.");
				}
				this.lastPollingTimeout = System.currentTimeMillis();
			}
			this.freshConnect = false;
		} catch (InterruptedException e) {
			throw new CardTerminalException(e.getMessage());
		} finally {
			this.longPoll = false;
		}

		return comObject;
	}



	/**
	 * Put response object into queue. Used by remote connection.
	 *
	 * @return the response object (i.e. ResponseAPDU, CardID, RemoteControl)
	 * @throws CardTerminalException
	 */
	public void put(RemoteProtocolUnit resObject) throws CardTerminalException {
		logger.debug("Placing R-APDU into queue");
		try {
			resQueue.put(resObject);
			if (resObject.isClosing()) {
				if (this.longPoll) {		// Add close for long polling request
					comQueue.put(resObject);
				}
				comQueue.put(resObject);	// Add close response
			}
		} catch (InterruptedException e) {
			throw new CardTerminalException(e.getMessage());
		}
	}



	@Override
	public CardID getCardID(int slotID) throws CardTerminalException {
		if (this.cardID != null) {
			return this.cardID;
		}
		return new CardID(this, 0, new byte[] {0x3b, (byte)0x80, 0x00, 0x00});
	}



	public void setRemoteCardSpec(RemoteCardSpec rcs) throws CardTerminalException {

		this.cardID = new CardID(this, 0, rcs.getCardID().getATR());
		this.maxCAPDU = rcs.getMaxCAPDU();
		this.maxRAPDU = rcs.getMaxRAPDU();
		this.freshConnect = true;
	}



	@Override
	protected Properties internalFeatures(Properties features) {
		if (this.maxCAPDU != -1) {
			features.put("maxCAPDUSize", String.valueOf(this.maxCAPDU));
		}
		if (this.maxRAPDU != -1) {
			features.put("maxRAPDUSize", String.valueOf(this.maxRAPDU));
		}
		return features;
	}



	public void setCardID(CardID cardID) throws CardTerminalException {
		this.cardID = new CardID(this, 0, cardID.getATR());
		this.freshConnect = true;
	}



	@Override
	public boolean isCardPresent(int slotID) throws CardTerminalException {
		return cardID != null;
	}



	@Override
	public void open() throws CardTerminalException {
		logger.debug("[open] open");
	}



	@Override
	public void close() throws CardTerminalException {
		logger.debug("[close] close");

		if (!comQueue.isEmpty()) {
			logger.debug("[close] TERMINAL: clearing com queue...");
			comQueue.clear();
		}
		comQueue.offer(new RemoteProtocolUnit(RemoteProtocolUnit.Action.CLOSE));
	}



	@Override
	protected CardID internalReset(int slot, int ms) throws CardTerminalException {

		RemoteProtocolUnit rpu = transmit(new RemoteProtocolUnit(RemoteProtocolUnit.Action.RESET), timeoutShort);

		if (!rpu.isRESET()) {
			throw new CardTerminalException("Received unexpected message");
		}

		setCardID(((RemoteCardSpec)rpu.getPayload()).getCardID());
		return this.cardID;
	}



	@Override
	protected ResponseAPDU internalSendAPDU(int slot, CommandAPDU capdu, int ms)
			throws CardTerminalException {

		int timeout = timeoutShort;
		if ((capdu.getByte(1) == IsoConstants.INS_GENERATE_KEYPAIR) || (capdu.getByte(1) == (IsoConstants.INS_INSTALL & 0xFF))) {
			timeout = timeoutLong;
		}
		RemoteProtocolUnit rpu = transmit(new RemoteProtocolUnit(capdu), timeout);

		if (!rpu.isAPDU()) {
			throw new CardTerminalException("Received unexpected message");
		}

		return (ResponseAPDU)rpu.getPayload();
	}



	@Override
	protected void internalCloseSlotChannel(SlotChannel sc) {
		cardID = null;
		try	{
			if (!comQueue.offer(new RemoteProtocolUnit(RemoteProtocolUnit.Action.CLOSE), 2, TimeUnit.SECONDS)) {
				logger.debug("Close message could not be added to queue");
			}
		} catch (InterruptedException e) {
			logger.debug("Adding close message interrupted");
		}
	}



	/**
	 * Send an asynchronous notification to the client
	 *
	 * @param id the integer status code, < 0 denotes an error, 0 denotes completion
	 * @param message the message to be send
	 * @param ttc the estimated time in seconds to complete this interaction
	 * @throws CardTerminalException
	 */
	public void sendNotification(int id, String message, int ttc) throws CardTerminalException {
		try	{
			if (!comQueue.offer(new RemoteProtocolUnit(RemoteProtocolUnit.Action.NOTIFY, id, message, ttc), 2, TimeUnit.SECONDS)) {
				logger.debug("Notify message could not be added to queue");
			}
		} catch (InterruptedException e) {
			logger.debug("Adding notify message interrupted");
		}
	}



	/**
	 * Send an asynchronous notification to the client
	 *
	 * @param id the integer status code, < 0 denotes an error, 0 denotes completion
	 * @param message the message to be send
	 * @throws CardTerminalException
	 */
	public void sendNotification(int id, String message) throws CardTerminalException {
		sendNotification(id, message, 0);
	}
}
