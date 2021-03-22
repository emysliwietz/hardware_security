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

package de.cardcontact.opencard.terminal.jcopsim;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.util.HexString;

/**
 * Class implementing a JCOP simulation card terminal
 *
 * @author Frank Thater (info@cardcontact.de)
 */
public class JCOPSimCardTerminal extends CardTerminal {

	private final static Logger logger = LoggerFactory.getLogger(JCOPSimCardTerminal.class);

	public static final int DEFAULT_SOCKET_TIMEOUT = 5000;

	// Set the buffer size to 65536 (max. extended length) + 100 bytes reserved for the protocol overhead
	private static final int JCOP_RECV_BUFFER_SIZE = 65636;

	/**
	 * Message types accepted by the simulation
	 */
	static final byte MTY_WAIT_FOR_CARD = 0;
	static final byte MTY_APDU_DATA = 1;
	static final byte MTY_STATUS = 2;
	static final byte MTY_ERROR_MESSAGE = 3;
	static final byte MTY_TERMINAL_INFO = 4;
	static final byte MTY_INIT_INFO = 5;
	static final byte MTY_ECHO = 6;
	static final byte MTY_DEBUG = 7;
	static final byte MTY_CONTROLLER_CONFIGURATION = (byte)0xFE;

	/**
	 * Node number of controller
	 */
	static final byte NODE_CONTROLLER = (byte)0xFF;

	/**
	 * Node number of terminal
	 */
	static final byte NODE_TERMINAL = 33;

	/**
	 * Node number of card
	 */
	static final byte NODE_CARD = 0;

	/**
	 * Status of the reader simulation
	 */
	static final int NOT_CONNECTED = 1;
	static final int SLOT_EMPTY = 2;
	static final int CARD_PRESENT = 4;
	static final int ERROR = 8;
	static final int PROTOCOL_T0 = 0;
	static final int PROTOCOL_T1 = 1;
	static final int PROTOCOL_TCL = 5;


	/**
	 * Socket for communication
	 */
	private Socket socket = null;

	/**
	 * Remote address (Hostname, Port) of the simulation
	 */
	private SocketAddress socketAddr;

	/**
	 * Timeout value for socket
	 */
	private int socketTimeout = DEFAULT_SOCKET_TIMEOUT;

	/**
	 * Stream for incoming data
	 */
	private BufferedInputStream inStream = null;

	/**
	 * Stream for outgoing data
	 */
	private BufferedOutputStream outStream = null;

	/**
	 * CardID of the simulated card
	 */
	private CardID cid = null;

	/**
	 * Indicator for established connection
	 */
	private boolean connected = false;

	private boolean isV2Prot = false;

	private byte nodeAddress = NODE_CARD;

	/**
	 * Data buffer
	 */
	private byte[] jcopBuffer;


	/**
	 * Constructor for JCOPSimCardTerminal
	 *
	 * @param name
	 * 			Friendly name of the terminal
	 * @param type
	 * 			Type of the card terminal
	 * @param address
	 * 			Identifier for the driver to locate the terminal
	 * @param host
	 * 			Host of the remote terminal simulation
	 * @param port
	 * 			Port number of the remote terminal simulation
	 * @param timeout
	 *
	 * @throws CardTerminalException
	 */
	public JCOPSimCardTerminal(String name, String type, String address, String host, int port, int timeout) throws CardTerminalException {

		super(name, type, address);

		socketAddr = new InetSocketAddress(host, port);
		jcopBuffer = new byte[JCOP_RECV_BUFFER_SIZE];

		this.socketTimeout = timeout;

		addSlots(1);
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminal#getCardID(int)
	 */
	@Override
	public CardID getCardID(int slotID) throws CardTerminalException {

		if (!connected) {
			connect();
		}

		if (!connected) {
			throw new CardTerminalException("JCOPSimCardTerminal: getCardID(), Terminal not opened.");
		}

		return cid;
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminal#isCardPresent(int)
	 */
	@Override
	public boolean isCardPresent(int slotID) throws CardTerminalException {
		if (!connected) {
			connect();
		}
		return connected;
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminal#open()
	 */
	@Override
	public void open() throws CardTerminalException {
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminal#open()
	 */
	public void connect() throws CardTerminalException {

		if (connected) {
			return;
		}

		try {
			// Try to open the specified socket
			socket = new Socket();
			socket.connect(socketAddr, this.socketTimeout);

			// Set timeout for socket
			socket.setSoTimeout(this.socketTimeout);

			// get streams for communication
			outStream = new BufferedOutputStream(socket.getOutputStream());
			inStream = new BufferedInputStream(socket.getInputStream());

			connected = true;
		} catch(ConnectException ste) {
			// Ignore, server may run sometimes later
		} catch(SocketTimeoutException ste) {
			// Ignore, server may run sometimes later
		} catch (Exception e) {
			throw new CardTerminalException("JCOPSimCardTerminal: Card terminal could not be opened! Reason: " + e.getLocalizedMessage());
		}

		try {

			if (connected) {

				sendJcop(MTY_TERMINAL_INFO, NODE_CONTROLLER, null);
				int read = 0;
				read = readJcop(MTY_TERMINAL_INFO, jcopBuffer);

				byte[] bin = new byte[read];
				System.arraycopy(jcopBuffer, 0, bin, 0, read);
				String id = new String(bin);
				logger.debug("Detected " + id);
				if (id.equals("JRCP Protocol 2+")) {
					isV2Prot = true;
					byte[] submty = { 0x00 , 0x01};
					sendJcop(MTY_CONTROLLER_CONFIGURATION, NODE_CONTROLLER, submty);
					read = readJcop(MTY_CONTROLLER_CONFIGURATION, jcopBuffer);
					nodeAddress = jcopBuffer[2];		// Use NAD of first indicated node
					byte[] data = {0x00, 0x00, 0x00, 0x00};
					sendJcop(MTY_WAIT_FOR_CARD, nodeAddress, data);
				} else {
					byte[] data = {0x00, 0x00, 0x00, 0x00};
					sendJcop(MTY_WAIT_FOR_CARD, NODE_TERMINAL, data);
				}

				read = readJcop(MTY_WAIT_FOR_CARD, jcopBuffer);

				byte[] scr = new byte[read];
				System.arraycopy(jcopBuffer, 0, scr, 0, read);

				cid = new CardID(this, 0, scr);

				cardInserted(0);
			}
		} catch (SocketException se) {
			close();
		} catch (Exception e) {
			close();
			throw new CardTerminalException("JCOPSimCardTerminal: Error in socket communication! Reason: " + e.getLocalizedMessage());
		}
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminal#close()
	 */
	@Override
	public void close() throws CardTerminalException {

		if (connected) {
			try {
				connected = false;

				outStream.close();
				inStream.close();

				outStream = null;
				inStream = null;

				socket.close();

			} catch (Exception e) {
				throw new CardTerminalException("JCOPSimCardTerminal: Error in socket communication! Reason: " + e.getLocalizedMessage());
			}
		}
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminal#internalReset(int, int)
	 */
	@Override
	protected CardID internalReset(int slot, int ms) throws CardTerminalException {

		close();
		connect();

		return cid;
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminal#internalSendAPDU(int, opencard.core.terminal.CommandAPDU, int)
	 */
	@Override
	protected ResponseAPDU internalSendAPDU(int slot, CommandAPDU capdu, int ms) throws CardTerminalException {

		if (!connected) {
			connect();
		}

		if (!connected) {
			throw new CardTerminalException("JCOPSimCardTerminal: Error sending APDU! No connection");
		}

		ResponseAPDU r = null;

		try {

			byte[] apdu = capdu.getBytes();

			sendJcop(MTY_APDU_DATA, nodeAddress, apdu);

			int read = 0;
			read = readJcop(MTY_APDU_DATA, jcopBuffer);

			byte[] rsp = new byte[read];
			System.arraycopy(jcopBuffer, 0, rsp, 0, read);

			r = new ResponseAPDU(rsp);
		}
		catch (Exception e) {
			logger.debug("[internalSendAPDU] Error sending APDU: " + e.getMessage());
			throw new CardTerminalException("JCOPSimCardTerminal: Error sending APDU! Reason: " + e.getLocalizedMessage());
		}

		return r;
	}



	/**
	 * Send a command message to the remote terminal simulation
	 *
	 * @param mty
	 * 			Message type
	 * @param destNode
	 * 			Destination node
	 * @param cmd
	 * 			Command data
	 *
	 * @throws CardTerminalException
	 */
	private void sendJcop(byte mty, byte destNode, byte[] cmd) throws CardTerminalException {

		int length = cmd == null ? 0 : cmd.length;

		byte[] scr;
		if (isV2Prot) {
			scr = new byte[9 + length];

			scr[0] = (byte)0xA5;	// Start of message
			scr[1] = mty;			// MTY (command)
			scr[2] = destNode;		// NAD
			scr[3] = 0x00;			// HDL (HD absent)
			scr[4] = (byte)(length >> 24);
			scr[5] = (byte)(length >> 16);
			scr[6] = (byte)(length >>  8);
			scr[7] = (byte)length;

			if (cmd != null) {
				System.arraycopy(cmd, 0, scr, 8, length);
			}

			scr[8 + length] = 0x00;			// TIL
		} else {
			scr = new byte[4 + length];

			scr[0] = mty;
			scr[1] = destNode;
			scr[2] = (byte)(length / 256);
			scr[3] = (byte) length;

			if (cmd != null) {
				System.arraycopy(cmd, 0, scr, 4, length);
			}
		}

		try {
			logger.debug("[sendJcop] SEND: " + HexString.dump(scr, 0, scr.length));
			outStream.write(scr);
			outStream.flush();
		} catch (IOException e) {
			connected = false;
		}
	}



	private int readJcopV1(byte mty, byte[] buf) throws Exception {

		int sizeRsp = -1;
		int totalBytesRead = 0;
		int read = 0;

		byte[] tmp = new byte[buf.length];

		read = inStream.read(tmp, 0, 4);

		if (read != 4) {
			connected = false;
			logger.debug("[readJcop] JCOP header not received! recv = " + HexString.dump(tmp, 0, read) + " (" + read +")");
			throw new CardTerminalException("JCOP header not received!");
		}

		if (tmp[0] != mty) { // Incorrect message type?
			connected = false;
			logger.debug("[readJcop] Mismatch of message types");
			throw new CardTerminalException("Mismatch of message types");
		}

		sizeRsp = (tmp[2] & 0xff) << 8 | (tmp[3] & 0xff);

		while (totalBytesRead < sizeRsp) {
			read = inStream.read(tmp, 0, tmp.length);
			System.arraycopy(tmp, 0, buf, totalBytesRead, read);
			totalBytesRead += read;
		}

		if (inStream.available() > 0) {
			logger.debug("[readJcop] Warning: not all bytes were read! left = " + inStream.available());
		}

		return totalBytesRead;
	}



	private int readJcopV2(byte mty, byte[] buf) throws Exception {

		int sizeRsp = -1;
		int totalBytesRead = 0;
		int read = 0;

		byte[] tmp = new byte[buf.length];

		read = inStream.read(tmp, 0, 4);

		if (read != 4) {
			connected = false;
			logger.debug("[readJcop] JCOP header not received! recv = " + HexString.dump(tmp, 0, read) + " (" + read +")");
			throw new CardTerminalException("JCOP header not received!");
		}

		if (((tmp[0] & 0xFF) != 0xA5) && (tmp[1] != mty)) { // Incorrect message type?
			connected = false;
			logger.debug("[readJcop] Mismatch of message types");
			throw new CardTerminalException("Mismatch of message types");
		}

		int ofs = 4;
		int len = tmp[3] & 0xFF;
		while (len > 0) {
			read = inStream.read(tmp, ofs, len);
			len -= read;
			ofs += read;
		}

		read = inStream.read(tmp, ofs, 4);
		if (read != 4) {
			connected = false;
			logger.debug("[readJcop] Could not read payload length");
			throw new CardTerminalException("Could not read payload length");
		}

		len = ((tmp[ofs++] & 0xFF) << 24) + ((tmp[ofs++] & 0xFF) << 16) + ((tmp[ofs++] & 0xFF) << 8) + (tmp[ofs++] & 0xFF);
		totalBytesRead = len;

		while (len > 0) {
			read = inStream.read(tmp, ofs, len);
			len -= read;
			ofs += read;
		}

		System.arraycopy(tmp, ofs - totalBytesRead, buf, 0, totalBytesRead);

		read = inStream.read(tmp, ofs, 1);
		if (read != 1) {
			connected = false;
			logger.debug("[readJcop] Could not read timestamp length");
			throw new CardTerminalException("Could not read timestamp length");
		}

		len = (tmp[ofs++] & 0xFF);

		while (len > 0) {
			read = inStream.read(tmp, ofs, len);
			len -= read;
			ofs += read;
		}

		if (inStream.available() > 0) {
			logger.debug("[readJcop] Warning: not all bytes were read! left = " + inStream.available());
		}

		return totalBytesRead;
	}



	/**
	 * Read a command message from the remote terminal simulation and extract the "raw" command data
	 *
	 * @param mty
	 * 			Expected message type
	 * @param buf
	 * 			Destination buffer for command data
	 * @return
	 * 			Number of bytes read
	 *
	 * @throws Exception
	 */
	private int readJcop(byte mty, byte[] buf) throws Exception {
		if (isV2Prot) {
			return readJcopV2(mty, buf);
		} else {
			return readJcopV1(mty, buf);
		}
	}
}
