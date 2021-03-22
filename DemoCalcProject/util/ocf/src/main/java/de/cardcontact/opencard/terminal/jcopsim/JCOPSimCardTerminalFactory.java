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

import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalFactory;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.terminal.TerminalInitException;

/**
 * Class implementing a JCOP simulation card terminal factory
 * 
 * @author Frank Thater (info@cardcontact.de)
 */
public class JCOPSimCardTerminalFactory implements CardTerminalFactory {


	/**
	 * Constructor
	 */
	public JCOPSimCardTerminalFactory() {
		super();
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminalFactory#createCardTerminals(opencard.core.terminal.CardTerminalRegistry, java.lang.String[])
	 */
	public void createCardTerminals(CardTerminalRegistry ctr, String[] terminalInfo) throws CardTerminalException, TerminalInitException {

		/*
		 * OpenCard.terminals =    de.cardcontact.opencard.terminal.jcopsim.JCOPSimCardTerminalFactory|Reader1|JCOPSIM|0|localhost|8050|5000  
		 */

		String host = "localhost"; // Default host

		int port = 8050; // Default port

		int timeout = JCOPSimCardTerminal.DEFAULT_SOCKET_TIMEOUT;

		if (terminalInfo.length < 3) {
			throw new TerminalInitException("JCOPSimCardTerminalFactory needs at least 3 parameters.");
		}

		if (!terminalInfo[TERMINAL_TYPE_ENTRY].equals("JCOPSIM")) {
			throw new TerminalInitException("Requested Terminal type not known.");
		}

		if (terminalInfo.length >= 4) {
			host = terminalInfo[3];
		}

		if (terminalInfo.length >= 5) {
			port = Integer.parseInt(terminalInfo[4]);
		}

		if (terminalInfo.length == 6) {
			timeout = Integer.parseInt(terminalInfo[5]);
		}

		try {
			ctr.add(new JCOPSimCardTerminal(terminalInfo[TERMINAL_NAME_ENTRY],terminalInfo[TERMINAL_TYPE_ENTRY],terminalInfo[TERMINAL_ADDRESS_ENTRY], host, port, timeout));	
		}
		catch (Exception e) {
			throw new TerminalInitException("JCOPSimCardTerminal could not be added to card terminal registry! " + e.getMessage());
		}

	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminalFactory#open()
	 */
	public void open() throws CardTerminalException {
	}



	/* (non-Javadoc)
	 * @see opencard.core.terminal.CardTerminalFactory#close()
	 */
	public void close() throws CardTerminalException {
	}
}
