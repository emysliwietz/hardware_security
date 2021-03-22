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

import java.util.Enumeration;
import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalFactory;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.terminal.Pollable;
import opencard.core.terminal.TerminalInitException;

/**
 * Factory that creates a CardTerminal object for each card reader listed via the javax.smartcardio interface.
 *
 */
public class SmartCardIOFactory implements CardTerminalFactory, Pollable {

	private final static Logger logger = LoggerFactory.getLogger(SmartCardIOFactory.class);

	private int numberOfRegisteredTerminals = 0;



	@Override
	public void close() throws CardTerminalException {
		// Empty
	}



	/**
	 * Creates an instance for each card listed.
	 */
	@Override
	public void createCardTerminals(CardTerminalRegistry ctr, String[] terminalInfo)
			throws CardTerminalException, TerminalInitException {

		String terminalType = "SmartCardIO";

		if (terminalInfo.length >= 2) {
			terminalType = terminalInfo[1];
		}
		if (terminalType.endsWith("-NOPOLL")) {
			try	{
				TerminalFactory factory = TerminalFactory.getDefault();
				List<javax.smartcardio.CardTerminal> terminals = factory.terminals().list();

				for (javax.smartcardio.CardTerminal ct : terminals) {
					ctr.add(new SmartCardIOTerminal(ct.getName(), terminalType, "", ct));
					numberOfRegisteredTerminals++;
				}
			}
			catch(CardException ce) {
				logger.error("[createCardTerminals]"+ce);
			}
		} else {
			CardTerminalRegistry.getRegistry().addPollable(this);
		}
	}



	@Override
	public void open() throws CardTerminalException {
		// Empty
	}



	/**
	 * Check whether a new physical terminal was plugged in or removed.
	 * If so update the CardTerminalRegistry.
	 */
	@Override
	public void poll() throws CardTerminalException {
		CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();

		TerminalFactory factory = TerminalFactory.getDefault();
		CardTerminals ts = factory.terminals();
		List<javax.smartcardio.CardTerminal> terminals = null;
		try {
			terminals = ts.list();
		} catch (CardException e) {
			// Catch exception which is thrown when no terminal is available
			if(numberOfRegisteredTerminals > 0) {
				removeAllTerminals(ctr);
			}
			return;
		}
		int numberOfTerminals = terminals.size();

		if (numberOfTerminals < numberOfRegisteredTerminals) {
			removeTerminals(terminals, ctr);
		}
		if (numberOfTerminals > numberOfRegisteredTerminals) {
			addTerminals(terminals, ctr);
		}
	}



	/**
	 * Remove all terminals from the CardTerminalRegistry
	 * @param ctr OCF card terminal registry
	 * @throws CardTerminalException
	 */
	private void removeAllTerminals(CardTerminalRegistry ctr) throws CardTerminalException {
		Enumeration terminals = ctr.getCardTerminals();
		while(terminals.hasMoreElements()) {
			CardTerminal t = (CardTerminal)terminals.nextElement();
			if (t instanceof SmartCardIOTerminal) {
				ctr.remove(t);
			}
		}
		numberOfRegisteredTerminals = 0;
	}



	/**
	 * Remove Terminals which doesn't exists any more
	 *
	 * @param terminals SmartCardIO terminals
	 * @param ctr OCF card terminal registry
	 * @throws CardTerminalException
	 */
	private void removeTerminals(List<javax.smartcardio.CardTerminal> terminals, CardTerminalRegistry ctr) throws CardTerminalException {
		Enumeration registeredTerminals = ctr.getCardTerminals();

		while(registeredTerminals.hasMoreElements()) {
			CardTerminal rct = (CardTerminal)registeredTerminals.nextElement();
			if (rct instanceof SmartCardIOTerminal) {
				boolean isRemoved = true;
				for (javax.smartcardio.CardTerminal ct : terminals) {
					if (ct.getName().equals(rct.getName())) {
						isRemoved = false;
						break;
					}
				}
				if (isRemoved) {
					ctr.remove(rct);
					numberOfRegisteredTerminals--;
				}
			}
		}
	}



	/**
	 * Add all new card terminal to the card terminal registry
	 *
	 * @param terminals SmartCardIO terminals
	 * @param ctr OCF card terminal registry
	 * @throws CardTerminalException
	 */
	private void addTerminals(List<javax.smartcardio.CardTerminal> terminals, CardTerminalRegistry ctr) throws CardTerminalException {
		for (javax.smartcardio.CardTerminal ct : terminals) {
			Enumeration registeredTerminals = ctr.getCardTerminals();

			boolean isNew = true;
			while(registeredTerminals.hasMoreElements()) {
				CardTerminal rct = (CardTerminal)registeredTerminals.nextElement();
				if (ct.getName().equals(rct.getName())) {
					isNew = false;
					break;
				}
			}
			if (isNew) {
				ctr.add(new SmartCardIOTerminal(ct.getName(), "PCSC", "", ct));
				numberOfRegisteredTerminals++;
			}
		}
	}
}
