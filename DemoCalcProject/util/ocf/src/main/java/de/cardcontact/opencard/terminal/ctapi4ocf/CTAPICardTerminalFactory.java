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

import java.util.List;

import de.cardcontact.ctapi.CTAPI;
import de.cardcontact.ctapi.CTAPIException;
import de.cardcontact.ctapi.CTAPITerminal;
import de.cardcontact.ctapi.ICTAPIEvent;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalFactory;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.terminal.Pollable;
import opencard.core.terminal.TerminalInitException;



/**
 * Implements a card terminal factory that can instantiate CT-API card terminals.
 *
 */
public class CTAPICardTerminalFactory implements CardTerminalFactory, Pollable, ICTAPIEvent {

	private CTAPI ctapi;



	public void open() throws CardTerminalException {
	}



	public void close() throws CardTerminalException {
		CardTerminalRegistry.getRegistry().removePollable(this);
	}



	@Override
	public void terminalsAdded(List<CTAPITerminal> terminals) {
		CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();
		for (CTAPITerminal ctterm : terminals) {
			try	{
				ctr.add(new CTAPICardTerminal(ctterm, ""));
			}
			catch (CardTerminalException e) {
				// Ignore
			}
		}
	}



	@Override
	public void terminalsRemoved(List<CTAPITerminal> terminals) {
		CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();
		for (CTAPITerminal ctterm : terminals) {
				try {
					ctr.remove(ctterm.getName());
				} catch (CardTerminalException e) {
					// Ignore
				}
		}
	}



	@Override
	public void poll() throws CardTerminalException {
		ctapi.checkEvent();
	}



	public void detectCardTerminals(CardTerminalRegistry ctr, String[] terminfo)
			throws CardTerminalException, TerminalInitException {

		ctapi = new CTAPI(terminfo[3]);

		if (terminfo[TERMINAL_TYPE_ENTRY].endsWith("-NOPOLL")) {
			List<CTAPITerminal> terminals = null;
			try	{
				terminals = ctapi.CT_List();
			}
			catch(CTAPIException e) {
				throw new CardTerminalException("Could not enumerate CT-API devices: " + e.getMessage());
			}
			for (CTAPITerminal ctterm : terminals) {
				ctr.add(new CTAPICardTerminal(ctterm, terminfo[TERMINAL_TYPE_ENTRY]));
			}
		} else {
			ctapi.setEventListener(this);
			CardTerminalRegistry.getRegistry().addPollable(this);
		}
	}



	public void createCardTerminals(CardTerminalRegistry ctr, String[] terminfo)
			throws CardTerminalException, TerminalInitException {
		if (terminfo.length != 4)
			throw new TerminalInitException(
					"CTAPICardTerminalFactory needs 4 parameters.");


		if (terminfo[TERMINAL_TYPE_ENTRY].startsWith("AUTO")) {
			detectCardTerminals(ctr, terminfo);
		} else if (terminfo[TERMINAL_TYPE_ENTRY].startsWith("CTAPIKBD")) {
			ctr.add(new CTAPIWithKeyboardCardTerminal(
					terminfo[TERMINAL_NAME_ENTRY],
					terminfo[TERMINAL_TYPE_ENTRY],
					terminfo[TERMINAL_ADDRESS_ENTRY], terminfo[3]));
		} else if (terminfo[TERMINAL_TYPE_ENTRY].startsWith("CTAPI")) {
			ctr.add(new CTAPICardTerminal(terminfo[TERMINAL_NAME_ENTRY],
					terminfo[TERMINAL_TYPE_ENTRY],
					terminfo[TERMINAL_ADDRESS_ENTRY], terminfo[3]));
		} else {
			throw new TerminalInitException(
					"Requested Terminal type not known.");
		}
	}
}
