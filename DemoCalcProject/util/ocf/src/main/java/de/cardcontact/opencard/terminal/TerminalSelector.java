/*
 * Copyright (c) 2020 CardContact Systems GmbH, Minden, Germany.
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

package de.cardcontact.opencard.terminal;

import java.util.HashSet;

import opencard.core.service.CardIDFilter;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminal;



public class TerminalSelector implements CardIDFilter {

	private String[] readerList;


	public TerminalSelector(String selector) {
		readerList = selector.split("\\s*;\\s*");
		if (readerList.length == 1 && readerList[0].length() == 0) {
			readerList = new String[0];
		}
	}



	/**
	 * Return the first selected terminal from the list
	 *
	 * @return the first selected terminal
	 */
	public String getFirstSelectedTerminal() {
		for (String sel : readerList) {
			if (sel.length() > 0 && sel.charAt(0) != '!') {
				return sel;
			}
		}
		return null;
	}



	public HashSet<String> getSelectedReader() {
		HashSet<String> readerSet = new HashSet<String>();

		for (String sel : readerList) {
			if (sel.length() > 0 && sel.charAt(0) != '!') {
				readerSet.add(sel);
			}
		}
		return readerSet;
	}



	public HashSet<String> getDeselectedReader() {
		HashSet<String> readerSet = new HashSet<String>();

		for (String sel : readerList) {
			if (sel.length() > 0 && sel.charAt(0) == '!') {
				readerSet.add(sel.substring(1));
			}
		}
		return readerSet;
	}



	public boolean isEmpty() {
		return readerList.length == 0;
	}



	public boolean match(String readerName) {
		boolean result = true;

		for (String sel : readerList) {
			if (sel.length() > 0 && sel.charAt(0) == '!') {
				sel = sel.substring(1);
				if (readerName.startsWith(sel)) {
					return false;
				}
			} else {
				if (readerName.startsWith(sel)) {
					return true;
				}
				result = false;
			}
		}
		return result;
	}



	@Override
	public boolean isCandidate(CardID cardID) {
		CardTerminal ct = cardID.getCardTerminal();
		String readerName = "";
		if (ct != null) {
			readerName = ct.getName();
		}
		return match(readerName);
	}
}
