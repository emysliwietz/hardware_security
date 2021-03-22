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

package de.cardcontact.opencard.service.remoteclient;

import opencard.core.terminal.APDU;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;

/**
 * Basic exchange unit for remote card terminal
 *
 * @author asc
 *
 */
public class RemoteProtocolUnit {

	public enum Action { APDU, RESET, NOTIFY, CLOSE };

	private Action action;
	private int id;
	private int ttc;
	private String message;
	private Object payload;


	public RemoteProtocolUnit(Action action) {
		this.action = action;
	}



	public RemoteProtocolUnit(RemoteProtocolUnit.Action action, int id, String message, int ttc) {
		this.id = id;
		this.message = message;
		this.action = action;
		this.ttc = ttc;
	}



	public RemoteProtocolUnit(RemoteProtocolUnit.Action action, int id, String message) {
		this(action, id, message, 0);
	}



	public RemoteProtocolUnit(CommandAPDU com) {
		this.action = RemoteProtocolUnit.Action.APDU;
		this.payload = com;
	}



	public RemoteProtocolUnit(ResponseAPDU res) {
		this.action = RemoteProtocolUnit.Action.APDU;
		this.payload = res;
	}



	public RemoteProtocolUnit(CardID cardID) {
		this(new RemoteCardSpec(cardID));
	}



	public RemoteProtocolUnit(RemoteCardSpec rcs) {
		this.action = RemoteProtocolUnit.Action.RESET;
		this.payload = rcs;
	}



	public Object getPayload() {
		return this.payload;
	}



	public Action getAction() {
		return this.action;
	}



	public int getId() {
		return this.id;
	}



	public String getMessage() {
		return this.message;
	}



	public int getTimeToCompletion() {
		return this.ttc;
	}



	public boolean isAPDU() {
		return this.action == Action.APDU;
	}



	public boolean isRESET() {
		return this.action == Action.RESET;
	}



	public boolean isNOTIFY() {
		return this.action == Action.NOTIFY;
	}



	public boolean isClosing() {
		return this.action == Action.CLOSE;
	}


	public String toString() {
		String str = "RemoteProtocolUnit ";

		switch(this.action) {
		case APDU:
			str += "APDU \n" + ((APDU)this.payload).toString();
			break;
		case RESET:
			if (this.payload == null) {
				str += "RESET";
			} else {
				str += "ATR " + ((RemoteCardSpec)this.payload).toString();
			}
			break;
		case NOTIFY:
			str += "NOTIFY";
			break;
		case CLOSE:
			str += "CLOSE";
			break;
		}
		return str;
	}
}
