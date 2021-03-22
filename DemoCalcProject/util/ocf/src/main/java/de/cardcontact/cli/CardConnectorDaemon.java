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

package de.cardcontact.cli;

import de.cardcontact.opencard.service.CardServiceUnexpectedStatusWordException;
import de.cardcontact.opencard.service.isocard.CHVCardServiceWithControl;
import de.cardcontact.opencard.service.isocard.CHVCardServiceWithControl.PasswordStatus;
import de.cardcontact.opencard.service.remoteclient.RemoteNotificationListener;
import de.cardcontact.opencard.service.remoteclient.RemoteUpdateService;
import opencard.core.event.CTListener;
import opencard.core.event.CardTerminalEvent;
import opencard.core.event.EventGenerator;
import opencard.core.service.CardServiceException;
import opencard.core.service.CardServiceInvalidCredentialException;
import opencard.core.service.CardServiceOperationFailedException;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalException;
import opencard.opt.security.CHVCardService;

public class CardConnectorDaemon implements Runnable, CTListener, RemoteNotificationListener {

	ReaderConfigurationModel readerConfig;
	CardUpdaterLog logger;
	int lastMessageId = 0;
	boolean ensurePIN = false;
	byte[] presetPIN = null;
	SmartCard card = null;
	String url = null;
	String session = null;
	String id = "unknown";
	RemoteUpdateService rus;



	public CardConnectorDaemon(CardUpdaterLog logger, ReaderConfigurationModel readerConfig, SmartCard card) {
		this.logger = logger;
		this.readerConfig = readerConfig;
		this.card = card;
	}




	public void log(int level, String msg) {
		logger.log(level, msg);
	}



	static String PINStatusString(PasswordStatus pws) {
		switch(pws) {
		case VERIFIED: return("PIN verified");
		case NOTVERIFIED: return("PIN not verified");
		case BLOCKED: return("PIN is blocked");
		case LASTTRY: return("Last PIN try");
		case NOTINITIALIZED: return("PIN not initialized");
		case RETRYCOUNTERLOW: return("PIn retry counter low");
		case TRANSPORTMODE: return("PIN in transport mode");
		}
		return "Unknown";
	}



	public void setPIN(byte[] pin) {
		this.presetPIN = pin;
	}



	public void setEnsurePIN(boolean ensurePIN) {
		this.ensurePIN = ensurePIN;
	}



	public void setURL(String url) {
		this.url = url;
	}



	public void setID(String id) {
		this.id = id;
	}



	public void setSession(String session) {
		this.session = session;
	}



	void ensurePINVerification(SmartCard sc, int chvNumber) throws CardServiceException, ClassNotFoundException, CardTerminalException {
		CHVCardService chv = (CHVCardService) sc.getCardService(CHVCardService.class, true);
		boolean verified = true;

		try	{
			if (chv instanceof CHVCardServiceWithControl) {
				CHVCardServiceWithControl chvcc = (CHVCardServiceWithControl)chv;

				PasswordStatus pws = null;
				try	{
					pws = chvcc.getPasswordStatus(null, chvNumber);
				}
				catch(CardServiceUnexpectedStatusWordException e) {
					log(1, "Unexpected SW1/SW2 received from card. Supported card in reader ?");
					return;
				}

				if ((pws == PasswordStatus.BLOCKED) || (pws == PasswordStatus.NOTINITIALIZED)) {
					log(1, PINStatusString(pws));
					return;
				}
				if (pws != PasswordStatus.VERIFIED) {
					try	{
						verified = chvcc.verifyPassword(null, chvNumber, presetPIN);
					}
					catch(CardServiceUnexpectedStatusWordException e) {
						log(1,"PIN verification failed: " + e.getMessage());
					}
				}
			} else {
				verified = chv.verifyPassword(null, chvNumber, presetPIN);
			}
			log(1, "PIN verified: " + verified);
		}
		catch (CardServiceOperationFailedException | CardServiceInvalidCredentialException e) {
			log(1, "PIN verification cancelled by user");
		}
	}



	@Override
	public void cardInserted(CardTerminalEvent ctEvent) throws CardTerminalException {
	}



	public void closeCard() {
		rus.cancel();
		card = null;
	}



	@Override
	public void cardRemoved(CardTerminalEvent ctEvent)
			throws CardTerminalException {

		if (card != null) {
			CardTerminal ct = card.getCardID().getCardTerminal();
			if ((ct != null) && (ctEvent.getCardTerminal().equals(ct))) {
				closeCard();
				log(1, "Card removed");
			}
		}
	}



	@Override
	public void remoteNotify(int id, String message, int ttc) {
		this.lastMessageId = id;
		log(1, message);
	}



	@Override
	public void run() {
		EventGenerator.getGenerator().addCTListener(this);
		String ctname = this.card.getCardID().getCardTerminal().getName();
		try {
			if (this.ensurePIN) {
				ensurePINVerification(this.card, 1);
			}
			rus = (RemoteUpdateService)card.getCardService(RemoteUpdateService.class, true);
			if (rus == null) {
				log(1, "No remote update service available");
			} else {
				log(1, "Connecting to " + url);
				rus.update(url, session, this);
				log(1, "Connection of token " + id + " to " + url + " completed");
			}
		} catch (Exception e) {
			log(1, "Remote connection failed with " + e.getMessage());
		} finally {
			if (readerConfig != null) {
				readerConfig.approveTerminal(ctname);
			}
			EventGenerator.getGenerator().removeCTListener(this);
		}
	}
}
