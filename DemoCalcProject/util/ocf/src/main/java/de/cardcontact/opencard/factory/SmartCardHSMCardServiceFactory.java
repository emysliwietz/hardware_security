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

package de.cardcontact.opencard.factory;

import java.util.Enumeration;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.opencard.service.isocard.IsoConstants;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService;
import opencard.core.service.CardServiceFactory;
import opencard.core.service.CardServiceScheduler;
import opencard.core.service.CardType;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminalException;



/**
 * Factory creating SmartCard-HSM card services
 *
 * @author lew
 *
 */
public class SmartCardHSMCardServiceFactory extends CardServiceFactory {
	private final static byte[] SMARTCARDHSM =    { (byte)0x80, (byte)0x31, (byte)0x81, (byte)0x54, (byte)0x48, (byte)0x53, (byte)0x4D, (byte)0x31, (byte)0x73, (byte)0x80, (byte)0x21, (byte)0x40, (byte)0x81, (byte)0x07 };
//	private final static byte[] GENERIC_JCOP241 = { (byte)0x4A, (byte)0x43, (byte)0x4F, (byte)0x50, (byte)0x76, (byte)0x32, (byte)0x34, (byte)0x31 };
//	private final static byte[] GENERIC_JCOP242 = { (byte)0x4A, (byte)0x43, (byte)0x4F, (byte)0x50, (byte)0x32, (byte)0x34, (byte)0x32 };
//	private final static byte[] GENERIC_JCOP3 =   { (byte)0x80, (byte)0x73, (byte)0xC8, (byte)0x21, (byte)0x13, (byte)0x66, (byte)0x05, (byte)0x03, (byte)0x63, (byte)0x51, (byte)0x00, (byte)0x02 };
//	private final static byte[] SOC_JCOP =        { (byte)0x3B, (byte)0x80, (byte)0x80, (byte)0x01, (byte)0x01 };



	/* A logger for debugging output. */
	private final static Logger logger = LoggerFactory.getLogger(SmartCardHSMCardServiceFactory.class);

	@Override
	protected CardType getCardType(CardID cid, CardServiceScheduler scheduler) throws CardTerminalException {

		Vector<Class<SmartCardHSMCardService>> serviceClasses = new Vector<Class<SmartCardHSMCardService>>();

		byte[] hb = cid.getHistoricals();
		int i = 0;

//		if ((hb != null && (partialMatch(hb, SMARTCARDHSM) || partialMatch(hb, GENERIC_JCOP241) || partialMatch(hb, GENERIC_JCOP242) || partialMatch(hb, GENERIC_JCOP3))) ||
//				partialMatch(cid.getATR(), SOC_JCOP)) {
		if (hb != null && (partialMatch(hb, SMARTCARDHSM))) {
			i = IsoConstants.CARDTYPE_SC_HSM;
			serviceClasses.addElement(SmartCardHSMCardService.class);
		}

		CardType cardType = new CardType(i);
		cardType.setInfo(serviceClasses);
		return cardType;
	}



	@Override
	protected Enumeration getClasses(CardType type) {
		logger.debug("[getClasses] card type is " + type.getType());
		Vector serviceClasses = (Vector)type.getInfo();
		return serviceClasses.elements();
	}



	private static boolean partialMatch(byte[] hb, byte[] ref) {
		int i = 0;

		if (hb.length < ref.length)
			return false;

		for (; i < ref.length && hb[i] == ref[i]; i++);

		return i == ref.length;
	}
}
