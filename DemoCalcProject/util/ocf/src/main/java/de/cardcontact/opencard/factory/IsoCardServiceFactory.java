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

import de.cardcontact.opencard.service.isocard.IsoCardService;
import de.cardcontact.opencard.service.isocard.IsoConstants;
import de.cardcontact.opencard.service.isocard.TransparentCardService;
import opencard.core.service.CardServiceFactory;
import opencard.core.service.CardServiceScheduler;
import opencard.core.service.CardType;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminalException;



/**
 * Factory used to create an card service for ISO 7816-4 / -8 / -9 compliant cards
 *
 * @author  Andreas Schwier
 */
public class IsoCardServiceFactory extends CardServiceFactory  {
	private final static byte[] Micardo20 = 			{ (byte)0x00,(byte)0x00,(byte)0x68,(byte)0xD2,(byte)0x76,(byte)0x00,(byte)0x00,(byte)0x28,(byte)0xFF,(byte)0x05,(byte)0x1E };
	private final static byte[] Micardo21 = 			{ (byte)0x00,(byte)0x00,(byte)0x68,(byte)0xD2,(byte)0x76,(byte)0x00,(byte)0x00,(byte)0x28,(byte)0xFF,(byte)0x05,(byte)0x24 };
	private final static byte[] Micardo23 = 			{ (byte)0x00,(byte)0x00,(byte)0x68,(byte)0xD2,(byte)0x76,(byte)0x00,(byte)0x00,(byte)0x28,(byte)0xFF,(byte)0x05,(byte)0x23 };
	private final static byte[] Starcos30 = 			{ (byte)0x80,(byte)0x67,(byte)0x04,(byte)0x12,(byte)0xB0,(byte)0x02,(byte)0x01,(byte)0x82,(byte)0x01 };
	private final static byte[] Starcos30_P5CC036 = 	{ (byte)0x80,(byte)0x67,(byte)0x04,(byte)0x14,(byte)0xB0,(byte)0x01,(byte)0x01,(byte)0x82,(byte)0x01 };
	private final static byte[] JCOP41CL1 =				{ (byte)0x41,(byte)0x20,(byte)0x00,(byte)0x11,(byte)0x33,(byte)0xB0,(byte)0x4A,(byte)0x43,(byte)0x4F,(byte)0x50,(byte)0x34,(byte)0x31,(byte)0x56,(byte)0x32 };
	private final static byte[] JCOP41CL2 =				{ (byte)0x41,(byte)0x28,(byte)0x00,(byte)0x11,(byte)0x33,(byte)0xB0,(byte)0x4A,(byte)0x43,(byte)0x4F,(byte)0x50,(byte)0x34,(byte)0x31,(byte)0x56,(byte)0x32 };
	private final static byte[] JCOP41 =				{ (byte)0x4A,(byte)0x43,(byte)0x4F,(byte)0x50,(byte)0x34,(byte)0x31,(byte)0x56,(byte)0x32,(byte)0x32 };
	private final static byte[] TCOSICAOPHICL =			{ (byte)0x41,(byte)0x20,(byte)0x00,(byte)0x41,(byte)0x22,(byte)0xE1,(byte)0x02,(byte)0x00,(byte)0x64,(byte)0x04,(byte)0x00,(byte)0x03,(byte)0x00,(byte)0x31 };
	private final static byte[] TCOSICAOIFXCL =			{ (byte)0x42,(byte)0x00,(byte)0x01,(byte)0x33,(byte)0xE1 };
	private final static byte[] EC = 					{ (byte)0x65,(byte)0x63 };

	private final static Logger logger = LoggerFactory.getLogger(IsoCardServiceFactory.class);


	/** Creates new IsoCardServiceFactory */
	public IsoCardServiceFactory()
	{
		super();
	}



	@Override
	protected CardType getCardType(CardID cid, CardServiceScheduler scheduler)
	throws CardTerminalException
	{
		byte[] hb;
		int i;

		Vector serviceClasses = new Vector();
		serviceClasses.addElement(TransparentCardService.class);

		hb = cid.getHistoricals();

		i = 0;
		if (hb != null) {
			if ((hb[0] != 0x00) && (hb[0] != (byte)0x80)) {
				logger.info("[IsoCardServiceFactory.getCardType] Historical bytes do not indicate an ISO card");
				if (partialMatch(hb, JCOP41CL1)) {
					i = IsoConstants.CARDTYPE_JCOP41;
					serviceClasses.addElement(IsoCardService.class);
				} else if (partialMatch(hb, JCOP41CL2)) {
					i = IsoConstants.CARDTYPE_JCOP41;
					serviceClasses.addElement(IsoCardService.class);
				} else if (partialMatch(hb, JCOP41)) {
					i = IsoConstants.CARDTYPE_JCOP41;
					serviceClasses.addElement(IsoCardService.class);
				} else if (partialMatch(hb, TCOSICAOPHICL)) {
					i = IsoConstants.CARDTYPE_TCOSICAO30;
					serviceClasses.addElement(IsoCardService.class);
				} else if (partialMatch(hb, TCOSICAOIFXCL)) {
					i = IsoConstants.CARDTYPE_TCOSICAO30;
					serviceClasses.addElement(IsoCardService.class);
				} else if (partialMatch(hb, EC)) {
					i = IsoConstants.CARDTYPE_EC;
					serviceClasses.addElement(IsoCardService.class);
				} else {
					serviceClasses.addElement(IsoCardService.class);
				}
			} else {
				serviceClasses.addElement(IsoCardService.class);
				if (partialMatch(hb, Micardo20)) {
					i = IsoConstants.CARDTYPE_MICARDO20;
				} else if (partialMatch(hb, Micardo21)) {
					i = IsoConstants.CARDTYPE_MICARDO21;
				} else if (partialMatch(hb, Micardo23)) {
					i = IsoConstants.CARDTYPE_MICARDO23;
				} else if (partialMatch(hb, Starcos30)) {
					i = IsoConstants.CARDTYPE_STARCOS30;
				} else if (partialMatch(hb, Starcos30_P5CC036)) {
					i = IsoConstants.CARDTYPE_STARCOS30;
				}
			}
		} else {
			serviceClasses.addElement(IsoCardService.class);
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
