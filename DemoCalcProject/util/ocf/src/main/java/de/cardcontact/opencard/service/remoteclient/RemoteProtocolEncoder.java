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

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.GPTLV_Generic;
import de.cardcontact.tlv.NativeTLVList;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.TLVDataSizeException;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.TagSizeException;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;

/**
 * Encode a list of RemoteProtocolUnits for transfer using RAMOverHttp encoding
 *
 * @author asc
 *
 */
public class RemoteProtocolEncoder {

	private static final int COMMAND_SCRIPTING_TEMPLATE = 0xAA;
	private static final int COMMAND_APDU = 0x22;
	private static final int RESPONSE_SCRIPTING_TEMPLATE = 0xAB;
	private static final int INITIATION_TEMPLATE = 0xE8;
	private static final int EXECUTED_COMMANDS = 0x80;
	private static final int RESPONSE_APDU = 0x23;
	private static final int INTEGER = 0x02;
	private static final int UTF8String = 0x0C;
	private static final int TTC = 0xC3;
	private static final int RESET = 0xC0;
	private static final int ATR = 0xC0;
	private static final int MAXCAPDU = 0xC1;
	private static final int MAXRAPDU = 0xC2;
	private static final int NOTIFY = 0xE0;
	private static final int CLOSE = 0xE1;
	private static final int VERSION = 0xE2;

	private int executedCommands = 0;

	ArrayList<RemoteProtocolUnit> rpus= new ArrayList<RemoteProtocolUnit>(1);

	public RemoteProtocolEncoder() {
	}



	public void setExecutedCommands(int executedCommands) {
		this.executedCommands = executedCommands;
	}



	public int getExecutedCommands() {
		return this.executedCommands;
	}



	public void add(RemoteProtocolUnit rpu) {
		rpus.add(rpu);
	}



	public List<RemoteProtocolUnit> getRemoteProtocolUnits() {
		return rpus;
	}



	private RemoteProtocolUnit decodeRPU(RemoteProtocolUnit.Action action, byte[] rpu) throws TLVEncodingException {
		int id = 0;
		int ttc = 0;
		String str = null;

		try {
			NativeTLVList list = new NativeTLVList(rpu);

			for (int i = 0; i < list.getLength(); i++) {
				GPTLV_Generic rpuenc = list.get(i);

				switch(rpuenc.getTag()) {
				case INTEGER:
					id = (new BigInteger(rpuenc.getValue())).intValue();
					break;
				case UTF8String:
					str = new String(rpuenc.getValue(), "UTF-8");
					break;
				case TTC:
					ttc = (new BigInteger(rpuenc.getValue())).intValue();
					break;
				}
			}
		} catch (TagSizeException e) {
			throw new TLVEncodingException();
		} catch (TLVDataSizeException e) {
			throw new TLVEncodingException();
		} catch (UnsupportedEncodingException e) {
			throw new TLVEncodingException();
		}

		return new RemoteProtocolUnit(action, id, str, ttc);
	}



	public byte[] encodeCommandScriptingTemplate() {

		ConstructedTLV cst;

		try	{
			cst = new ConstructedTLV(COMMAND_SCRIPTING_TEMPLATE);

			for (RemoteProtocolUnit rpu : rpus) {
				switch(rpu.getAction()) {
				case APDU:
					CommandAPDU com = (CommandAPDU)rpu.getPayload();
					cst.add(new PrimitiveTLV(COMMAND_APDU, com.getBytes()));
					break;
				case RESET:
					cst.add(new PrimitiveTLV(RESET, new byte[] {} ));
					break;
				case NOTIFY:
					ConstructedTLV notify = new ConstructedTLV(NOTIFY);
					notify.add(new PrimitiveTLV(INTEGER, BigInteger.valueOf(rpu.getId()).toByteArray()));
					notify.add(new PrimitiveTLV(UTF8String, rpu.getMessage().getBytes("UTF-8")));
					if (rpu.getTimeToCompletion() > 0) {
						notify.add(new PrimitiveTLV(TTC, BigInteger.valueOf(rpu.getTimeToCompletion()).toByteArray()));
					}
					cst.add(notify);
					break;
				case CLOSE:
					ConstructedTLV closemsg = new ConstructedTLV(CLOSE);
					closemsg.add(new PrimitiveTLV(UTF8String, rpu.getMessage().getBytes("UTF-8")));
					cst.add(closemsg);
					break;
				}
			}
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}

		return cst.getBytes();
	}



	public void decodeCommandScriptingTemplate(byte[] cst) throws TLVEncodingException {
		try {
			NativeTLVList list = new NativeTLVList(cst);
			GPTLV_Generic csttlv = list.get(0);

			if (csttlv.getTag() != COMMAND_SCRIPTING_TEMPLATE) {
				throw new TLVEncodingException("Expected tag 'AA' in Command Scripting Template");
			}

			list = new NativeTLVList(csttlv.getValue());

			for (int i = 0; i < list.getLength(); i++) {
				GPTLV_Generic rpuenc = list.get(i);

				switch(rpuenc.getTag()) {
				case COMMAND_APDU:
					CommandAPDU apdu = new CommandAPDU(rpuenc.getValue());
					rpus.add(new RemoteProtocolUnit(apdu));
					break;
				case RESET:
					rpus.add(new RemoteProtocolUnit(RemoteProtocolUnit.Action.RESET));
					break;
				case NOTIFY:
					rpus.add(decodeRPU(RemoteProtocolUnit.Action.NOTIFY, rpuenc.getValue()));
					break;
				case CLOSE:
					rpus.add(decodeRPU(RemoteProtocolUnit.Action.CLOSE, rpuenc.getValue()));
					break;
				}
			}
		} catch (TagSizeException e) {
			throw new TLVEncodingException();
		} catch (TLVDataSizeException e) {
			throw new TLVEncodingException();
		}
	}



	public byte[] encodeResponseScriptingTemplate() {

		ConstructedTLV cst;

		try	{
			cst = new ConstructedTLV(RESPONSE_SCRIPTING_TEMPLATE);

			for (RemoteProtocolUnit rpu : rpus) {
				switch(rpu.getAction()) {
				case APDU:
					ResponseAPDU com = (ResponseAPDU)rpu.getPayload();
					cst.add(new PrimitiveTLV(RESPONSE_APDU, com.getBytes()));
					break;
				case RESET:
					cst.add(new PrimitiveTLV(ATR, ((RemoteCardSpec)rpu.getPayload()).getCardID().getATR()));
					break;
				case CLOSE:
					ConstructedTLV closemsg = new ConstructedTLV(CLOSE);
					closemsg.add(new PrimitiveTLV(UTF8String, rpu.getMessage().getBytes("UTF-8")));
					cst.add(closemsg);
					break;
				}
			}
			cst.add(new PrimitiveTLV(EXECUTED_COMMANDS, new byte[] { (byte) this.executedCommands } ));
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}

		return cst.getBytes();
	}



	public void decodeResponseScriptingTemplate(byte[] cst) throws TLVEncodingException {
		try {
			NativeTLVList list = new NativeTLVList(cst);
			GPTLV_Generic csttlv = list.get(0);

			if (csttlv.getTag() != RESPONSE_SCRIPTING_TEMPLATE) {
				throw new TLVEncodingException("Expected tag 'AB' in Response Scripting Template");
			}

			list = new NativeTLVList(csttlv.getValue());

			for (int i = 0; i < list.getLength(); i++) {
				GPTLV_Generic rpuenc = list.get(i);

				switch(rpuenc.getTag()) {
				case RESPONSE_APDU:
					ResponseAPDU apdu = new ResponseAPDU(rpuenc.getValue());
					rpus.add(new RemoteProtocolUnit(apdu));
					break;
				case EXECUTED_COMMANDS:
					this.executedCommands = rpuenc.getValue()[0] & 0xFF;
					break;
				case ATR:
					CardID cardid = new CardID(rpuenc.getValue());
					rpus.add(new RemoteProtocolUnit(new RemoteCardSpec(cardid)));
					break;
				case CLOSE:
					rpus.add(decodeRPU(RemoteProtocolUnit.Action.CLOSE, rpuenc.getValue()));
					break;
				}
			}
		} catch (TagSizeException e) {
			throw new TLVEncodingException();
		} catch (CardTerminalException e) {
			throw new TLVEncodingException();
		} catch (TLVDataSizeException e) {
			throw new TLVEncodingException();
		}
	}



	public byte[] encodeInitiationTemplate() {

		ConstructedTLV pit;

		try	{
			pit = new ConstructedTLV(INITIATION_TEMPLATE);

			for (RemoteProtocolUnit rpu : rpus) {
				switch(rpu.getAction()) {
				case RESET:
					RemoteCardSpec rcs = (RemoteCardSpec)rpu.getPayload();
					CardID cardId = rcs.getCardID();

					pit.add(new PrimitiveTLV(ATR, cardId.getATR()));

					Properties features = cardId.getCardTerminal().features();
					if (features.containsKey("maxCAPDUSize")) {
						int i = Integer.parseInt(features.getProperty("maxCAPDUSize"));
						pit.add(new PrimitiveTLV(MAXCAPDU, BigInteger.valueOf(i).toByteArray()));
					}
					if (features.containsKey("maxRAPDUSize")) {
						int i = Integer.parseInt(features.getProperty("maxRAPDUSize"));
						pit.add(new PrimitiveTLV(MAXRAPDU, BigInteger.valueOf(i).toByteArray()));
					}

					break;
				}
			}
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}

		return pit.getBytes();
	}



	public void decodeInitiationTemplate(byte[] pit) throws TLVEncodingException {
		try {
			NativeTLVList list = new NativeTLVList(pit);
			GPTLV_Generic pittlv = list.get(0);

			if (pittlv.getTag() != INITIATION_TEMPLATE) {
				throw new TLVEncodingException("Expected tag 'E8' in Initiation Template");
			}

			list = new NativeTLVList(pittlv.getValue());

			RemoteCardSpec rcs = null;
			int len;

			for (int i = 0; i < list.getLength(); i++) {
				GPTLV_Generic rpuenc = list.get(i);

				switch(rpuenc.getTag()) {
				case ATR:
					CardID cardid = new CardID(rpuenc.getValue());
					rcs = new RemoteCardSpec(cardid);
					rpus.add(new RemoteProtocolUnit(rcs));
					break;
				case MAXCAPDU:
					if (rcs == null) {
						throw new TLVEncodingException("MAXCAPU out of sequence");
					}
					len = (new BigInteger(rpuenc.getValue())).intValue();
					rcs.setMaxCAPDU(len);
					break;
				case MAXRAPDU:
					if (rcs == null) {
						throw new TLVEncodingException("MAXRAPU out of sequence");
					}
					len = (new BigInteger(rpuenc.getValue())).intValue();
					rcs.setMaxRAPDU(len);
					break;
				}
			}
		} catch (TagSizeException e) {
			throw new TLVEncodingException();
		} catch (CardTerminalException e) {
			throw new TLVEncodingException();
		} catch (TLVDataSizeException e) {
			throw new TLVEncodingException();
		}
	}



	static public boolean isInitiation(byte[] pit) {
		return ((pit[0] & 0xFF) == INITIATION_TEMPLATE);
	}
}
