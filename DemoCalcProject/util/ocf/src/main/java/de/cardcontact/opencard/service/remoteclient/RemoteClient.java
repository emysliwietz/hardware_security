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

package de.cardcontact.opencard.service.remoteclient;

import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.tlv.TLVDataSizeException;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.TagSizeException;
import opencard.core.OpenCardException;
import opencard.core.service.CardService;
import opencard.core.service.CardServiceException;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;
import opencard.opt.util.APDUInterface;

public class RemoteClient {
	private final static Logger logger = LoggerFactory.getLogger(RemoteClient.class);

	private HttpURLConnection connection;
	private String serverURL;
	private String session = null;
	private final static String contentType = "application/org.openscdp-content-mgt-response;version=1.0";
	private CardService cardService;



	public RemoteClient(CardService cardService, String serverURL, String sessionId) {
		if (!(cardService instanceof APDUInterface)) {
			throw new RuntimeException("CardService must implement the APDUInterface");
		}
		this.cardService = cardService;
		this.serverURL = serverURL;

		if (sessionId != null) {
			if (sessionId.contains("=")) {
				this.session = sessionId;
			} else {
				this.session = "JSESSIONID=" + sessionId;
			}
		}
	}



	/**
	 * Read full binary contents
	 *
	 * @param connection the http connection
	 * @return null if no data returned or a byte array containing the response
	 *
	 * @throws IOException
	 */
	private byte[] readFully(HttpURLConnection connection) throws IOException {
		int resplen = connection.getContentLength();

		if (resplen <= 0) {
			return null;
		}

		byte[] resp = new byte[resplen];
		InputStream is = connection.getInputStream();

		try	{
			int offset = 0;
			int bread = 0;
			while ((resplen > 0) && (bread = is.read(resp, offset, resplen)) != -1) {
				offset += bread;
				resplen -= bread;
			}
		}
		finally {
			is.close();
		}

		return resp;
	}



	/**
	 * Connect to the remote administration server
	 *
	 * @param serverURL The url of the remote administration server
	 * @return the command scripting template
	 * @throws IOException
	 * @throws TLVEncodingException
	 */
	private byte[] initialConnect() throws IOException, TLVEncodingException {
		URL url = new URL(serverURL);
		connection = (HttpURLConnection) url.openConnection();
		connection.setDoInput(true);
		connection.setDoOutput(true);
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Content-Type", contentType);

		// Use the given sessionid if available
		if (session != null) {
			connection.addRequestProperty("Cookie", session);
		}

		RemoteProtocolEncoder rpe = new RemoteProtocolEncoder();
		rpe.add(new RemoteProtocolUnit(cardService.getCard().getCardID()));
		OutputStream writer = connection.getOutputStream();

		writer.write(rpe.encodeInitiationTemplate());
		writer.close();

		// The session returned from the server may differ from the given one
		String cookie = connection.getHeaderField("Set-Cookie");
		if (cookie != null) {
			session = cookie.split(";")[0];
		}

		byte[] data = readFully(connection);

		if (data == null) {
			throw new CardServiceException("No data received from server. HTTP code " + connection.getResponseCode() + " " + connection.getResponseMessage());
		}

		return data;
	}



	/**
	 * Send the Response Scripting Template to the server
	 * and obtain the next Command Scripting Template from the server
	 * if available.
	 *
	 * @param serverURL The url of the remote administration server
	 * @param rst The response APDU that will be send to the server
	 * @return The new command APDU or null if it's not exists.
	 * @throws IOException
	 * @throws TLVEncodingException
	 * @throws TagSizeException
	 * @throws TLVDataSizeException
	 */
	private byte[] processNext(byte[] rst) throws IOException, TLVEncodingException, TagSizeException, TLVDataSizeException {
		URL url = new URL(serverURL);

		connection = (HttpURLConnection) url.openConnection();
		connection.setDoInput(true);
		connection.setDoOutput(true);
		connection.setRequestMethod("POST");
		connection.addRequestProperty("Cookie", session);
		connection.setRequestProperty("Content-Type", contentType);

		DataOutputStream writer = new DataOutputStream(connection.getOutputStream());

		writer.write(rst);
		writer.close();

		return readFully(connection);
	}



	private RemoteProtocolUnit sendCommandAPDU(RemoteProtocolUnit rpu) throws OpenCardException{
		CommandAPDU capdu = (CommandAPDU)rpu.getPayload();
		ResponseAPDU res = ((APDUInterface)cardService).sendCommandAPDU(capdu);
		return new RemoteProtocolUnit(res);
	}



	private RemoteProtocolUnit resetCard(RemoteProtocolUnit rpu) throws CardTerminalException {
		CardID cid = cardService.getCard().reset(false);

		if (cid == null) {
			throw new CardTerminalException("Could not reset card");
		}
		return new RemoteProtocolUnit(cid);
	}



	private byte[] process(byte[] cst, RemoteNotificationListener notificationListener) throws TLVEncodingException {
		RemoteProtocolEncoder rpe = new RemoteProtocolEncoder();

		rpe.decodeCommandScriptingTemplate(cst);
		List<RemoteProtocolUnit> rpus = rpe.getRemoteProtocolUnits();

		rpe = new RemoteProtocolEncoder();

		int apdus = 0;

		try	{
			for (RemoteProtocolUnit rpu : rpus) {
				switch(rpu.getAction()) {
				case APDU:
					rpe.add(sendCommandAPDU(rpu));
					apdus++;
					break;
				case RESET:
					rpe.add(resetCard(rpu));
					break;
				case NOTIFY:
					if (notificationListener != null) {
						notificationListener.remoteNotify(rpu.getId(), rpu.getMessage(), rpu.getTimeToCompletion());
					}
					break;
				default:
					break;
				}
			}
		} catch(OpenCardException cte) {
			rpe.add(new RemoteProtocolUnit(RemoteProtocolUnit.Action.CLOSE, -1, cte.toString()));
		}

		rpe.setExecutedCommands(apdus);
		return rpe.encodeResponseScriptingTemplate();
	}



	public void cancel() {
		RemoteProtocolEncoder rpe = new RemoteProtocolEncoder();
		rpe.add(new RemoteProtocolUnit(RemoteProtocolUnit.Action.CLOSE, -1, "Session canceled"));

		try	{
			processNext(rpe.encodeResponseScriptingTemplate());
		}
		catch(Exception e) {
			logger.error("Cancel failed.", e);
		}
	}



	public void update(RemoteNotificationListener notificationListener) throws CardServiceException {

		try {
			byte[] cst = initialConnect();
			int code = connection.getResponseCode();
			while (code == 200) {
				byte[] rst = process(cst, notificationListener);
				cst = processNext(rst);
				code = connection.getResponseCode();
				logger.debug("HTTP Code " + code);
			}
			if (code != 204) {
				throw new CardServiceException("Connection to " + serverURL + " failed with HTTP code " + code);
			}
			logger.debug("Session " + session + " completed");
		} catch (FileNotFoundException e) {
			throw new CardServiceException("URL " + serverURL + " not found");
		} catch (IOException e) {
			throw new RemoteUpdateServiceNotAvailableException("IO error during connection to " + serverURL + "(" + e.toString() + ")");
		} catch (TLVEncodingException e) {
			throw new CardServiceException(e.toString());
		} catch (TagSizeException e) {
			throw new CardServiceException(e.toString());
		} catch (TLVDataSizeException e) {
			throw new CardServiceException(e.toString());
		}
	}
}
