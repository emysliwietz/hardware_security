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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.util.Timer;
import java.util.TimerTask;

import de.cardcontact.opencard.service.remoteclient.RemoteClientCardService;
import de.cardcontact.opencard.service.remoteclient.RemoteUpdateService;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService;
import opencard.core.OpenCardException;
import opencard.core.event.CTListener;
import opencard.core.event.CardTerminalEvent;
import opencard.core.event.EventGenerator;
import opencard.core.service.CardRequest;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalException;



/**
 * Daemon accepting requests from the local browser to initiate card update sessions with remote server
 *
 * @author asc
 *
 */
public class CardUpdaterDaemon extends CardConnectorDaemon implements CTListener {


	final static int SERVER_PORT = 27001;
	final static int closingDelay = 60;

	private ServerSocket server;
	private byte[] passedImage;
	private byte[] failedImage;
	private URLVerifier urlVerifier;
	private Timer timer = new Timer();
	private SmartCardCloser scc = null;
	private boolean autoConnect = false;



	public CardUpdaterDaemon(CardUpdaterLog logger, ReaderConfigurationModel readerConfig, URLVerifier urlVerifier) throws IOException {
		super(logger, readerConfig, null);
		server = new ServerSocket(SERVER_PORT, 0, InetAddress.getByName(null));		// Bind to localhost
		loadImages();
		this.urlVerifier = urlVerifier;
	}



	class SmartCardCloser extends TimerTask {
		CardUpdaterDaemon daemon;

		public SmartCardCloser(CardUpdaterDaemon daemon) {
			super();
			this.daemon = daemon;
		}



		@Override
		public void run() {
			if (this.daemon.card != null) {

				try	{
					this.daemon.card.close();
					this.daemon.log(1,"Smartcard closed");
				}
				catch(Exception e) {
					// Ignore
				}
				this.daemon.card = null;
			}
		}
	}



	public void setAutoConnect(boolean ac) {
		this.autoConnect = ac;
	}



	private byte[] loadImage(String name) throws IOException {
		InputStream is = CardUpdaterDaemon.class.getResourceAsStream(name);
		byte[] buffer = new byte[1024];
		int ofs = 0, len = buffer.length;
		int r;
		while((r = is.read(buffer, ofs, len)) > 0) {
			ofs += r;
			len -= r;
		}
		byte[] rb = new byte[ofs];
		System.arraycopy(buffer, 0, rb, 0, ofs);
		return rb;
	}



	void loadImages() throws IOException {
		passedImage = loadImage("passed.png");
		failedImage = loadImage("failed.png");
	}



	void serveResponse(Socket con, boolean passed) throws IOException {
		byte[] image = passed ? passedImage : failedImage;

		OutputStream os = con.getOutputStream();
		BufferedWriter out = new BufferedWriter(new OutputStreamWriter(os));

		out.write("HTTP/1.1 200 OK\r\n");
		out.write("Content-Length: " + image.length + "\r\n");
		out.write("\r\n");
		out.flush();

		os.write(image);
		os.close();
	}



	private boolean handleRequest() {
		Socket con = null;
		boolean passed = false;

		try	{
			log(1, "Daemon waiting on port " + SERVER_PORT + "...");
			try	{
				con = server.accept();
			}
			catch(SocketException se) {
				return false;
			}

			if (this.scc != null){
				this.scc.cancel();
			}

			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));

			String methodAndUrl = in.readLine();
			if (methodAndUrl == null)		// Skip empty connects
				return true;

			log(2, methodAndUrl);

			String s;
			while (((s = in.readLine()) != null) && !s.equals("")) {
				log(2, s);
			}

			int sofs = methodAndUrl.indexOf('?');
			if (methodAndUrl.startsWith("GET /") && (sofs > 0)) {
				int eofs = methodAndUrl.lastIndexOf(' ');
				String query = methodAndUrl.substring(sofs + 1, eofs);
				String[] params = query.split("&");
				String url = null;
				String sessionId = null;
				boolean pinRequired = false;
				int chvNumber = -1;

				for (String p : params) {
					String[] keyvalue = p.split("=");
					if (keyvalue[0].equals("url")) {
						url = keyvalue[1];
					} else if (keyvalue[0].equals("sessionId")) {
						sessionId = keyvalue[1];
					} else if (keyvalue[0].equals("pinrequired")) {
						pinRequired = true;
						chvNumber = Integer.parseInt(keyvalue[1]);
					}
				}

				if (url == null) {
					log(1, "No URL defined in redirect");
					return true;
				}

				boolean valid = verifyURL(url);
				if (!valid) {
					return true;
				}

				try	{
					if (this.card != null) {
						// Check if filter has changed and card is no longer valid
						if (!readerConfig.isCandidate(this.card.getCardID())) {
							closeCard();
							log(1, "Reader changed");
						}
					}

					if (this.card == null) {
						CardRequest cr = new CardRequest(CardRequest.ANYCARD, null, RemoteClientCardService.class);
						cr.setTimeout(0);
						cr.setFilter(readerConfig);

						this.card = SmartCard.waitForCard(cr);
					}

					if (this.card == null) {
						log(1, "No card in reader");
					} else {
						SmartCard sc = this.card;

						if (logger.getVerbosityLevel() > 1) {
							sc.setAPDUTracer(new APDUTracerLogAdapter(logger));
						}

						if (pinRequired) {
							ensurePINVerification(sc, chvNumber);
						}

						log(1, "Connecting to " + url);

						this.rus = (RemoteUpdateService)sc.getCardService(RemoteClientCardService.class, true);
						this.rus.update(url, sessionId, this);
						this.scc = new SmartCardCloser(this);
						this.timer.schedule(this.scc, 1000 * closingDelay);
						passed = true;
					}
				}
				catch(Exception e) {
					log(1, e.getMessage());
					e.printStackTrace();
					if (this.card!= null) {
						this.card.close();
						this.card = null;
					}
				}
			}
			serveResponse(con, passed);
		}
		catch(IOException e) {
			e.printStackTrace();
		}
		finally {
			if (con != null) {
				try	{
					con.close();
				}
				catch(IOException e) {
					// Ignore
				}
			}
		}
		return true;
	}



	private boolean verifyURL(String url) {
		if (urlVerifier == null) {
			return true;
		}
		log(2, "Verify URL " + url);

		try {
			URL urlparts = new URL(url);
			url = urlparts.getProtocol() + "://" + urlparts.getHost();
		} catch (MalformedURLException e) {
			return false;
		}

		return urlVerifier.verifyURL(url);
	}



	public void stop() {
		if (server != null) {
			try {
				server.close();
			} catch (IOException e) {
				// Ignore
			}
		}
	}



	@Override
	public void cardInserted(CardTerminalEvent ctEvent)
			throws CardTerminalException {
		if (!this.autoConnect) {
			return;
		}

		CardTerminal ct = ctEvent.getCardTerminal();
		CardRequest cr = new CardRequest(CardRequest.ANYCARD, ct, SmartCardHSMCardService.class);
		SmartCard sc = SmartCard.getSmartCard(ctEvent, cr);
		if (sc == null) {
			log(1, "Inserted card is not a SmartCard-HSM");
			return;
		}

		if (logger.getVerbosityLevel() > 1) {
			sc.setAPDUTracer(new APDUTracerLogAdapter(logger));
		}

		try {
			SmartCardHSMCardService cs = (SmartCardHSMCardService)sc.getCardService(SmartCardHSMCardService.class, false);
			String url = cs.getProvisioningURL();
			if (url == null) {
				log(1, "No provisioning URL found");
				return;
			}
			String id = cs.getId();

			if (urlVerifier != null) {
				if (!urlVerifier.verifyURLforToken(url, id)) {
					log(1, "User denied auto connect");
					return;
				}
			}

			readerConfig.ignoreTerminal(ct.getName());
			CardConnectorDaemon ccd = new CardConnectorDaemon(logger, readerConfig, sc);
			ccd.setPIN(presetPIN);
			ccd.setEnsurePIN(ensurePIN);
			ccd.setID(id);
			ccd.setURL(url);
			Thread daemonThread = new Thread(ccd, "Background connector");
			daemonThread.setDaemon(true);
			daemonThread.start();

		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OpenCardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Ignore
	}



	@Override
	public void closeCard() {
		super.closeCard();
		scc.cancel();
	}


	@Override
	public void run() {
		EventGenerator.getGenerator().addCTListener(this);
		while(handleRequest());
		timer.cancel();
		EventGenerator.getGenerator().removeCTListener(this);
	}
}
