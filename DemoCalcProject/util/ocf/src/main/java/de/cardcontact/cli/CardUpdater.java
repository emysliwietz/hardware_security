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

import java.io.IOException;
import java.util.Enumeration;

import de.cardcontact.opencard.factory.IsoCardServiceFactory;
import de.cardcontact.opencard.factory.RemoteClientCardServiceFactory;
import de.cardcontact.opencard.factory.SmartCardHSMCardServiceFactory;
import de.cardcontact.opencard.service.remoteclient.RemoteClientCardService;
import de.cardcontact.opencard.terminal.smartcardio.SmartCardIOFactory;
import opencard.core.OpenCardException;
import opencard.core.service.CardRequest;
import opencard.core.service.CardServiceFactory;
import opencard.core.service.CardServiceRegistry;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalFactory;
import opencard.core.terminal.CardTerminalRegistry;



/**
 * Card remote update command line tool.
 */
public class CardUpdater implements CardUpdaterLog {

	private String readerName = null;
	private String url = null;
	private String session = null;
	private byte[] pin = null;
	private int verbose = 1;
	private boolean reset = true;
	private boolean listReaders = false;
	private boolean password = false;
	private boolean showLog = false;
	private boolean autoConnect = false;
	private TerminalManager terminalManager;



	public CardUpdater() {
		terminalManager = new TerminalManager();
	}



	@Override
	public void log(int level, String msg) {
		if (verbose >= level) {
			System.out.println(msg);
		}
	}



	@Override
	public int getVerbosityLevel() {
		return verbose;
	}



	/**
	 * Configure and start OCF
	 *
	 * @throws OpenCardException
	 * @throws ClassNotFoundException
	 */
	private void setupOCF() throws OpenCardException, ClassNotFoundException {
		SmartCard.startup();
		CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();
		CardTerminalFactory ctf = new SmartCardIOFactory();
		String param[] = { "*", "PCSC" };
		ctf.createCardTerminals(ctr, param);

		CardServiceRegistry csr = CardServiceRegistry.getRegistry();
		CardServiceFactory csf = new RemoteClientCardServiceFactory();
		csr.add(csf);
		csf = new SmartCardHSMCardServiceFactory();
		csr.add(csf);
		csf = new IsoCardServiceFactory();
		csr.add(csf);
	}



	/**
	 * Display help
	 */
	private void help() {
		System.out.println("Usage: java -jar ocf-cc.jar [-r <readername>] [-s <id>] [-n] [-l] [-w] [-v] [<url>]\n");
		System.out.println("-n\t\tNo card reset at end of session");
		System.out.println("-s <id>\t\tSession id");
		System.out.println("-a\t\tAuto connect if inserted device has provisioning URL");
		System.out.println("-w\t\tOpen log window");
		System.out.println("-l\t\tList reader names");
		System.out.println("-v\t\tVerbose");
		System.out.println("-q\t\tQuiet");
		System.out.println("-p\t\tPassword verification");
		System.out.println("An URL on the command line deactivates the daemon mode and connects directly with that URL");
	}



	/**
	 * Decode command line arguments
	 *
	 * @param args Arguments passed on the command line
	 * @return true if arguments valid
	 */
	private boolean decodeArgs(String[] args) {
		int i = 0;

		while (i < args.length) {
			if (args[i].equals("-r")) {
				readerName = args[++i];
			} else if (args[i].equals("-s")) {
				session = args[++i];
			} else if (args[i].equals("-v")) {
				verbose++;
			} else if (args[i].equals("-q")) {
				verbose--;
			} else if (args[i].equals("-n")) {
				reset = false;
			} else if (args[i].equals("-a")) {
				autoConnect = true;
			} else if (args[i].equals("-l")) {
				listReaders = true;
			} else if (args[i].equals("-w")) {
				showLog = true;
			} else if (args[i].equals("--")) {
			} else if (args[i].equals("-p")) {
				password = true;
				if ((i + 1 < args.length) && !args[i + 1].startsWith("-")) {
					i++;
					pin = args[i].getBytes();
				}
			} else if (args[i].charAt(0) == '-') {
				log(1, "Unknown option " + args[i]);
				return false;
			} else {
				url = args[i];
			}
			i++;
		}

		return true;
	}



	private void listReaders() {
		CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();
		Enumeration ctlist = ctr.getCardTerminals();

		if (listReaders) {
			System.out.println("Available card terminals:");
			while(ctlist.hasMoreElements()) {
				CardTerminal ct = (CardTerminal)ctlist.nextElement();
				System.out.println(" " + ct.getName());
			}
			System.out.println("");
		}
	}



	private void startDaemon() throws IOException {
		if (readerName != null) {
			terminalManager.setSelectedTerminal(readerName);
		}
		CardUpdaterDaemon updaterDaemon = new CardUpdaterDaemon(this, terminalManager, new URLVerifier());
		updaterDaemon.setAutoConnect(autoConnect);
		updaterDaemon.setEnsurePIN(password);
		if (pin != null) {
			updaterDaemon.setPIN(pin);
		}
		TrayView view = new TrayView(terminalManager);
		if (this.showLog) {
			view.showLog();
		}
		Thread daemonThread = new Thread(updaterDaemon, "Redirect Handler");
		daemonThread.setDaemon(true);
		daemonThread.start();
	}



	private void connectToServer() throws OpenCardException, ClassNotFoundException {
		CardTerminal ct = null;
		CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();
		if (readerName != null) {
			ct = ctr.cardTerminalForName(readerName);

			if (ct == null) {
				log(1, "Card reader " + readerName + " not found");
				System.exit(1);
			}
			log(1, "Using reader " + readerName);
		}

		CardRequest cr = new CardRequest(CardRequest.ANYCARD, ct, RemoteClientCardService.class);
		cr.setTimeout(0);
		if (ct == null) {
			cr.setFilter(terminalManager);
		}
		SmartCard sc = SmartCard.waitForCard(cr);
		if (sc == null) {
			log(1, "No card in reader");
			return;
		}

		if (getVerbosityLevel() > 1) {
			sc.setAPDUTracer(new APDUTracerLogAdapter(this));
		}

		CardConnectorDaemon ccd = new CardConnectorDaemon(this, null, sc);
		if (pin != null) {
			ccd.setPIN(pin);
		}
		ccd.setEnsurePIN(password);
		ccd.setURL(url);
		ccd.setSession(session);
		ccd.run();

		if (reset) {
			try	{
				sc.reset(false);
			}
			catch(Exception e) {
				// Ignore, as card could have been removed
			}
		}
		sc.close();
	}



	public void run(String[] args) {
		if (!decodeArgs(args)) {
			help();
			System.exit(1);
		}
		try	{
			setupOCF();
			log(1, SmartCard.getVersion());

			if (listReaders) {
				listReaders();
			} else {
				if (url == null) {
					startDaemon();
				} else {
					connectToServer();
				}
			}
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		finally {
			try	{
				if (url != null) {
					SmartCard.shutdown();
				}
			}
			catch(Exception e) {
				// Ignore
			}
		}
	}



	public static void main(String[] args) {
		CardUpdater cu = new CardUpdater();
		cu.run(args);
	}
}
