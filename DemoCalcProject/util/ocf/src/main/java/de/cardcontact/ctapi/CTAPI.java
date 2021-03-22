/*
 * Copyright (c) 2018 CardContact Systems GmbH, Minden, Germany.
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

package de.cardcontact.ctapi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class CTAPI {

	public final static int OK			= 0;
	public final static int ERR_INVALID	= -1;
	public final static int ERR_CT		= -8;
	public final static int ERR_TRANS	= -10;
	public final static int ERR_MEMORY	= -11;
	public final static int ERR_HOST	= -127;

	public final static int ICC1		= 0x00;
	public final static int CT			= 0x01;
	public final static int HOST		= 0x02;
	public final static int ICC2		= 0x02;
	public final static int REMOTE_HOST = 0x05;

	public final static int NO_READER_NAME = 0x0001;

	private ICTAPIEvent eventListener = null;
	private HashMap<Integer, CTAPITerminal> map = null;

	private long ctInitPointer;
	private long ctClosePointer;
	private long ctDataPointer;
	private long ctListPointer;

	/**
	 * Initialize Host to Card Terminal connection.
	 *
	 * @param ctn the logical card terminal number assigned by the caller and used in subsequent CT_Data and CT_Close calls
	 * @param pn the port number representing the physical port
	 * @return the return code
	 */
	public native int CT_Init(int ctn, int pn);

	/**
	 * Close Host to Card Terminal connection
	 *
	 * @param ctn the logical card terminal number
	 * @return the return code
	 */
	public native int CT_Close(int ctn);

	/**
	 * Exchange an Application Protocol Data Unit (APDU) with the card terminal.
	 *
	 * The API works like the native CT_Data API, with exception of the lenr parameter which in inbound only.
	 * The value for lenr returned by the CT-API device is passed as result of the method instead
	 *
	 * @param ctn the logical card terminal number
	 * @param dad the destination address (ICC1, CT, ICC2...)
	 * @param sad the source address (usually HOST)
	 * @param lenc the number of bytes to be send from command. Must be less or equal command.length()
	 * @param command the outgoing command bytes
	 * @param lenr the number of bytes reserved in response. Must be less or equal response.length()
	 * @param response the buffer allocated to receive the response
	 * @return the number of bytes placed in response or one of the negative error codes
	 */
	public native int CT_Data(int ctn, byte dad, byte sad, byte[] command, int lenr, byte[] response);

	// Native list reader implementation
	private native int CT_List_native(byte[] readers, int options);

	// Sets the name of the shared lib which holds the CTAPI references for a specific card terminal
	private native void setCTAPILib(String libname) throws UnsatisfiedLinkError;


	// get the native library
	static 	{
		String arch = System.getProperty("os.arch");
		System.loadLibrary("ctapi-jni-" + arch);
	}

	/**
	 * Create a CT-API access object for a given shared object / DLL
	 *
	 * @param readername the shared object or DLL name
	 */
	public CTAPI(String libname) {
		ctInitPointer = 0;
		ctClosePointer = 0;
		ctDataPointer = 0;
		ctListPointer = 0;

		setCTAPILib(System.mapLibraryName(libname));
	}



	public List<CTAPITerminal> CT_List() throws CTAPIException {
		return CT_List(false);
	}



	public List<CTAPITerminal> CT_List(boolean noName) throws CTAPIException {
		ArrayList<CTAPITerminal> readers = new ArrayList<CTAPITerminal>(32);
		byte[] r = new byte[4096];

		int len = CT_List_native(r, noName ? NO_READER_NAME : 0);
		if (len < 0) {
			throw new CTAPIException("Failed enumerating CT-API devices (" + len + ")");
		}

		int ofs = 0;
		while(ofs < len) {
			int port = (r[ofs] & 0xFF) << 8 | (r[ofs + 1] & 0xFF);
			ofs += 2;
			int s = ofs;

			while ((ofs < len) && (r[ofs] != 0)) {
				ofs++;
			}

			byte[] namebin = new byte[ofs - s];
			System.arraycopy(r, s, namebin, 0, ofs - s);

			readers.add(new CTAPITerminal(this, port, new String(namebin)));

			ofs++;
		}

		return readers;
	}



	public void setEventListener(ICTAPIEvent eventListener) {
		this.eventListener = eventListener;
	}



	public void checkEvent() {
		boolean termsAdded = false;
		List<CTAPITerminal> terms;
		HashMap<Integer, CTAPITerminal> newMap = new HashMap<Integer, CTAPITerminal>();

		if (this.eventListener == null) {
			throw new RuntimeException("No event listener defined");
		}

		if (this.map != null) {
			// Obtain a quick list of card readers
			// Quick, because no reader names are determined
			try	{
				terms = CT_List(true);
			}
			catch(CTAPIException e) {
				return;
			}

			// Remove all existing terminals from hash map to determine
			// terminals that are removed
			for (CTAPITerminal term : terms) {
				CTAPITerminal et = this.map.remove(term.getPort());
				if (et == null) {
					termsAdded = true;
				} else {
					newMap.put(et.getPort(), et);
				}
			}

			if (!this.map.isEmpty()) {
				terms = new ArrayList<CTAPITerminal>();
				for (CTAPITerminal t : this.map.values()) {
					terms.add(t);
				}
				this.eventListener.terminalsRemoved(terms);
			}
		} else {
			termsAdded = true;
		}

		if (termsAdded) {
			List<CTAPITerminal> addedterms = new ArrayList<CTAPITerminal>();
			try	{
				terms = CT_List(false);
			}
			catch(CTAPIException e) {
				// Make sure we preserve the old state
				this.map = newMap;
				return;
			}

			for (CTAPITerminal term : terms) {
				if (!newMap.containsKey(term.getPort())) {
					newMap.put(term.getPort(), term);
					addedterms.add(term);
				}
			}
			this.eventListener.terminalsAdded(addedterms);
		}
		this.map = newMap;
	}
}
