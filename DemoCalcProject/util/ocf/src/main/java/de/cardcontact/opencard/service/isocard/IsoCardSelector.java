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

package de.cardcontact.opencard.service.isocard;

import java.util.Enumeration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.opencard.security.SecureChannel;
import de.cardcontact.opencard.security.SecureChannelCredential;
import de.cardcontact.opencard.service.CardServiceUnexpectedStatusWordException;
import opencard.core.service.CardChannel;
import opencard.core.service.InvalidCardChannelException;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.terminal.SlotChannel;
import opencard.core.util.APDUTracer;
import opencard.core.util.HexString;
import opencard.opt.iso.fs.CardFileAppID;
import opencard.opt.iso.fs.CardFileFileID;
import opencard.opt.iso.fs.CardFileInfo;
import opencard.opt.iso.fs.CardFilePath;
import opencard.opt.iso.fs.CardFilePathComponent;
import opencard.opt.iso.fs.CardFileShortFileID;
import opencard.opt.service.CardServiceObjectNotAvailableException;



/**
 * Class to support the selection of card objects and the maintenance of the
 * current selection status
 *
 * @author Andreas Schwier (info@cardcontact.de)
 */
public class IsoCardSelector {
	private final static CardFileFileID root_file = new CardFileFileID((short)0x3F00);
	private final static Logger logger = LoggerFactory.getLogger(IsoCardSelector.class);

	public final static int ALREADY_SELECTED = -1;
	public final static int NEWLY_SELECTED = 0;

	private CardFilePath rootPath;
	private CardFilePath currentPath;
	private CardFileInfo currentFCI;
	private boolean isElementaryFile;
	private byte selectFCI;
	private boolean leInSelectEnabled;
	private boolean supportsP1InSelect;



	/**
	 * CTOR for IsoCardState object
	 */
	public IsoCardSelector(CardFilePath root) {
		rootPath = root;
		currentPath = root;
		currentFCI = null;
		selectFCI = IsoConstants.SO_RETURNFCP;
		isElementaryFile = false;
		leInSelectEnabled = true;
		supportsP1InSelect = true;
	}



	/**
	 * Returns the currently selected path
	 *
	 * @return the currently selected path
	 */
	public CardFilePath getPath() {
		return currentPath;
	}



	/**
	 * Returns the CardFileInfo of the last selected file
	 *
	 * @return the latest CardFileInfo or null if unknown
	 */
	public CardFileInfo getFCI() {
		return currentFCI;
	}



	/**
	 * Check if the last selected file is an EF
	 * @return true if the last selected object is an EF
	 */
	public boolean elementaryFileSelected() {
		return isElementaryFile;
	}



	/**
	 * Override Parameter P2 in SELECT APDU
	 * @param p2 the new P2 to use
	 */
	public void setSelectCommandResponseQualifier(byte p2) {
		selectFCI = p2;
	}



	/**
	 * Gets value used for P2
	 *
	 * @return the value for P2
	 */
	public byte getSelectCommandResponseQualifier() {
		return selectFCI;
	}



	/**
	 * Enable or disable flag to include Le in command APDU
	 *
	 * @param flag true to include Le in command APDU
	 */
	public void setLeInSelectFlag(boolean flag) {
		this.leInSelectEnabled = flag;
	}



	/**
	 * Query if Le is included in command APDU
	 *
	 * @return true if Le is included
	 */
	public boolean isLeInSelectEnabled() {
		return this.leInSelectEnabled;
	}



	/**
	 * Callback from CardService to record selected EF when short file identifier are used
	 *
	 * @param file the file path
	 */
	public void setImplicitlySelectedBySFI(CardFilePath file) {
		this.currentPath = file;
		this.currentFCI = null;
		this.isElementaryFile = true;
	}



	/**
	 * Select a single path component
	 *
	 * @param channel
	 *          Card channel to use for SELECT command
	 * @param comp
	 *          Path component. null is parent file is to be selected
	 * @param isDF
	 *          true if the path component is known to be a DF
	 * @return
	 *          Response APDU from SELECT command
	 *
	 * @throws InvalidCardChannelException
	 * @throws CardTerminalException
	 */
	protected ResponseAPDU doSelect(CardChannel channel, CardFilePathComponent comp, boolean isDF, byte p1, SecureChannelCredential secureChannelCredential) throws InvalidCardChannelException, CardTerminalException {
		ResponseAPDU res;
		CommandAPDU com = new CommandAPDU(30);

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_SELECT_FILE);

		if (p1 != -1) {
			com.append(p1);
		} else {
			if (comp == null) {
				com.append(IsoConstants.SC_PARENT);
			} else if (comp instanceof CardFileAppID) {
				com.append(IsoConstants.SC_AID);
			} else if (comp.equals(root_file)) {
				com.append(IsoConstants.SC_MF);
			} else if (supportsP1InSelect){
				com.append(isDF ? IsoConstants.SC_DF : IsoConstants.SC_EF);
			} else {
				com.append(IsoConstants.SC_FID);
			}
		}

		com.append(selectFCI);

		if (comp != null) {
			if (comp instanceof CardFileFileID) {
				com.append((byte)0x02);
				com.append(((CardFileFileID)comp).toByteArray());
			} else if (comp instanceof CardFileAppID) {
				byte aid[] = ((CardFileAppID)comp).toByteArray();
				com.append((byte)aid.length);
				com.append(aid);
			}
		}

		if (leInSelectEnabled) {
			com.append((byte)0x00);
		}

		if (secureChannelCredential != null) {
			SlotChannel slc = channel.getSlotChannel();
			APDUTracer tracer = slc.getAPDUTracer();
			if ((tracer != null) && (com.getLength() > 5)) {
				tracer.traceCommandAPDU(slc, com);
			}
			int uq = secureChannelCredential.getUsageQualifier();
			SecureChannel sc = secureChannelCredential.getSecureChannel();
			com = sc.wrap(com, uq);
			res = channel.sendCommandAPDU(com);
			res = sc.unwrap(res, uq);
			if ((tracer != null) && (res.getLength() > 2)) {
				tracer.traceResponseAPDU(slc, res);
			}
		} else {
			res = channel.sendCommandAPDU(com);
		}

		if (res.sw1() == IsoConstants.RC_OKMOREDATA) {
			com.setLength(0);
			com.append(IsoConstants.CLA_ISO);
			com.append(IsoConstants.INS_GET_RESPONSE);
			com.append((byte)0x00);
			com.append((byte)0x00);
			com.append(res.sw2());
			res = channel.sendCommandAPDU(com);
		}

		return res;
	}



	/**
	 * Select directory or file according to path. This function
	 * observes the currently selected EF or DF as stored in the
	 * CardState object of the CardChannel.
	 *
	 * This method has some rather complex algorithm to determine
	 * the way to select the new object. It will in general try to
	 * find the shortest way to the new object or otherwise reselect
	 * the full path starting at the MF
	 *
	 * @param channel
	 *          Card channel used to communicate with the card
	 * @param secureChannelCredential
	 *          Credential to be used when transforming APDUs
	 * @param path
	 *          Path to file to be selected
	 * @param explicit
	 *          Explicitly select object to obtain file control information
	 * @return NEWLY_SELECTED or ALREADY_SELECTED
	 *
	 *
	 * @throws InvalidCardChannelException
	 * @throws CardTerminalException
	 * @throws CardServiceObjectNotAvailableException
	 * @throws CardServiceUnexpectedStatusWordException
	 */
	public synchronized int selectFile(CardChannel channel, SecureChannelCredential secureChannelCredential, CardFilePath path, boolean explicit) throws InvalidCardChannelException, CardTerminalException, CardServiceObjectNotAvailableException, CardServiceUnexpectedStatusWordException {
		boolean selectFromRoot = false;
		ResponseAPDU res = new ResponseAPDU( new byte[] { (byte)0x90, (byte)0x00 });
		CardFilePathComponent comp;
		int count;

		/* We need to select a file if the path differs from the current*/
		/* path or the file control information are not cached          */

		if (path.equals(currentPath) && !explicit) {
			logger.info("[selectFile] File already selected");
			return ALREADY_SELECTED;
		}

		/* If the currently selected object is a file or if the     */
		/* non cached fci is requested for a DF then strip of the   */
		/* last component of the path                               */
		CardFilePath currentDir = new CardFilePath(currentPath);

		if (isElementaryFile) {
			logger.info("[selectFile] Stripping last element of current path");
			if (!currentDir.chompTail()) {
				selectFromRoot = true;
			} else {
				if (currentDir.equals(path) && !explicit) {
					logger.info("[selectFile] Directory already selected");
					currentFCI = null;
					return ALREADY_SELECTED;
				}
			}
		}

		/* If the new object is a subordinate of the currently      */
		/* selected directory, then we just need to select          */
		/* whatever is remaining                                    */
		CardFilePath toselect = new CardFilePath(path);

		if (path.startsWith(currentDir)) {
			toselect.chompPrefix(currentDir);
		} else {
			// If there is a common path and the difference is only
			// one DF, then we will try a SELECT(PARENT) to get where
			// we want to
			int common;

			common = toselect.commonPrefixLength(currentDir);

			if ((common > 0) && ((currentDir.numberOfComponents() - common) == 1)) {
				/* Select parent */
				res = doSelect(channel, null, false, (byte)-1, secureChannelCredential);

				if ((res.sw() == IsoConstants.RC_OK) || (res.sw() == IsoConstants.RC_INVFILE)) {
					isElementaryFile = false;
					currentDir.chompTail();

					if (currentDir.equals(toselect)) { // Are we there already ?
						logger.info("[selectFile] FCI = " + HexString.hexify(res.data()));

						if (res.getLength() > 2) {
							currentFCI = new IsoFileControlInformation(res.data());
						} else {
							currentFCI = new IsoFileControlInformation();
						}
						currentPath = currentDir;
						return NEWLY_SELECTED;
					}
					toselect.chompPrefix(currentDir);
				} else {
					selectFromRoot = true;
				}
			} else {
				selectFromRoot = true;
			}
		}

		if (selectFromRoot)
			currentDir = null;

		logger.info("[selectFile] Going to select " + toselect.toString());

		Enumeration components = toselect.components();

		count = toselect.numberOfComponents();
		boolean assumeDF = true;

		while (components.hasMoreElements()) {
			comp = (CardFilePathComponent)components.nextElement();

			/* If we reached a short file identifier, then the actual
			 * selection of the file is done in the command itself (e.g. READ BINARY)
			 */
			if (comp instanceof CardFileShortFileID) {
				if (currentDir != null) {
					currentPath = currentDir;
				}
				isElementaryFile = false;
				currentFCI = null;
				logger.info("[selectFile] Last path component is a short file identifier" + comp);
				return ((CardFileShortFileID)comp).toByte();
			}

			/* Some cards do not support a SELECT without knowing */
			/* the file type. As we don't know either, we try    */
			/* selecting an EF first. If that fails, we retry    */
			/* selecting a DF                                    */

			/* The last component may be an EF */
			if ((comp instanceof CardFileFileID) && (count == 1)) {
				assumeDF = false;
			}

			res = doSelect(channel, comp, assumeDF, (byte)-1, secureChannelCredential);
			if ((res.sw1() == IsoConstants.RC_INVLEN) && selectFromRoot) {
				logger.info("[selectFile] Invalid length when selecting MF - Trying without data");
				res = doSelect(channel, null, assumeDF, IsoConstants.SC_MF, secureChannelCredential);
			}

			// Some cards do not support P2=04 to return the FCP, fallback is to use P2=00
			if ((res.sw() == IsoConstants.RC_INCP1P2) ||
					(res.sw() == IsoConstants.RC_INVP1P2) ||
					(res.sw() == IsoConstants.RC_FUNCNOTSUPPORTED) ||
					(res.sw() == IsoConstants.RC_INVPARA) ||
					(res.sw1() == IsoConstants.RC_INVLEN)) {
				logger.info("[selectFile] Invalid P1/P2 - Trying FCI instead of FCP");
				selectFCI = IsoConstants.SO_RETURNFCI;
				res = doSelect(channel, comp, assumeDF, (byte)-1, secureChannelCredential);

				// Some cards do not support P1!=00, fallback is to use P1=00 in any case
				if ((res.sw() == IsoConstants.RC_INCP1P2) ||
						(res.sw() == IsoConstants.RC_INVP1P2) ||
						(res.sw() == IsoConstants.RC_FUNCNOTSUPPORTED) ||
						(res.sw() == IsoConstants.RC_INVPARA) ||
						(res.sw1() == IsoConstants.RC_INVLEN)) {
					logger.info("[selectFile] Invalid P1/P2 - Trying with P1 = 0");
					supportsP1InSelect = false;
					res = doSelect(channel, comp, assumeDF, (byte)-1, secureChannelCredential);
				}

				// ETSI cards require P1=00 and P2=04
				if ((res.sw() == IsoConstants.RC_INCP1P2) ||
						(res.sw() == IsoConstants.RC_INVP1P2) ||
						(res.sw() == IsoConstants.RC_FUNCNOTSUPPORTED) ||
						(res.sw() == IsoConstants.RC_INVPARA) ||
						(res.sw1() == IsoConstants.RC_INVLEN)) {
					logger.info("[selectFile] Invalid P1/P2 - Trying with P1 = 0");
					supportsP1InSelect = false;
					this.selectFCI = IsoConstants.SO_RETURNFCP;
					res = doSelect(channel, comp, assumeDF, (byte)-1, secureChannelCredential);
				}

				// Even other cards don't want a Le byte in select
				if (res.sw() == IsoConstants.RC_WRONGLENGTH) {
					logger.info("[selectFile] Wrong length - Trying without Le");
					leInSelectEnabled = false;
					res = doSelect(channel, comp, assumeDF, (byte)-1, secureChannelCredential);
				}

				// Even other cards don't want a Le byte in select
				if (res.sw() == IsoConstants.RC_WRONGLENGTH) {
					logger.info("[selectFile] Wrong length - Trying with P1='0C' and without Le");
					leInSelectEnabled = false;
					supportsP1InSelect = true;
					selectFCI = IsoConstants.SO_NONE;
					res = doSelect(channel, comp, assumeDF, (byte)-1, secureChannelCredential);
				}
			}

			if ((res.sw() == IsoConstants.RC_FILENOTFOUND) && !assumeDF) {
				logger.info("[selectFile] EF not found - Trying DF");
				assumeDF = true;
				res = doSelect(channel, comp, assumeDF, (byte)-1, secureChannelCredential);
			}

			if ((res.sw() == IsoConstants.RC_OK) ||
					(res.sw() == IsoConstants.RC_INVFILE) ||
					(res.sw1() == IsoConstants.RC_OKMOREDATA)) {
				if (currentDir == null) {
					/* We are starting at the root */
					currentDir = new CardFilePath(comp.toString());
					assumeDF = true;
				} else {
					currentDir.append(comp);
				}

				logger.info("[selectFile] FCI = " + HexString.hexify(res.data()));

				if (res.getLength() > 2) {
					currentFCI = new IsoFileControlInformation(res.data());
				} else {
					currentFCI = new IsoFileControlInformation();
				}
			} else {
				logger.error("[selectFile] SW1SW2 = " + HexString.hexifyShort(res.sw()));
				assumeDF = true;
				break;
			}

			count--;
		}

		if (currentDir != null) {
			currentPath = currentDir;
			isElementaryFile = !assumeDF;
		}

		/* If we only succeded to select part of the path   */
		/* then we can not return the fci                   */

		if (res.sw() == IsoConstants.RC_FILENOTFOUND) {
			throw new CardServiceObjectNotAvailableException("File not found");
		}
		if ((res.sw() != IsoConstants.RC_OK) &&
				(res.sw() != IsoConstants.RC_INVFILE) &&
				(res.sw1() != IsoConstants.RC_OKMOREDATA)) {
			throw new CardServiceUnexpectedStatusWordException("SELECT", res.sw());
		}

		return NEWLY_SELECTED;
	}



	/**
	 * Select directory or file according to path. This function
	 * observes the currently selected EF or DF as stored in the
	 * CardState object of the CardChannel.
	 *
	 * This method has some rather complex algorithm to determine
	 * the way to select the new object. It will in general try to
	 * find the shortest way to the new object or otherwise reselect
	 * the full path starting at the MF
	 *
	 * @param channel
	 *          Card channel used to communicate with the card
	 * @param secureChannelCredential
	 *          Credential to be used when transforming APDUs
	 * @param path
	 *          Path to file to be selected
	 * @return NEWLY_SELECTED or ALREADY_SELECTED
	 *
	 *
	 * @throws InvalidCardChannelException
	 * @throws CardTerminalException
	 * @throws CardServiceObjectNotAvailableException
	 * @throws CardServiceUnexpectedStatusWordException
	 */
	public int selectFile(CardChannel channel, SecureChannelCredential secureChannelCredential, CardFilePath path) throws InvalidCardChannelException, CardTerminalException, CardServiceObjectNotAvailableException, CardServiceUnexpectedStatusWordException {
		return selectFile(channel, secureChannelCredential, path, false);
	}

}
