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

import opencard.opt.iso.fs.CardFileInfo;
import opencard.opt.iso.fs.CardFilePath;

/**
 * Object to hold information card related card service information
 * 
 * @author Andreas Schwier
 */
public class IsoCardState {
	private CardFilePath currentPath;
	private CardFileInfo currentFCI;
	private boolean isElementaryFile;
	private byte selectFCI;
	private boolean leInSelectEnabled = true;

	/**
	 * CTOR for IsoCardState object 
	 */
	public IsoCardState() {
		currentPath = null;
		currentFCI = null;
		selectFCI = IsoConstants.SO_RETURNFCP;
	}

	public CardFilePath getPath() {
		return currentPath;
	}

	public void setPath(CardFilePath newPath) {
		currentPath = new CardFilePath(newPath);
	}

	public CardFileInfo getFCI() {
		return currentFCI;
	}

	public void setFCI(CardFileInfo newFCI, boolean isEF) {
		currentFCI = newFCI;
		isElementaryFile = isEF;
	}

	public boolean elementaryFileSelected() {
		return isElementaryFile;
	}

	public void setSelectCommandResponseQualifier(byte p2) {
		selectFCI = p2;
	}

	public byte getSelectCommandResponseQualifier() {
		return selectFCI;
	}

	public void setLeInSelectFlag(boolean flag) {
		this.leInSelectEnabled = flag;
	}

	public boolean isLeInSelectEnabled() {
		return this.leInSelectEnabled;
	}
}
