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

import opencard.core.service.CardServiceException;
import opencard.core.terminal.CardTerminalException;
import opencard.opt.iso.fs.CardFileInfo;
import opencard.opt.iso.fs.CardFilePath;
import opencard.opt.iso.fs.CardFilePathComponent;
import opencard.opt.iso.fs.FileAccessCardService;
import opencard.opt.iso.fs.FileSystemCardService;

/**
 * This interface extents the original interface in the signature for the
 * create() and delete() method to allow better compatibility with ISO 7816-9
 * smart cards.
 * 
 * @author Andreas Schwier (info@cardcontact.de)
 */
public interface IsoFileSystemCardService extends FileSystemCardService {

	/**
	 * Creates a file on the smartcard.
	 * 
	 * This method is an extension to the method originally defined by OCF. It
	 * allows the caller to specify P1 and P2 in the command APDU as defined by
	 * ISO 7816-9. <br>
	 * Creating files is a card-specific operation. While the ISO file types are
	 * specified, the access conditions that can be defined are not. When
	 * creating a file, the access conditions to the new file have to be given.
	 * The result is that no card-independent arguments to a <tt>create</tt>
	 * method can be specified. <br>
	 * This method defines only a card-neutral <i>signature</i> by expecting a
	 * byte array as a parameter. The data to be stored in that byte array is
	 * card-specific. It is suggested, but not required, that a file header, as
	 * it is returned by <tt>CardFileInfo.getHeader</tt>, is accepted as that
	 * parameter block. A file header typically holds all information needed for
	 * creating a file, in a card-specific encoding. This information includes
	 * the file ID, structure, size, and the access conditions.
	 * <p>
	 * This method is intended to be used in a scenario where new applications
	 * have to be downloaded on a smartcard. Typically, a server will be
	 * contacted to retrieve the information about the directories and files
	 * that have to be created. This server can be supplied with the card's ATR,
	 * which is encapsulated by class <tt>CardID</tt>. The server will then be
	 * able to send parameter blocks that are appropriate arguments for this
	 * method and the respective card.
	 * 
	 * @param parent
	 *            the path to the directory in which to create a new file
	 * @param fileDescriptorByte
	 *            File descriptor byte according to ISO 7816-4
	 * @param shortFileIdentifier
	 *            Short file identifer coded on bit b8 - b4
	 * @param data
	 *            the parameters specifying the file to create. This argument is
	 *            card-specific. Refer to the documentation of the card-specific
	 *            service for details.
	 * 
	 * @see opencard.opt.iso.fs.FileSystemCardService
	 * @see FileAccessCardService#getFileInfo
	 * @see CardFileInfo#getHeader
	 * @see opencard.core.terminal.CardID
	 * @see opencard.core.service.SmartCard#getCardID
	 * 
	 * @exception CardServiceException
	 *                if the service encountered an error
	 * @exception CardTerminalException
	 *                if the terminal encountered an error
	 */
	public void create(CardFilePath parent, byte fileDescriptorByte,
			byte shortFileIdentifier, byte[] data) throws CardServiceException,
			CardTerminalException;

	/**
	 * Deletes a file on the smartcard.
	 * 
	 * This method is an extension to the original method defined by OCF. It
	 * allows to delete an object from within a selected DF. The implementation
	 * therefore allows to differentiate between a "delete child" and a
	 * "delete self" operation which may have different access conditions.
	 * 
	 * Deleting a file completely removes it from the smartcard. The associated
	 * resources on the card, that is the allocated memory, will be freed. It is
	 * not possible to restore the file. A new file with the same id as the
	 * deleted file may be created in the same directory (DF).
	 * 
	 * @param file
	 *            the path to the file to delete
	 * @param child
	 *            File identifier of child object (either EF, DF or application)
	 * @param childIsDF
	 *            True, if the child is a dedicated file
	 * 
	 * @exception CardServiceException
	 *                if the service encountered an error
	 * @exception CardTerminalException
	 *                if the terminal encountered an error
	 */
	public void delete(CardFilePath file, CardFilePathComponent child,
			boolean childIsDF) throws CardServiceException,
			CardTerminalException;
}
