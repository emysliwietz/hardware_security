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

import java.awt.Dialog;

import javax.swing.JDialog;
import javax.swing.JOptionPane;


public class URLVerifier {

	private ServerURLManager manager;
	private final static int OPTION_ALWAYS = 0;
	private final static int OPTION_ONCE = 1;
	private final static int OPTION_NO = 2;



	public URLVerifier() {
		manager = new ServerURLManager();
	}



	private int prompt(String title, String message, String[] options) {
		JOptionPane pane = new JOptionPane(message, JOptionPane.QUESTION_MESSAGE, JOptionPane.YES_NO_CANCEL_OPTION, null, options, null);
		JDialog dialog = pane.createDialog(title);
		dialog.setModalityType(Dialog.ModalityType.TOOLKIT_MODAL);
		dialog.setLocationRelativeTo(null); // Center this frame
		dialog.setAlwaysOnTop(true);
		dialog.setVisible(true);

		Object value = pane.getValue();
		if (value == null) {
			return -1;
		}

		int n = 0;
		for (; n < options.length && !value.equals(options[n]); n++);

		return n;
	}



	public boolean verifyURL(String url) {
		if (manager.isApproved(url)) {
			return true;
		}

		String[] options = {
				"Yes, always",
				"Yes, only once",
		"No"};

		String message = "The server "
				+"\n" + url
				+ "\nis trying to connect to your smart card."
				+ "\n\nDo you wish to allow the connection ?";

		String title = "Incoming Connection";
/*
		JOptionPane pane = new JOptionPane(message, JOptionPane.QUESTION_MESSAGE, JOptionPane.YES_NO_CANCEL_OPTION, null, options, null);
		JDialog dialog = pane.createDialog(title);
		dialog.setModalityType(Dialog.ModalityType.TOOLKIT_MODAL);
		dialog.setLocationRelativeTo(null); // Center this frame
		dialog.setAlwaysOnTop(true);
		dialog.setVisible(true);

		Object value = pane.getValue();
		if (value == null) {
			return false;
		}

		int n = 0;
		for (; n < options.length && !value.equals(options[n]); n++);
*/
		int n = prompt(title, message, options);

		if (n == OPTION_ALWAYS) {
			manager.approveServerURL(url);
			return true;
		} else if (n == OPTION_ONCE) {
			return true;
		}

		return false;
	}



	public boolean verifyURLforToken(String url, String token) {

		String[] options = { "Yes", "No"};

		String message = "Connect token " + token + " to server at " + url + " ?";
		int opt = prompt("Auto connect token", message, options);
		return opt == 0;
	}
}
