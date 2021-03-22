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

package de.cardcontact.opencard.service.smartcardhsm;

import java.awt.Dimension;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Locale;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import de.cardcontact.opencard.service.isocard.CHVCardServiceWithControl.PasswordStatus;
import opencard.core.service.CHVDialog;
import opencard.core.service.CardServiceException;
import opencard.core.terminal.CardTerminalException;

/**
 * Cardholder Verification Dialog for the SmartCard-HSM.
 * This dialog will display the given password status
 * <li>Not Verified</li>
 * <li>Last But One Try</li>
 * <li>Last Try</li>
 * <li>Blocked</li>
 * <li>Transport PIN State</li>
 * <li>Not Initialized</li><br>
 * and depending on the status display a PIN prompt or
 * show an error message.
 * 
 * @author lew
 */
public class SmartCardHSMCHVDialog implements CHVDialog {

	private int pinLength = 6;
	private PasswordStatus status;

	private String title = rb.getString("chvdialog.title");

	static ResourceBundle rb = ResourceBundle.getBundle("MessagesBundle", Locale.getDefault());

	private SmartCardHSMCardService service;

	// Messages
	private String pinPrompt = rb.getString("chvdialog.pinPrompt");

	// Error Messages
	private String blockedMessage = rb.getString("message.blocked");
	private String notInitializedMessage = rb.getString("message.notInitialized");
	private String transportModeMessage = rb.getString("message.transport");

	// Status
	private String notVerifiedStatus = rb.getString("status.notVerified");
	private String lowRetryCounterStatus = rb.getString("status.lowRetryCounter");
	private String lastTryStatus = rb.getString("status.lastTry");
	private String blockedStatus = rb.getString("status.blocked");
	private String transportModeStatus = rb.getString("status.transport");
	private String notInitializedStatus = rb.getString("status.notInitialized");


	// Swing Elements
	private JLabel txtMessage;
	private JLabel txtStatus;
	private JPasswordField pwField;
	private JPanel pnlPin;



	public SmartCardHSMCHVDialog() {
		txtMessage = new JLabel(pinPrompt);
		txtStatus = new JLabel();
		txtStatus.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
		pwField = new JPasswordField(pinLength);

		pnlPin = new JPanel();
		pnlPin.setLayout(new BoxLayout(pnlPin, BoxLayout.LINE_AXIS));
		pnlPin.add(txtMessage);
		pnlPin.add(Box.createRigidArea(new Dimension(6, 0)));
		pnlPin.add(pwField);
	}



	public SmartCardHSMCHVDialog(SmartCardHSMCardService service) {
		this();
		this.service = service;
	}



	/**
	 * Set the current password status which
	 * will be displayed in the dialog
	 * @param status the password status
	 */
	public void setPasswordStatus(PasswordStatus status) {
		this.status = status;
	}



	@Override
	public String getCHV(int chvNumber) {
		String pw = null;

		JComponent[] input;
		int messageType = JOptionPane.PLAIN_MESSAGE;
		int optionType = JOptionPane.OK_CANCEL_OPTION;
		String[] options;
		if (service != null) {
			options = new String[] {rb.getString("ok"), rb.getString("cancel"), rb.getString("change")};
		} else {
			options = new String[] {rb.getString("ok"), rb.getString("cancel")};
		}

		if (status == PasswordStatus.NOTVERIFIED) {
			txtStatus.setText(notVerifiedStatus);
			txtMessage.setText(pinPrompt);
			input = new JComponent[] {txtStatus, pnlPin};
			//options = new String[] {rb.getString("change")};
		} else if (status == PasswordStatus.RETRYCOUNTERLOW) {
			txtStatus.setText(lowRetryCounterStatus);
			txtMessage.setText(pinPrompt);
			input = new JComponent[] {txtStatus, pnlPin};
			messageType = JOptionPane.WARNING_MESSAGE;
		} else if (status == PasswordStatus.LASTTRY) {
			txtStatus.setText(lastTryStatus);
			txtMessage.setText(pinPrompt);
			input = new JComponent[] {txtStatus, pnlPin};
			messageType = JOptionPane.WARNING_MESSAGE;
		} else if (status == PasswordStatus.BLOCKED) {
			txtStatus.setText(blockedStatus);
			txtMessage.setText(blockedMessage);
			input = new JComponent[] {txtStatus, txtMessage};
			messageType = JOptionPane.ERROR_MESSAGE;
			optionType = JOptionPane.DEFAULT_OPTION;
			options = new String[] {rb.getString("ok")};
		} else if (status == PasswordStatus.TRANSPORTMODE) {
			txtStatus.setText(transportModeStatus);
			txtMessage.setText(transportModeMessage);
			input = new JComponent[] {txtStatus, txtMessage};
			messageType = JOptionPane.ERROR_MESSAGE;
			optionType = JOptionPane.DEFAULT_OPTION;
			if (service != null) {
				options = new String[] {rb.getString("ok"), rb.getString("change")};
			} else {
				options = new String[] {};
			}
		} else if (status == PasswordStatus.NOTINITIALIZED) {
			txtStatus.setText(notInitializedStatus);
			txtMessage.setText(notInitializedMessage);
			input = new JComponent[] {txtStatus, txtMessage};
			messageType = JOptionPane.ERROR_MESSAGE;
			optionType = JOptionPane.DEFAULT_OPTION;
			options = new String[] {rb.getString("ok")};
		} else {
			txtMessage.setText(pinPrompt);
			input = new JComponent[] {pnlPin};
		}

		JOptionPane pane = new JOptionPane(input, messageType, optionType, null, options, options[0]);
		JDialog dialog = pane.createDialog(title);
		dialog.addWindowFocusListener(new WindowAdapter() {
			public void windowGainedFocus(WindowEvent e) {
				pwField.requestFocusInWindow();
			}
		});

		dialog.setAlwaysOnTop(true);
		dialog.setVisible(true);

		Object action = pane.getValue();
		if (action == rb.getString("ok")) {
			if (pwField.getPassword().length == 0) {
				pw = null;
			} else {
				pw = new String(pwField.getPassword());
			}
		} else if (action == rb.getString("change")) {
			try {
				if (service != null) {
					service.changeReferenceData();
				}
				pw = null;
			} catch (CardServiceException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (CardTerminalException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}

		pwField.setText("");
		return pw;
	}
}