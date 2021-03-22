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

import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Locale;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;

import de.cardcontact.opencard.service.isocard.CHVCardServiceWithControl.PasswordStatus;

/**
 * Change Reference Data dialog for the SmartCard-HSM.
 * 
 * This dialog retrieves the current PIN and new PIN values
 * from the user.
 * 
 * @author lew
 */
public class ChangeReferenceDataDialog {
	private int pinLength = 6;

	static ResourceBundle rb = ResourceBundle.getBundle("MessagesBundle", Locale.getDefault());

	private String title = rb.getString("chvmanagement.title");

	// Status
	private String lowRetryCounterStatus = rb.getString("status.lowRetryCounter");
	private String lastTryStatus = rb.getString("status.lastTry");
	private String blockedStatus = rb.getString("status.blocked");	
	private String transportStatus = rb.getString("status.transport");
	private String wrongPINStatus = rb.getString("chvmanagement.error.wrongPin");

	// Swing Elements
	private JLabel currentPINMsg = new JLabel(rb.getString("chvmanagement.pin"));
	private JLabel newPINMsg = new JLabel(rb.getString("chvmanagement.newPin"));
	private JLabel newPINConfirmationMsg = new JLabel(rb.getString("chvmanagement.confirmPin"));
	private JLabel txtStatus = new JLabel();

	private JPanel currentPINField;
	private JPanel newPINField;
	private JPanel pinConfirmationField;
	private JPanel newPINFields;

	private JPasswordField currentPIN = new JPasswordField(pinLength);;
	private JPasswordField newPIN = new JPasswordField(pinLength);
	private JPasswordField newPINConfirmation = new JPasswordField(pinLength);

	private PasswordStatus passwordStatus;

	private JOptionPane optionPane;
	private JDialog dialog;


	private boolean validInput = false;



	/**
	 * Create the dialog GUI
	 */
	private void createDialog() {
		txtStatus.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
		currentPINMsg.setBorder(new EmptyBorder(0, 0, 0, 6));
		newPINMsg.setBorder(new EmptyBorder(0, 0, 0, 6));
		newPINConfirmationMsg.setBorder(new EmptyBorder(0, 0, 0, 6));

		currentPINField = new JPanel();
		currentPINField.setLayout(new GridLayout(0, 2));
		currentPINField.add(currentPINMsg);
		currentPINField.add(currentPIN);

		newPINField = new JPanel();
		newPINField.setLayout(new GridLayout(0, 2));
		newPINField.add(newPINMsg);
		newPINField.add(newPIN);

		pinConfirmationField = new JPanel();
		pinConfirmationField.setLayout(new GridLayout(0, 2));
		pinConfirmationField.add(newPINConfirmationMsg);
		pinConfirmationField.add(newPINConfirmation);

		newPINFields = new JPanel();
		newPINFields.setLayout(new BoxLayout(newPINFields, BoxLayout.PAGE_AXIS));
		newPINFields.add(newPINField);
		newPINFields.add(pinConfirmationField);

		JComponent[] input = new JComponent[] {txtStatus, currentPINField, newPINFields};
		int messageType = JOptionPane.PLAIN_MESSAGE;
		int optionType = JOptionPane.OK_CANCEL_OPTION;
		String[] options = null;
		if (passwordStatus == PasswordStatus.NOTVERIFIED) {
			addErrorMessage(currentPINField, wrongPINStatus);
		} else if (passwordStatus == PasswordStatus.RETRYCOUNTERLOW) {
			txtStatus.setText(lowRetryCounterStatus);
			messageType = JOptionPane.WARNING_MESSAGE;
		} else if (passwordStatus == PasswordStatus.LASTTRY) {
			txtStatus.setText(lastTryStatus);
			messageType = JOptionPane.WARNING_MESSAGE;
		} else if (passwordStatus == PasswordStatus.BLOCKED) {
			txtStatus.setText(blockedStatus);
			input = new JComponent[] {txtStatus};
			messageType = JOptionPane.ERROR_MESSAGE;
			optionType = JOptionPane.DEFAULT_OPTION;
			options = new String[] {"OK"};
		} else if (passwordStatus == PasswordStatus.TRANSPORTMODE) {
			txtStatus.setText(transportStatus);
		}

		optionPane = new JOptionPane(input, messageType, optionType, null, options, null);
		dialog = optionPane.createDialog(title);
		focusCurrentPIN();
	}



	/**
	 * Set focus to the current PIN field
	 */
	private void focusCurrentPIN() {
		dialog.addWindowFocusListener(new WindowAdapter() {
			public void windowGainedFocus(WindowEvent e) {
				currentPIN.requestFocusInWindow();
			}
		});
	}



	/**
	 * Set focus to the new PIN field
	 */
	private void focusNewPIN() {
		dialog.addWindowFocusListener(new WindowAdapter() {
			public void windowGainedFocus(WindowEvent e) {
				newPIN.requestFocusInWindow();
			}
		});
	}



	/**
	 * Set focus to the confirmation PIN field
	 */
	private void focusConfirmationPIN() {
		dialog.addWindowFocusListener(new WindowAdapter() {
			public void windowGainedFocus(WindowEvent e) {
				newPINConfirmation.requestFocusInWindow();
			}
		});
	}



	/**
	 * Show the Change Reference Data dialog.
	 * 
	 * @return true if current PIN and new PIN were correctly entered, false if the dialog was cancelled
	 */
	public boolean showDialog() {
		createDialog();
		validInput = false;

		while (!validInput) {
			dialog.setAlwaysOnTop(true);
			dialog.setVisible(true);

			Object action = optionPane.getValue();
			if (action != null && (int)action == JOptionPane.OK_OPTION) {
				validate();
			} else if (action != null && (int)action == JOptionPane.CANCEL_OPTION) {
				currentPIN.setText("");
				newPIN.setText("");
				newPINConfirmation.setText("");
				return false;
			}
		}
		return true;
	}



	/**
	 * Validate the input data. 
	 * If validation failed an error message will be to the dialog.
	 */
	private void validate() {
		if (currentPIN.getPassword().length == 0) {
			createDialog();
			addErrorMessage(currentPINField, rb.getString("chvmanagement.error.noPin"));
			return;
		}

		if (newPIN.getPassword().length == 0) {
			// no user input error message
			createDialog();
			focusNewPIN();
			addErrorMessage(newPINField, rb.getString("chvmanagement.error.noNewPin"));
			return;
		}

		if (newPINConfirmation.getPassword().length == 0) {
			// no user input error message
			createDialog();
			focusConfirmationPIN();
			addErrorMessage(pinConfirmationField, rb.getString("chvmanagement.error.noConfirmPin"));
			return;
		}

		if (!Arrays.equals(newPIN.getPassword(), newPINConfirmation.getPassword())) {
			newPIN.setText("");
			newPINConfirmation.setText("");
			createDialog();
			focusNewPIN();
			addErrorMessage(newPINFields, rb.getString("chvmanagement.error.confirmationFailed"));
			return;
		}

		validInput = true;
	}



	/**
	 * Set the current password status which
	 * will be displayed in the dialog
	 * @param status the password status
	 */
	public void setPasswordStatus(PasswordStatus status) {
		this.passwordStatus = status;
	}



	/**
	 * Add a red error message to the specified panel.
	 * Message and panel will be framed.
	 * 
	 * @param panel the panel with invalid or nonexistent user input
	 * @param msg the error message
	 */
	private void addErrorMessage(JPanel panel, String msg) {
		JLabel error = new JLabel(msg);
		error.setForeground(Color.RED);
		panel.add(error);

		Border outsideBorder = BorderFactory.createLineBorder(Color.RED);
		Border insideBorder = BorderFactory.createEmptyBorder(5, 5, 5, 5);
		Border border = BorderFactory.createCompoundBorder(outsideBorder, insideBorder);
		panel.setBorder(border);

		if (dialog != null) {
			dialog.pack();
		}
	}



	/**
	 * @return the current PIN or an empty array
	 */
	public byte[] getCurrentPIN() {
		byte[] pin = toByteArray(currentPIN.getPassword());
		currentPIN.setText("000000");
		currentPIN.setText("");
		return pin;
	}



	/**
	 * @return the new PIN or an empty array
	 */
	public byte[] getNewPIN() {
		byte[] pin = toByteArray(newPIN.getPassword());
		newPIN.setText("000000");
		newPIN.setText("");
		newPINConfirmation.setText("000000");
		newPINConfirmation.setText("");
		return pin;
	}



	/**
	 * @param chars
	 * @return the corresponding byte array
	 */
	private byte[] toByteArray(char[] chars) {
		CharBuffer charBuffer = CharBuffer.wrap(chars);
		ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
		byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
				byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(charBuffer.array(), '\u0000');
		Arrays.fill(byteBuffer.array(), (byte) 0);
		return bytes;
	}
}
