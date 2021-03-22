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

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.net.URL;
import java.util.HashSet;

import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.TitledBorder;


@SuppressWarnings("serial")
public class ReaderConfigurationView extends JFrame {
	private ReaderConfigurationModel readerConfigurationModel;

	private JButton okButton;

	private JScrollPane ignoredScrollPanel;
	private JPanel ignorePanel;
	private JComboBox<String> selectionCB;
	private DefaultComboBoxModel<String> comboBoxModel;
	private JLabel noReaderLabel;



	public ReaderConfigurationView(ReaderConfigurationModel rcm) {
		URL iconURL = TrayView.class.getResource("cardcontact_24bit.gif");
		ImageIcon icon = new ImageIcon(iconURL);

		this.setIconImage(icon.getImage());
		this.readerConfigurationModel = rcm;

		init();

		this.setLocationRelativeTo(null); // Center this frame
	}



	public void init() {
		this.setTitle("Card Reader Configuration");

		JPanel contentPane = new JPanel(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		int y = 0;

		contentPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		comboBoxModel = new DefaultComboBoxModel<String>();
		selectionCB = new JComboBox<String>(comboBoxModel);
		selectionCB.setBorder(BorderFactory.createTitledBorder("Use Reader"));

		ignoredScrollPanel = new JScrollPane();
		TitledBorder title = BorderFactory.createTitledBorder("Ignore Reader");
		ignoredScrollPanel.setBorder(title);
		ignoredScrollPanel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		ignoredScrollPanel.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		Dimension d = new Dimension(0, 65);
		ignoredScrollPanel.setMinimumSize(d);

		c.gridy = y++;
		c.fill = GridBagConstraints.HORIZONTAL;
		contentPane.add(selectionCB, c);

		c.gridy = y++;
		contentPane.add(ignoredScrollPanel, c);

//		c.fill = GridBagConstraints.NONE;
//		noReaderLabel = new JLabel("No selectable reader available");
//		contentPane.add(noReaderLabel, c);

		JPanel buttons = new JPanel(new FlowLayout());
		okButton = new JButton("OK");
		JButton cancelButton = new JButton("Cancel");
		JButton refreshButton = new JButton("Refresh");
		buttons.add(okButton);
		buttons.add(cancelButton);
		buttons.add(refreshButton);

		c.gridy = y++;
		contentPane.add(buttons, c);

		refreshButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				showView();
			}
		});

		okButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				// Set default reader
				Object selected = selectionCB.getSelectedItem();
				if (selected != null) {
					String reader = (String)selected;
					if (reader == "any") {
						reader = "";
					}
					readerConfigurationModel.setSelectedTerminal(reader);
				}

				readerConfigurationModel.saveSettings();
				setVisible(false);
			}
		});

		cancelButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				readerConfigurationModel.discardChanges();
				setVisible(false);
			}
		});

		this.setContentPane(contentPane);
		this.pack();
	}



	public void showView(){
		updateIgnoreReaderList();
		preselectDefaultReader();

		revalidate();
		repaint();
		pack();
		setVisible(true);
	}



	/**
	 * Pre-select the default reader from the combo box.
	 */
	private void preselectDefaultReader() {
		updateReaderCB();
		String defaultReader = readerConfigurationModel.getSelectedTerminal();
		int listIndex = comboBoxModel.getIndexOf(defaultReader);
		if (comboBoxModel.getElementAt(listIndex) != null) {
			selectionCB.setSelectedIndex(listIndex);
		}
	}



	private void updateIgnoreReaderList() {
		HashSet<String> ignored = readerConfigurationModel.getIgnoredTerminals();

		ignorePanel = new JPanel(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.anchor = GridBagConstraints.LINE_START;
		c.fill = GridBagConstraints.HORIZONTAL;
		int y = 0;

		for (String reader : readerConfigurationModel.getAllTerminals()) {
			JCheckBox cb = new JCheckBox(reader);
			if (ignored.contains(reader)) {
				cb.setSelected(true);
			}
			cb.addItemListener(new ItemListener() {

				@Override
				public void itemStateChanged(ItemEvent event) {
					JCheckBox cb = (JCheckBox) event.getItem();
					if (event.getStateChange() == ItemEvent.SELECTED) {
						readerConfigurationModel.ignoreTerminal(cb.getText());
					} else {
						readerConfigurationModel.approveTerminal(cb.getText());
					}
					updateReaderCB();
				}
			});

			c.gridy = y++;
			ignorePanel.add(cb, c);

		}

		ignoredScrollPanel.setViewportView(ignorePanel);
		if (y == 0) { // no elements added
			ignoredScrollPanel.setVisible(false);
		} else {
			ignoredScrollPanel.setVisible(true);
		}
	}



	/**
	 * {available reader} \ {ignored reader}
	 */
	private void updateReaderCB() {
		// save last selection
		Object selection = comboBoxModel.getSelectedItem();

		// fill model with valid readers
		comboBoxModel.removeAllElements();
		comboBoxModel.addElement("any");
		for (String reader : readerConfigurationModel.getValidTerminals()) {
			comboBoxModel.addElement(reader);
		}

		// select last reader if available or "any"
		if (selection == null || comboBoxModel.getIndexOf(selection) == -1) {
			selection = comboBoxModel.getElementAt(0); // Select "any"
		}
		comboBoxModel.setSelectedItem(selection);

		pack();
	}
}
