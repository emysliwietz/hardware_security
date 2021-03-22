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

import java.awt.AWTException;
import java.awt.Font;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintStream;
import java.net.URL;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;



public class TrayView extends JFrame {

	private String iconPath = "cardcontact_24bit.gif";
	private ImageIcon ccIcon;
	final ReaderConfigurationView readerFrame;
	final JTextArea text = new JTextArea();
	final PopupMenu menu = new PopupMenu();
	private PrintStream out;



	public TrayView(TerminalManager tm) {
		super("Log");
		URL iconURL = TrayView.class.getResource(iconPath);
		ccIcon = new ImageIcon(iconURL);

		this.readerFrame = new ReaderConfigurationView(tm);

		try	{
			initSystemTray();
		}
		catch(Exception e) {
			// Ignore
		}
		Font font = new Font(Font.MONOSPACED, Font.PLAIN, 12);
		text.setFont(font);
	}



	private void initSystemTray() throws AWTException {
		String tooltip = "Card Updater Daemon";
		initPopUp();

		if (SystemTray.isSupported()) {
			TrayIcon trayIcon = new TrayIcon(ccIcon.getImage(), tooltip, menu);
			SystemTray systemTray = SystemTray.getSystemTray();
			systemTray.add(trayIcon);

			trayIcon.setImageAutoSize(true);
			trayIcon.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					setVisible(true);
				}
			});
		}

		text.add(menu);
		text.addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent e) {
				menu.show(text, e.getX(), e.getY());
			}
		});
	}



	private PopupMenu initPopUp() {
		MenuItem exit = new MenuItem("Exit");
		MenuItem log = new MenuItem("Show log");
		MenuItem clearLog = new MenuItem("Clear log");
		MenuItem showReader = new MenuItem("Reader Configuration");

		initLog();

		// PopupMenu menu = new PopupMenu("Settings");
		menu.add(log);
		menu.add(clearLog);
		menu.addSeparator();
		menu.add(showReader);
		menu.addSeparator();
		menu.add(exit);

		log.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setVisible(true);
			}
		});

		clearLog.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					text.getDocument().remove(0, text.getDocument().getLength());
				} catch (BadLocationException e1) {
					System.out.println(e1.getMessage());
				}
			}
		});

		showReader.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				readerFrame.showView();
			}
		});

		exit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});

		return menu;
	}



	public void showLog() {
		setVisible(true);
	}



	private void initLog() {
		setSize(600, 700);
		setIconImage(ccIcon.getImage());

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setViewportView(text);
		getContentPane().add(scrollPane);

		changeStandardOutput();
	}



	private void changeStandardOutput() {
		out = new PrintStream(System.out) {
			@Override
			public void println(String s) {
				this.print(s);
				this.print("\n");
			}

			@Override
			public void print(String s) {
				text.append(s);
				text.setCaretPosition(text.getDocument().getLength());
			}
		};
		System.setOut(out);
	}
}
