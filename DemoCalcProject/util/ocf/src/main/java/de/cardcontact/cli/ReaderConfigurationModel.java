package de.cardcontact.cli;

import java.util.Enumeration;
import java.util.HashSet;

import opencard.core.service.CardIDFilter;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminal;
import opencard.core.terminal.CardTerminalRegistry;

public abstract class ReaderConfigurationModel implements CardIDFilter {

	private String selectedTerminal;
	protected HashSet<String> ignored;



	public String getSelectedTerminal() {
		return selectedTerminal;
	}



	public void setSelectedTerminal(String terminal) {
		selectedTerminal = terminal;
	}



	public HashSet<String> getAllTerminals() {
		HashSet<String> all = getValidTerminals();
		all.addAll(ignored);
		return all;
	}



	/**
	 * {available reader} \ {ignored reader}
	 */
	public HashSet<String> getValidTerminals() {
		HashSet<String> valid = new HashSet<String>();
		Enumeration ctlist = CardTerminalRegistry.getRegistry().getCardTerminals();

		while(ctlist.hasMoreElements()) {
			CardTerminal ct = (CardTerminal)ctlist.nextElement();
			String reader = ct.getName();
			if (!ignored.contains(reader)) {
				valid.add(reader);
			}
		}

		return valid;
	}



	public HashSet<String> getIgnoredTerminals() {
		return ignored;
	}



	public void setIgnoredTerminals(HashSet<String> ignored) {
		this.ignored = ignored;
	}



	public void ignoreTerminal(String terminal) {
		this.ignored.add(terminal);
	}



	public void approveTerminal(String terminal) {
		this.ignored.remove(terminal);
	}



	public boolean isCandidate(CardID cardID) {
		CardTerminal terminal = cardID.getCardTerminal();
		String name = terminal.getName();

		if (ignored.contains(name)) {
			return false;
		}

		if (selectedTerminal == null) {
			return true;
		}

		return name.startsWith(selectedTerminal);
	}



	abstract public void saveSettings();
	abstract public void discardChanges();
}
