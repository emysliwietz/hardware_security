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

import java.util.HashSet;
import java.util.prefs.Preferences;



/**
 * Persistently store client configurations in a property file.
 * This property file is located in the CardContact folder
 * at the user's home directory.
 * @author lew
 */
public class ClientProperties {

	private static ClientProperties instance;

	private Preferences preferences;

	private static final String KEY_READER = "reader";

	private static final String KEY_IGNORE = "ignore";

	private static final String KEY_SERVER_URL = "url";

	private static final String DELIMITER = " ; ";



	private ClientProperties() {
		preferences = Preferences.userRoot().node("OCFClient");
	}



	static public ClientProperties getClientProperties() {
		if (instance == null) {
			instance = new ClientProperties();
		}
		return instance;
	}



	/**
	 * Save the key value pair in the property file
	 * @param key
	 * @param value
	 */
	private void save(String key, String value) {
		preferences.put(key, value);
	}



	/**
	 * Save the selected reader name
	 * @param reader the selected card terminal name
	 */
	public void saveReaderName(String reader) {
		preferences.put(KEY_READER, reader);
	}



	/**
	 * @return the selected card terminal name
	 */
	public String getReaderName() {
		return preferences.get(KEY_READER, "");
	}



	/**
	 * Append the given set of reader names to the set of already stored names.
	 * These card reader will be ignored by the client.
	 * @param reader
	 */
	public void appendToIgnored(HashSet<String> reader) {
		HashSet<String> ignored = getIgnoredReader();
		String ignoreList = "";
		for (String r : reader) {
			if (!ignored.contains(r)) {
				ignoreList += r + DELIMITER;
			}
		}

		String propertyList = preferences.get(KEY_IGNORE, "");
		propertyList += ignoreList;

		preferences.put(KEY_IGNORE, propertyList);
	}



	/**
	 * Get a set of all ignored card reader names.
	 * These card reader will be ignored by the client.
	 * @return the set of ignored card reader names
	 */
	public HashSet<String> getIgnoredReader() {
		HashSet<String> readerSet = new HashSet<String>();
		String readerList = preferences.get(KEY_IGNORE, null);

		if (readerList == null) {
			return readerSet;
		}

		String[] ignored = readerList.split(DELIMITER);
		for (String reader : ignored) {
			if (!reader.equals("")) {
				readerSet.add(reader);
			}
		}

		return readerSet;
	}



	/**
	 * Overwrite the current set of ignored card reader names
	 * with the given set.
	 * @param ignored the set of ignored card reader names
	 */
	public void saveIgnoredReader(HashSet<String> ignored) {
		String ignoreList = "";
		for (String r : ignored) {
			ignoreList += r + DELIMITER;
		}

		preferences.put(KEY_IGNORE, ignoreList);
	}



	/**
	 * Overwrite the current set of permitted server URLs
	 * with the given set.
	 * @param urlSet the set of permitted server URLs
	 */
	public void saveServerURL(HashSet<String> urlSet) {
		String urlList = "";
		for (String url : urlSet) {
			urlList += url + DELIMITER;
		}

		preferences.put(KEY_SERVER_URL, urlList);
	}



	/**
	 * Append a new server URL to the set of permitted server URLs
	 * @param newUrl the server URL
	 */
	public void appendServerURL(String newUrl) {
		HashSet<String> urlSet = getServerURL();

		if (urlSet.contains(newUrl)) {
			return;
		}

		String list = "";
		for (String url: urlSet) {
			list += url + DELIMITER;
		}
		list += newUrl + DELIMITER;

		preferences.put(KEY_SERVER_URL, list);
	}



	/**
	 * @return the set of permitted server URLs
	 */
	public HashSet<String> getServerURL() {
		HashSet<String> urlSet = new HashSet<String>();
		String urlList = preferences.get(KEY_SERVER_URL, null);

		if (urlList == null) {
			return urlSet;
		}

		String[] approved = urlList.split(DELIMITER);
		for (String url : approved) {
			if (!url.equals("")) {
				urlSet.add(url);
			}
		}

		return urlSet;
	}
}
