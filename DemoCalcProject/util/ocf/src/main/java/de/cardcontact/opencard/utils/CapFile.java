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

package de.cardcontact.opencard.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import opencard.opt.util.TLV;
import opencard.opt.util.Tag;


/**
 * JavaCard CAP file decoder
 * 
 * @author Andreas Schwier
 */
public class CapFile {
	public final static int HEADER = 0;
	public final static int DIRECTORY = 1;
	public final static int APPLET = 2;
	public final static int IMPORT = 3;
	public final static int CONSTANTPOOL = 4;
	public final static int CLASS = 5;
	public final static int METHOD = 6;
	public final static int STATICFIELD = 7;
	public final static int REFLOCATION = 8;
	public final static int EXPORT = 9;
	public final static int DESCRIPTOR = 10;
	public final static int DEBUG = 11;

	public final static String[] COMPONENTS = {
		"HEADER",
		"DIRECTORY",
		"APPLET",
		"IMPORT",
		"CONSTANTPOOL",
		"CLASS",
		"METHOD",
		"STATICFIELD",
		"REFLOCATION",
		"EXPORT",
		"DESCRIPTOR",
		"DEBUG"
	};

	// Load order of mandatory components according to JC 2.2.2 VM Spec
	public final static int[] CAPSEQUENCE = { HEADER, DIRECTORY, IMPORT, APPLET,
		CLASS, METHOD, STATICFIELD, EXPORT, CONSTANTPOOL, REFLOCATION};

	protected String filename;
	protected byte[][] components = new byte[COMPONENTS.length][];



	public CapFile() {
	}



	@Deprecated
	public CapFile(String filename) {
		this.filename = filename;
	}



	public void read(InputStream is) throws IOException {
		int i;

		for (i = 0; i < components.length; i++) {
			components[i] = null;
		}

		ZipInputStream zip = new ZipInputStream(is);

		ZipEntry ze;
		while ((ze = zip.getNextEntry()) != null) {

			String name = ze.getName().toUpperCase();

			if (name.startsWith("META-INF") || name.startsWith("APPLET-INF")) {
				zip.closeEntry();
				continue;
			}

			for (i = 0; i < COMPONENTS.length; i++) {
				if (name.endsWith("JAVACARD/" + COMPONENTS[i] + ".CAP")) {
					break;
				}
			}

			if (i >= COMPONENTS.length) {
				throw new IOException("Invalid component " + name + " in cap file");
			}

			if (components[i] != null) {
				throw new IOException("Duplicate component " + name + " in cap file");
			}

			int size = (int)ze.getSize();

			byte[] buff = new byte[size];
			components[i] = buff;

			int offset = 0;
			int len;
			while((len = zip.read(buff, offset, buff.length - offset)) > 0) {
				offset += len;
			}
			zip.closeEntry();
		}
	}



	public void read(String filename) throws IOException {
		int i;

		for (i = 0; i < components.length; i++) {
			components[i] = null;
		}

		ZipFile cap = new ZipFile(new File(filename));
		Enumeration zipEnum = cap.entries();
		while (zipEnum.hasMoreElements()) {
			ZipEntry ze = (ZipEntry)zipEnum.nextElement();

			String name = ze.getName().toUpperCase();

			if (name.startsWith("META-INF")) {
				continue;
			}

			for (i = 0; i < COMPONENTS.length; i++) {
				if (name.endsWith("JAVACARD/" + COMPONENTS[i] + ".CAP")) {
					break;
				}
			}

			if (i >= COMPONENTS.length) {
				throw new IOException("Invalid component " + name + " in cap file");
			}

			if (components[i] != null) {
				throw new IOException("Duplicate component " + name + " in cap file");
			}

			int size = (int)ze.getSize();

			byte[] buff = new byte[size];
			components[i] = buff;

			InputStream is = cap.getInputStream(ze);
			int offset = 0;
			int len;
			while((len = is.read(buff, offset, buff.length - offset)) > 0) {
				offset += len;
			}
		}
	}



	@Deprecated
	public void read() throws IOException {
		read(this.filename);
	}



	public byte[] getLoadFile(int[] caplist) {
		int i, j;
		int size = 0;

		for (i = 0; i < caplist.length; i++) {
			j = caplist[i];
			if (components[j] != null) {
				size += components[j].length;
			}
		}

		byte[] buffer = new byte[size];
		int offset = 0;

		for (i = 0; i < caplist.length; i++) {
			j = caplist[i];
			if (components[j] != null) {
				int len = components[j].length;
				System.arraycopy(components[j], 0, buffer, offset, len);
				offset += len;
			}
		}

		TLV c4 = new TLV(new Tag(4, (byte)3, false), buffer);
		return c4.toBinary();
	}
}
