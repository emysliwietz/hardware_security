/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2016 CardContact Systems GmbH
 * |'##> <##'|  32429 Minden, Germany (www.cardcontact.de)
 *  ---------
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package de.cardcontact.opencard.service.smartcardhsm;

import java.util.Arrays;

/**
 * Class to maintain the Key Domain status on a SmartCard-HSM
 *
 * @author asc
 *
 */
public class KeyDomain {

	private byte id;
	private boolean isCreated = false;
	private byte shares;
	private byte outstanding;
	private byte[] kcv;
	private byte[] keyDomainUID;



	public KeyDomain(byte id) {
		this.id = id;
	}




	public byte getId() {
		return id;
	}




	public boolean isCreated() {
		return isCreated;
	}




	public byte getShares() {
		return shares;
	}




	public byte getOutstanding() {
		return outstanding;
	}




	public byte[] getKcv() {
		return kcv;
	}




	public byte[] getKeyDomainUID() {
		return keyDomainUID;
	}




	public void update(byte[] status) {
		if ((status == null) || (status.length == 0)) {
			isCreated = false;
			kcv = null;
			keyDomainUID = null;
			return;
		}

		isCreated = true;
		shares = status[0];
		outstanding = status[1];
		kcv = new byte[8];
		System.arraycopy(status, 2, kcv, 0, kcv.length);

		if (status.length > 10) {
			keyDomainUID = new byte[status.length - 10];
			System.arraycopy(status, 10, keyDomainUID, 0, keyDomainUID.length);
		}
	}



	public boolean equals(KeyDomain kd) {
		if (kd == null) {
			return false;
		}

		if (keyDomainUID != null) {
			if (kd.keyDomainUID == null) {
				return false;
			}
			return Arrays.equals(keyDomainUID, kd.keyDomainUID);
		}

		if ((kcv != null) && Arrays.equals(kcv, kd.kcv)) {
			return true;
		}

		return false;
	}
}
