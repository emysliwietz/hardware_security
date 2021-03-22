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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cardcontact.opencard.security.SecureChannel;
import de.cardcontact.opencard.security.SecureChannelCredential;
import de.cardcontact.opencard.service.CardServiceUnexpectedStatusWordException;
import de.cardcontact.opencard.service.eac20.EAC20;
import de.cardcontact.opencard.service.isocard.CHVCardServiceWithControl;
import de.cardcontact.opencard.service.isocard.CHVManagementCardService;
import de.cardcontact.opencard.service.isocard.FileSystemSendAPDU;
import de.cardcontact.opencard.service.isocard.IsoConstants;
import de.cardcontact.opencard.service.isocard.IsoFileControlInformation;
import de.cardcontact.opencard.service.remoteclient.RemoteClient;
import de.cardcontact.opencard.service.remoteclient.RemoteNotificationListener;
import de.cardcontact.opencard.service.remoteclient.RemoteUpdateService;
import de.cardcontact.tlv.ByteBuffer;
import de.cardcontact.tlv.ConstructedTLV;
import de.cardcontact.tlv.ObjectIdentifier;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.TLV;
import de.cardcontact.tlv.TLVEncodingException;
import de.cardcontact.tlv.Tag;
import de.cardcontact.tlv.cvc.CardVerifiableCertificate;
import de.cardcontact.tlv.cvc.PublicKeyReference;
import opencard.core.OpenCardException;
import opencard.core.service.CHVDialog;
import opencard.core.service.CHVUtils;
import opencard.core.service.CardChannel;
import opencard.core.service.CardServiceException;
import opencard.core.service.CardServiceInabilityException;
import opencard.core.service.CardServiceInvalidCredentialException;
import opencard.core.service.CardServiceInvalidParameterException;
import opencard.core.service.CardServiceOperationFailedException;
import opencard.core.service.CardServiceScheduler;
import opencard.core.service.InvalidCardChannelException;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CHVControl;
import opencard.core.terminal.CHVEncoder;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalIOControl;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ExtendedVerifiedAPDUInterface;
import opencard.core.terminal.ResponseAPDU;
import opencard.core.terminal.VerifiedAPDUInterface;
import opencard.opt.applet.AppletID;
import opencard.opt.applet.AppletInfo;
import opencard.opt.applet.AppletSelector;
import opencard.opt.applet.AppletState;
import opencard.opt.applet.BasicAppletCardService;
import opencard.opt.iso.fs.CardFileAppID;
import opencard.opt.iso.fs.CardFileFileID;
import opencard.opt.iso.fs.CardFileInfo;
import opencard.opt.iso.fs.CardFilePath;
import opencard.opt.iso.fs.CardIOException;
import opencard.opt.iso.fs.FileSystemCardService;
import opencard.opt.security.CredentialBag;
import opencard.opt.security.PrivateKeyRef;
import opencard.opt.security.PublicKeyRef;
import opencard.opt.security.SecureService;
import opencard.opt.security.SecurityDomain;
import opencard.opt.service.CardServiceObjectNotAvailableException;
import opencard.opt.service.CardServiceResourceNotFoundException;
import opencard.opt.service.CardServiceUnexpectedResponseException;
import opencard.opt.util.APDUInterface;



/**
 * Class implementing a SmartCard HSM card service
 *
 * @author lew
 *
 */
public class SmartCardHSMCardService extends BasicAppletCardService implements
FileSystemCardService, CHVCardServiceWithControl, CHVManagementCardService, SecureService,
KeyGenerationCardServiceWithSpec, DecipherCardService, FileSystemSendAPDU, RemoteUpdateService, APDUInterface {


	/**
	 * SmartCardHSMCardService log
	 */
	final Logger log = LoggerFactory.getLogger(SmartCardHSMCardService.class);


	/**
	 * CardFilePath containing the master file
	 */
	private static final CardFilePath mf = new CardFilePath("#E82B0601040181C31F0201");



	/**
	 * The application identifier
	 */
	private final static AppletID AID = new AppletID(new byte[] {(byte)0xE8, (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01, (byte)0x81, (byte)0xC3, (byte)0x1F, (byte)0x02, (byte)0x01});



	public static final String ALGO_PADDING_PKCS1_PSS = "PKCS1_PSS";



	/**
	 * This HashMap returns by a given padding algorithm a HashMap
	 * which contains the corresponding algorithm identifier
	 */
	private static HashMap<String, HashMap<String, Byte>> ALGORITHM_PADDING = new HashMap<String, HashMap<String, Byte>>();



	/**
	 * ECDH algorithm id
	 */
	private static byte ECDH = (byte)0x80;



	/**
	 * Algorithm id used for decipher
	 */
	private static byte NONE_WITH_RSA_DECRIPTION = (byte)0x21;



	/**
	 * Wrap algorithm id
	 */
	private static final byte WRAP = (byte)0x92;



	/**
	 * Unwrap algorithm id
	 */
	private static final byte UNWRAP = (byte)0x93;



	/**
	 * Number for User PIN
	 */
	private static final int USER_PIN = 0x81;



	/**
	 * Number for SO PIN
	 */
	private static final int SO_PIN = 0x88;



	/**
	 * This HashMap returns by a given alias the corresponding SmartCardHSMEntry
	 */
	private final HashMap<String, SmartCardHSMEntry> namemap = new HashMap<String, SmartCardHSMEntry>(200);



	/**
	 * This HashMap returns by a given key id the corresponding private key reference
	 */
	private final HashMap<Byte, SmartCardHSMKey> idmap = new HashMap<Byte, SmartCardHSMKey>(100);



	/**
	 * Map id to certificate
	 */
	private final HashMap<Byte, Certificate> certIDMap = new HashMap<Byte, Certificate>(100);



	/**
	 * A Vector containing CA id's
	 */
	private final Vector<Byte> caid = new Vector<Byte>();



	/**
	 * Last list of card objects. Stored to detect diffs
	 */
	private byte[] lastobjectlist = null;



	private ArrayList<KeyDomain> keyDomains = null;



	/**
	 * The maximum number of keys that can be stored on the card
	 */
	private static final int KEY_CAPACITY  = 60;



	/**
	 * Prefix for private keys
	 */
	public static final byte KEYPREFIX = (byte) 0xCC;



	/**
	 * Prefix for private key description
	 */
	public static final byte PRKDPREFIX = (byte) 0xC4;



	/**
	 * Prefix for EE certificates
	 */
	public static final byte EECERTIFICATEPREFIX = (byte) 0xCE;



	/**
	 * Prefix for CA certificates
	 */
	public static final byte CACERTIFICATEPREFIX = (byte) 0xCA;



	/**
	 * Prefix for CA certificates description
	 */
	public static final byte CERTDESCRIPTIONPREFIX = (byte) 0xC8;



	/**
	 * Maximum APDU size for JCOP 3
	 */
	private static final int MAX_APDU = 1232;



	private static final byte[] ROOT_CA = "DESRCACC100001".getBytes();



	private static final byte[] UT_CA = "UTSRCACC100001".getBytes();


	public final static ObjectIdentifier ID_KEY_DOMAIN_UID = new ObjectIdentifier( new int[] { 1,3,6,1,4,1,24991,3,2,2} );


	private static final byte[] rootCert = new byte[] {
		(byte)0x7F,(byte)0x21,(byte)0x82,(byte)0x01,(byte)0xB4,(byte)0x7F,(byte)0x4E,(byte)0x82,
		(byte)0x01,(byte)0x6C,(byte)0x5F,(byte)0x29,(byte)0x01,(byte)0x00,(byte)0x42,(byte)0x0E,
		(byte)0x44,(byte)0x45,(byte)0x53,(byte)0x52,(byte)0x43,(byte)0x41,(byte)0x43,(byte)0x43,
		(byte)0x31,(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x31,(byte)0x7F,(byte)0x49,
		(byte)0x82,(byte)0x01,(byte)0x1D,(byte)0x06,(byte)0x0A,(byte)0x04,(byte)0x00,(byte)0x7F,
		(byte)0x00,(byte)0x07,(byte)0x02,(byte)0x02,(byte)0x02,(byte)0x02,(byte)0x03,(byte)0x81,
		(byte)0x20,(byte)0xA9,(byte)0xFB,(byte)0x57,(byte)0xDB,(byte)0xA1,(byte)0xEE,(byte)0xA9,
		(byte)0xBC,(byte)0x3E,(byte)0x66,(byte)0x0A,(byte)0x90,(byte)0x9D,(byte)0x83,(byte)0x8D,
		(byte)0x72,(byte)0x6E,(byte)0x3B,(byte)0xF6,(byte)0x23,(byte)0xD5,(byte)0x26,(byte)0x20,
		(byte)0x28,(byte)0x20,(byte)0x13,(byte)0x48,(byte)0x1D,(byte)0x1F,(byte)0x6E,(byte)0x53,
		(byte)0x77,(byte)0x82,(byte)0x20,(byte)0x7D,(byte)0x5A,(byte)0x09,(byte)0x75,(byte)0xFC,
		(byte)0x2C,(byte)0x30,(byte)0x57,(byte)0xEE,(byte)0xF6,(byte)0x75,(byte)0x30,(byte)0x41,
		(byte)0x7A,(byte)0xFF,(byte)0xE7,(byte)0xFB,(byte)0x80,(byte)0x55,(byte)0xC1,(byte)0x26,
		(byte)0xDC,(byte)0x5C,(byte)0x6C,(byte)0xE9,(byte)0x4A,(byte)0x4B,(byte)0x44,(byte)0xF3,
		(byte)0x30,(byte)0xB5,(byte)0xD9,(byte)0x83,(byte)0x20,(byte)0x26,(byte)0xDC,(byte)0x5C,
		(byte)0x6C,(byte)0xE9,(byte)0x4A,(byte)0x4B,(byte)0x44,(byte)0xF3,(byte)0x30,(byte)0xB5,
		(byte)0xD9,(byte)0xBB,(byte)0xD7,(byte)0x7C,(byte)0xBF,(byte)0x95,(byte)0x84,(byte)0x16,
		(byte)0x29,(byte)0x5C,(byte)0xF7,(byte)0xE1,(byte)0xCE,(byte)0x6B,(byte)0xCC,(byte)0xDC,
		(byte)0x18,(byte)0xFF,(byte)0x8C,(byte)0x07,(byte)0xB6,(byte)0x84,(byte)0x41,(byte)0x04,
		(byte)0x8B,(byte)0xD2,(byte)0xAE,(byte)0xB9,(byte)0xCB,(byte)0x7E,(byte)0x57,(byte)0xCB,
		(byte)0x2C,(byte)0x4B,(byte)0x48,(byte)0x2F,(byte)0xFC,(byte)0x81,(byte)0xB7,(byte)0xAF,
		(byte)0xB9,(byte)0xDE,(byte)0x27,(byte)0xE1,(byte)0xE3,(byte)0xBD,(byte)0x23,(byte)0xC2,
		(byte)0x3A,(byte)0x44,(byte)0x53,(byte)0xBD,(byte)0x9A,(byte)0xCE,(byte)0x32,(byte)0x62,
		(byte)0x54,(byte)0x7E,(byte)0xF8,(byte)0x35,(byte)0xC3,(byte)0xDA,(byte)0xC4,(byte)0xFD,
		(byte)0x97,(byte)0xF8,(byte)0x46,(byte)0x1A,(byte)0x14,(byte)0x61,(byte)0x1D,(byte)0xC9,
		(byte)0xC2,(byte)0x77,(byte)0x45,(byte)0x13,(byte)0x2D,(byte)0xED,(byte)0x8E,(byte)0x54,
		(byte)0x5C,(byte)0x1D,(byte)0x54,(byte)0xC7,(byte)0x2F,(byte)0x04,(byte)0x69,(byte)0x97,
		(byte)0x85,(byte)0x20,(byte)0xA9,(byte)0xFB,(byte)0x57,(byte)0xDB,(byte)0xA1,(byte)0xEE,
		(byte)0xA9,(byte)0xBC,(byte)0x3E,(byte)0x66,(byte)0x0A,(byte)0x90,(byte)0x9D,(byte)0x83,
		(byte)0x8D,(byte)0x71,(byte)0x8C,(byte)0x39,(byte)0x7A,(byte)0xA3,(byte)0xB5,(byte)0x61,
		(byte)0xA6,(byte)0xF7,(byte)0x90,(byte)0x1E,(byte)0x0E,(byte)0x82,(byte)0x97,(byte)0x48,
		(byte)0x56,(byte)0xA7,(byte)0x86,(byte)0x41,(byte)0x04,(byte)0x6D,(byte)0x02,(byte)0x5A,
		(byte)0x80,(byte)0x26,(byte)0xCD,(byte)0xBA,(byte)0x24,(byte)0x5F,(byte)0x10,(byte)0xDF,
		(byte)0x1B,(byte)0x72,(byte)0xE9,(byte)0x88,(byte)0x0F,(byte)0xFF,(byte)0x74,(byte)0x6D,
		(byte)0xAB,(byte)0x40,(byte)0xA4,(byte)0x3A,(byte)0x3D,(byte)0x5C,(byte)0x6B,(byte)0xEB,
		(byte)0xF2,(byte)0x77,(byte)0x07,(byte)0xC3,(byte)0x0F,(byte)0x6D,(byte)0xEA,(byte)0x72,
		(byte)0x43,(byte)0x0E,(byte)0xE3,(byte)0x28,(byte)0x7B,(byte)0x06,(byte)0x65,(byte)0xC1,
		(byte)0xEA,(byte)0xA6,(byte)0xEA,(byte)0xA4,(byte)0xFA,(byte)0x26,(byte)0xC4,(byte)0x63,
		(byte)0x03,(byte)0x00,(byte)0x19,(byte)0x83,(byte)0xF8,(byte)0x2B,(byte)0xD1,(byte)0xAA,
		(byte)0x31,(byte)0xE0,(byte)0x3D,(byte)0xA0,(byte)0x62,(byte)0x87,(byte)0x01,(byte)0x01,
		(byte)0x5F,(byte)0x20,(byte)0x0E,(byte)0x44,(byte)0x45,(byte)0x53,(byte)0x52,(byte)0x43,
		(byte)0x41,(byte)0x43,(byte)0x43,(byte)0x31,(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,
		(byte)0x31,(byte)0x7F,(byte)0x4C,(byte)0x10,(byte)0x06,(byte)0x0B,(byte)0x2B,(byte)0x06,
		(byte)0x01,(byte)0x04,(byte)0x01,(byte)0x81,(byte)0xC3,(byte)0x1F,(byte)0x03,(byte)0x01,
		(byte)0x01,(byte)0x53,(byte)0x01,(byte)0xC0,(byte)0x5F,(byte)0x25,(byte)0x06,(byte)0x01,
		(byte)0x02,(byte)0x01,(byte)0x01,(byte)0x00,(byte)0x09,(byte)0x5F,(byte)0x24,(byte)0x06,
		(byte)0x03,(byte)0x02,(byte)0x01,(byte)0x01,(byte)0x00,(byte)0x08,(byte)0x5F,(byte)0x37,
		(byte)0x40,(byte)0x9D,(byte)0xBB,(byte)0x38,(byte)0x2B,(byte)0x17,(byte)0x11,(byte)0xD2,
		(byte)0xBA,(byte)0xAC,(byte)0xB0,(byte)0xC6,(byte)0x23,(byte)0xD4,(byte)0x0C,(byte)0x62,
		(byte)0x67,(byte)0xD0,(byte)0xB5,(byte)0x2B,(byte)0xA4,(byte)0x55,(byte)0xC0,(byte)0x1F,
		(byte)0x56,(byte)0x33,(byte)0x3D,(byte)0xC9,(byte)0x55,(byte)0x48,(byte)0x10,(byte)0xB9,
		(byte)0xB2,(byte)0x87,(byte)0x8D,(byte)0xAF,(byte)0x9E,(byte)0xC3,(byte)0xAD,(byte)0xA1,
		(byte)0x9C,(byte)0x7B,(byte)0x06,(byte)0x5D,(byte)0x78,(byte)0x0D,(byte)0x6C,(byte)0x9C,
		(byte)0x3C,(byte)0x2E,(byte)0xCE,(byte)0xDF,(byte)0xD7,(byte)0x8D,(byte)0xEB,(byte)0x18,
		(byte)0xAF,(byte)0x40,(byte)0x77,(byte)0x8A,(byte)0xDF,(byte)0x89,(byte)0xE8,(byte)0x61,
		(byte)0xCA
	};



	private static final byte[] utCert = new byte[] {
		(byte)0x7F,(byte)0x21,(byte)0x82,(byte)0x01,(byte)0xB4,(byte)0x7F,(byte)0x4E,(byte)0x82,
		(byte)0x01,(byte)0x6C,(byte)0x5F,(byte)0x29,(byte)0x01,(byte)0x00,(byte)0x42,(byte)0x0E,
		(byte)0x55,(byte)0x54,(byte)0x53,(byte)0x52,(byte)0x43,(byte)0x41,(byte)0x43,(byte)0x43,
		(byte)0x31,(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x31,(byte)0x7F,(byte)0x49,
		(byte)0x82,(byte)0x01,(byte)0x1D,(byte)0x06,(byte)0x0A,(byte)0x04,(byte)0x00,(byte)0x7F,
		(byte)0x00,(byte)0x07,(byte)0x02,(byte)0x02,(byte)0x02,(byte)0x02,(byte)0x03,(byte)0x81,
		(byte)0x20,(byte)0xA9,(byte)0xFB,(byte)0x57,(byte)0xDB,(byte)0xA1,(byte)0xEE,(byte)0xA9,
		(byte)0xBC,(byte)0x3E,(byte)0x66,(byte)0x0A,(byte)0x90,(byte)0x9D,(byte)0x83,(byte)0x8D,
		(byte)0x72,(byte)0x6E,(byte)0x3B,(byte)0xF6,(byte)0x23,(byte)0xD5,(byte)0x26,(byte)0x20,
		(byte)0x28,(byte)0x20,(byte)0x13,(byte)0x48,(byte)0x1D,(byte)0x1F,(byte)0x6E,(byte)0x53,
		(byte)0x77,(byte)0x82,(byte)0x20,(byte)0x7D,(byte)0x5A,(byte)0x09,(byte)0x75,(byte)0xFC,
		(byte)0x2C,(byte)0x30,(byte)0x57,(byte)0xEE,(byte)0xF6,(byte)0x75,(byte)0x30,(byte)0x41,
		(byte)0x7A,(byte)0xFF,(byte)0xE7,(byte)0xFB,(byte)0x80,(byte)0x55,(byte)0xC1,(byte)0x26,
		(byte)0xDC,(byte)0x5C,(byte)0x6C,(byte)0xE9,(byte)0x4A,(byte)0x4B,(byte)0x44,(byte)0xF3,
		(byte)0x30,(byte)0xB5,(byte)0xD9,(byte)0x83,(byte)0x20,(byte)0x26,(byte)0xDC,(byte)0x5C,
		(byte)0x6C,(byte)0xE9,(byte)0x4A,(byte)0x4B,(byte)0x44,(byte)0xF3,(byte)0x30,(byte)0xB5,
		(byte)0xD9,(byte)0xBB,(byte)0xD7,(byte)0x7C,(byte)0xBF,(byte)0x95,(byte)0x84,(byte)0x16,
		(byte)0x29,(byte)0x5C,(byte)0xF7,(byte)0xE1,(byte)0xCE,(byte)0x6B,(byte)0xCC,(byte)0xDC,
		(byte)0x18,(byte)0xFF,(byte)0x8C,(byte)0x07,(byte)0xB6,(byte)0x84,(byte)0x41,(byte)0x04,
		(byte)0x8B,(byte)0xD2,(byte)0xAE,(byte)0xB9,(byte)0xCB,(byte)0x7E,(byte)0x57,(byte)0xCB,
		(byte)0x2C,(byte)0x4B,(byte)0x48,(byte)0x2F,(byte)0xFC,(byte)0x81,(byte)0xB7,(byte)0xAF,
		(byte)0xB9,(byte)0xDE,(byte)0x27,(byte)0xE1,(byte)0xE3,(byte)0xBD,(byte)0x23,(byte)0xC2,
		(byte)0x3A,(byte)0x44,(byte)0x53,(byte)0xBD,(byte)0x9A,(byte)0xCE,(byte)0x32,(byte)0x62,
		(byte)0x54,(byte)0x7E,(byte)0xF8,(byte)0x35,(byte)0xC3,(byte)0xDA,(byte)0xC4,(byte)0xFD,
		(byte)0x97,(byte)0xF8,(byte)0x46,(byte)0x1A,(byte)0x14,(byte)0x61,(byte)0x1D,(byte)0xC9,
		(byte)0xC2,(byte)0x77,(byte)0x45,(byte)0x13,(byte)0x2D,(byte)0xED,(byte)0x8E,(byte)0x54,
		(byte)0x5C,(byte)0x1D,(byte)0x54,(byte)0xC7,(byte)0x2F,(byte)0x04,(byte)0x69,(byte)0x97,
		(byte)0x85,(byte)0x20,(byte)0xA9,(byte)0xFB,(byte)0x57,(byte)0xDB,(byte)0xA1,(byte)0xEE,
		(byte)0xA9,(byte)0xBC,(byte)0x3E,(byte)0x66,(byte)0x0A,(byte)0x90,(byte)0x9D,(byte)0x83,
		(byte)0x8D,(byte)0x71,(byte)0x8C,(byte)0x39,(byte)0x7A,(byte)0xA3,(byte)0xB5,(byte)0x61,
		(byte)0xA6,(byte)0xF7,(byte)0x90,(byte)0x1E,(byte)0x0E,(byte)0x82,(byte)0x97,(byte)0x48,
		(byte)0x56,(byte)0xA7,(byte)0x86,(byte)0x41,(byte)0x04,(byte)0xA0,(byte)0x41,(byte)0xFE,
		(byte)0xB2,(byte)0xFD,(byte)0x11,(byte)0x6B,(byte)0x2A,(byte)0xD1,(byte)0x9C,(byte)0xA6,
		(byte)0xB7,(byte)0xEA,(byte)0xCD,(byte)0x71,(byte)0xC9,(byte)0x89,(byte)0x2F,(byte)0x94,
		(byte)0x1B,(byte)0xB8,(byte)0x8D,(byte)0x67,(byte)0xDC,(byte)0xEE,(byte)0xC9,(byte)0x25,
		(byte)0x01,(byte)0xF0,(byte)0x70,(byte)0x01,(byte)0x19,(byte)0x57,(byte)0xE2,(byte)0x21,
		(byte)0x22,(byte)0xBA,(byte)0x6C,(byte)0x2C,(byte)0xF5,(byte)0xFF,(byte)0x02,(byte)0x93,
		(byte)0x6F,(byte)0x48,(byte)0x2E,(byte)0x35,(byte)0xA6,(byte)0x12,(byte)0x9C,(byte)0xCB,
		(byte)0xBA,(byte)0x8E,(byte)0x93,(byte)0x83,(byte)0x83,(byte)0x6D,(byte)0x31,(byte)0x06,
		(byte)0x87,(byte)0x9C,(byte)0x40,(byte)0x8E,(byte)0xF0,(byte)0x87,(byte)0x01,(byte)0x01,
		(byte)0x5F,(byte)0x20,(byte)0x0E,(byte)0x55,(byte)0x54,(byte)0x53,(byte)0x52,(byte)0x43,
		(byte)0x41,(byte)0x43,(byte)0x43,(byte)0x31,(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,
		(byte)0x31,(byte)0x7F,(byte)0x4C,(byte)0x10,(byte)0x06,(byte)0x0B,(byte)0x2B,(byte)0x06,
		(byte)0x01,(byte)0x04,(byte)0x01,(byte)0x81,(byte)0xC3,(byte)0x1F,(byte)0x03,(byte)0x01,
		(byte)0x01,(byte)0x53,(byte)0x01,(byte)0xC0,(byte)0x5F,(byte)0x25,(byte)0x06,(byte)0x01,
		(byte)0x02,(byte)0x01,(byte)0x01,(byte)0x00,(byte)0x09,(byte)0x5F,(byte)0x24,(byte)0x06,
		(byte)0x03,(byte)0x02,(byte)0x01,(byte)0x01,(byte)0x00,(byte)0x08,(byte)0x5F,(byte)0x37,
		(byte)0x40,(byte)0x91,(byte)0x4D,(byte)0xD0,(byte)0xFA,(byte)0x00,(byte)0x61,(byte)0x5C,
		(byte)0x44,(byte)0x04,(byte)0x8D,(byte)0x14,(byte)0x67,(byte)0x43,(byte)0x54,(byte)0x00,
		(byte)0x42,(byte)0x3A,(byte)0x4A,(byte)0xD1,(byte)0xBD,(byte)0x37,(byte)0xFD,(byte)0x98,
		(byte)0xD6,(byte)0xDE,(byte)0x84,(byte)0xFD,(byte)0x80,(byte)0x37,(byte)0x48,(byte)0x95,
		(byte)0x82,(byte)0x32,(byte)0x5C,(byte)0x72,(byte)0x95,(byte)0x6D,(byte)0x4F,(byte)0xDF,
		(byte)0xAB,(byte)0xC6,(byte)0xED,(byte)0xBA,(byte)0x48,(byte)0x18,(byte)0x4A,(byte)0x75,
		(byte)0x4F,(byte)0x37,(byte)0xF1,(byte)0xBE,(byte)0x51,(byte)0x42,(byte)0xDD,(byte)0x1C,
		(byte)0x27,(byte)0xD6,(byte)0x65,(byte)0x69,(byte)0x30,(byte)0x8C,(byte)0xE1,(byte)0x9A,
		(byte)0xAF
	};



	private static final byte[] issuerCert = new byte[] {
			(byte)0x30, (byte)0x82, (byte)0x02, (byte)0xBC, (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x60,
			(byte)0xA0, (byte)0x03, (byte)0x02, (byte)0x01, (byte)0x02, (byte)0x02, (byte)0x01, (byte)0x01,
			(byte)0x30, (byte)0x0C, (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE,
			(byte)0x3D, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x05, (byte)0x00, (byte)0x30, (byte)0x54,
			(byte)0x31, (byte)0x2F, (byte)0x30, (byte)0x2D, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04,
			(byte)0x03, (byte)0x0C, (byte)0x26, (byte)0x43, (byte)0x61, (byte)0x72, (byte)0x64, (byte)0x43,
			(byte)0x6F, (byte)0x6E, (byte)0x74, (byte)0x61, (byte)0x63, (byte)0x74, (byte)0x20, (byte)0x44,
			(byte)0x65, (byte)0x76, (byte)0x69, (byte)0x63, (byte)0x65, (byte)0x20, (byte)0x41, (byte)0x75,
			(byte)0x74, (byte)0x68, (byte)0x65, (byte)0x6E, (byte)0x74, (byte)0x69, (byte)0x63, (byte)0x61,
			(byte)0x74, (byte)0x69, (byte)0x6F, (byte)0x6E, (byte)0x20, (byte)0x43, (byte)0x41, (byte)0x20,
			(byte)0x31, (byte)0x31, (byte)0x14, (byte)0x30, (byte)0x12, (byte)0x06, (byte)0x03, (byte)0x55,
			(byte)0x04, (byte)0x0A, (byte)0x0C, (byte)0x0B, (byte)0x43, (byte)0x61, (byte)0x72, (byte)0x64,
			(byte)0x43, (byte)0x6F, (byte)0x6E, (byte)0x74, (byte)0x61, (byte)0x63, (byte)0x74, (byte)0x31,
			(byte)0x0B, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06,
			(byte)0x13, (byte)0x02, (byte)0x44, (byte)0x45, (byte)0x30, (byte)0x1E, (byte)0x17, (byte)0x0D,
			(byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31,
			(byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x5A, (byte)0x17, (byte)0x0D, (byte)0x34,
			(byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31,
			(byte)0x31, (byte)0x31, (byte)0x31, (byte)0x5A, (byte)0x30, (byte)0x54, (byte)0x31, (byte)0x2F,
			(byte)0x30, (byte)0x2D, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x0C,
			(byte)0x26, (byte)0x43, (byte)0x61, (byte)0x72, (byte)0x64, (byte)0x43, (byte)0x6F, (byte)0x6E,
			(byte)0x74, (byte)0x61, (byte)0x63, (byte)0x74, (byte)0x20, (byte)0x44, (byte)0x65, (byte)0x76,
			(byte)0x69, (byte)0x63, (byte)0x65, (byte)0x20, (byte)0x41, (byte)0x75, (byte)0x74, (byte)0x68,
			(byte)0x65, (byte)0x6E, (byte)0x74, (byte)0x69, (byte)0x63, (byte)0x61, (byte)0x74, (byte)0x69,
			(byte)0x6F, (byte)0x6E, (byte)0x20, (byte)0x43, (byte)0x41, (byte)0x20, (byte)0x31, (byte)0x31,
			(byte)0x14, (byte)0x30, (byte)0x12, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0A,
			(byte)0x0C, (byte)0x0B, (byte)0x43, (byte)0x61, (byte)0x72, (byte)0x64, (byte)0x43, (byte)0x6F,
			(byte)0x6E, (byte)0x74, (byte)0x61, (byte)0x63, (byte)0x74, (byte)0x31, (byte)0x0B, (byte)0x30,
			(byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02,
			(byte)0x44, (byte)0x45, (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x33, (byte)0x30, (byte)0x81,
			(byte)0xEC, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D,
			(byte)0x02, (byte)0x01, (byte)0x30, (byte)0x81, (byte)0xE0, (byte)0x02, (byte)0x01, (byte)0x01,
			(byte)0x30, (byte)0x2C, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE,
			(byte)0x3D, (byte)0x01, (byte)0x01, (byte)0x02, (byte)0x21, (byte)0x00, (byte)0xA9, (byte)0xFB,
			(byte)0x57, (byte)0xDB, (byte)0xA1, (byte)0xEE, (byte)0xA9, (byte)0xBC, (byte)0x3E, (byte)0x66,
			(byte)0x0A, (byte)0x90, (byte)0x9D, (byte)0x83, (byte)0x8D, (byte)0x72, (byte)0x6E, (byte)0x3B,
			(byte)0xF6, (byte)0x23, (byte)0xD5, (byte)0x26, (byte)0x20, (byte)0x28, (byte)0x20, (byte)0x13,
			(byte)0x48, (byte)0x1D, (byte)0x1F, (byte)0x6E, (byte)0x53, (byte)0x77, (byte)0x30, (byte)0x44,
			(byte)0x04, (byte)0x20, (byte)0x7D, (byte)0x5A, (byte)0x09, (byte)0x75, (byte)0xFC, (byte)0x2C,
			(byte)0x30, (byte)0x57, (byte)0xEE, (byte)0xF6, (byte)0x75, (byte)0x30, (byte)0x41, (byte)0x7A,
			(byte)0xFF, (byte)0xE7, (byte)0xFB, (byte)0x80, (byte)0x55, (byte)0xC1, (byte)0x26, (byte)0xDC,
			(byte)0x5C, (byte)0x6C, (byte)0xE9, (byte)0x4A, (byte)0x4B, (byte)0x44, (byte)0xF3, (byte)0x30,
			(byte)0xB5, (byte)0xD9, (byte)0x04, (byte)0x20, (byte)0x26, (byte)0xDC, (byte)0x5C, (byte)0x6C,
			(byte)0xE9, (byte)0x4A, (byte)0x4B, (byte)0x44, (byte)0xF3, (byte)0x30, (byte)0xB5, (byte)0xD9,
			(byte)0xBB, (byte)0xD7, (byte)0x7C, (byte)0xBF, (byte)0x95, (byte)0x84, (byte)0x16, (byte)0x29,
			(byte)0x5C, (byte)0xF7, (byte)0xE1, (byte)0xCE, (byte)0x6B, (byte)0xCC, (byte)0xDC, (byte)0x18,
			(byte)0xFF, (byte)0x8C, (byte)0x07, (byte)0xB6, (byte)0x04, (byte)0x41, (byte)0x04, (byte)0x8B,
			(byte)0xD2, (byte)0xAE, (byte)0xB9, (byte)0xCB, (byte)0x7E, (byte)0x57, (byte)0xCB, (byte)0x2C,
			(byte)0x4B, (byte)0x48, (byte)0x2F, (byte)0xFC, (byte)0x81, (byte)0xB7, (byte)0xAF, (byte)0xB9,
			(byte)0xDE, (byte)0x27, (byte)0xE1, (byte)0xE3, (byte)0xBD, (byte)0x23, (byte)0xC2, (byte)0x3A,
			(byte)0x44, (byte)0x53, (byte)0xBD, (byte)0x9A, (byte)0xCE, (byte)0x32, (byte)0x62, (byte)0x54,
			(byte)0x7E, (byte)0xF8, (byte)0x35, (byte)0xC3, (byte)0xDA, (byte)0xC4, (byte)0xFD, (byte)0x97,
			(byte)0xF8, (byte)0x46, (byte)0x1A, (byte)0x14, (byte)0x61, (byte)0x1D, (byte)0xC9, (byte)0xC2,
			(byte)0x77, (byte)0x45, (byte)0x13, (byte)0x2D, (byte)0xED, (byte)0x8E, (byte)0x54, (byte)0x5C,
			(byte)0x1D, (byte)0x54, (byte)0xC7, (byte)0x2F, (byte)0x04, (byte)0x69, (byte)0x97, (byte)0x02,
			(byte)0x21, (byte)0x00, (byte)0xA9, (byte)0xFB, (byte)0x57, (byte)0xDB, (byte)0xA1, (byte)0xEE,
			(byte)0xA9, (byte)0xBC, (byte)0x3E, (byte)0x66, (byte)0x0A, (byte)0x90, (byte)0x9D, (byte)0x83,
			(byte)0x8D, (byte)0x71, (byte)0x8C, (byte)0x39, (byte)0x7A, (byte)0xA3, (byte)0xB5, (byte)0x61,
			(byte)0xA6, (byte)0xF7, (byte)0x90, (byte)0x1E, (byte)0x0E, (byte)0x82, (byte)0x97, (byte)0x48,
			(byte)0x56, (byte)0xA7, (byte)0x02, (byte)0x01, (byte)0x01, (byte)0x03, (byte)0x42, (byte)0x00,
			(byte)0x04, (byte)0x4C, (byte)0x01, (byte)0xEA, (byte)0x36, (byte)0xC5, (byte)0x06, (byte)0x5F,
			(byte)0xF4, (byte)0x7E, (byte)0x8F, (byte)0x06, (byte)0x76, (byte)0xA7, (byte)0x7C, (byte)0xDC,
			(byte)0xED, (byte)0x6C, (byte)0x8F, (byte)0x74, (byte)0x5E, (byte)0x67, (byte)0x84, (byte)0xF7,
			(byte)0x80, (byte)0x7F, (byte)0x55, (byte)0x20, (byte)0x12, (byte)0x4F, (byte)0x81, (byte)0xED,
			(byte)0x05, (byte)0x41, (byte)0x12, (byte)0xDC, (byte)0xE4, (byte)0x71, (byte)0xCA, (byte)0x00,
			(byte)0x34, (byte)0x42, (byte)0x83, (byte)0x0A, (byte)0x10, (byte)0xC7, (byte)0x5B, (byte)0x31,
			(byte)0xF9, (byte)0xBF, (byte)0xAD, (byte)0xD6, (byte)0x06, (byte)0x28, (byte)0xF4, (byte)0x71,
			(byte)0x31, (byte)0x62, (byte)0x8C, (byte)0x72, (byte)0x54, (byte)0xAD, (byte)0x8B, (byte)0x95,
			(byte)0x6A, (byte)0xA3, (byte)0x45, (byte)0x30, (byte)0x43, (byte)0x30, (byte)0x0E, (byte)0x06,
			(byte)0x03, (byte)0x55, (byte)0x1D, (byte)0x0F, (byte)0x01, (byte)0x01, (byte)0xFF, (byte)0x04,
			(byte)0x04, (byte)0x03, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x30, (byte)0x12, (byte)0x06,
			(byte)0x03, (byte)0x55, (byte)0x1D, (byte)0x13, (byte)0x01, (byte)0x01, (byte)0xFF, (byte)0x04,
			(byte)0x08, (byte)0x30, (byte)0x06, (byte)0x01, (byte)0x01, (byte)0xFF, (byte)0x02, (byte)0x01,
			(byte)0x01, (byte)0x30, (byte)0x1D, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1D, (byte)0x0E,
			(byte)0x04, (byte)0x16, (byte)0x04, (byte)0x14, (byte)0x7A, (byte)0x2F, (byte)0xBB, (byte)0x93,
			(byte)0x7D, (byte)0xCC, (byte)0xE2, (byte)0x03, (byte)0x81, (byte)0x0F, (byte)0x6E, (byte)0xCE,
			(byte)0x60, (byte)0x9A, (byte)0xB8, (byte)0xAD, (byte)0xB5, (byte)0xF1, (byte)0x36, (byte)0xB5,
			(byte)0x30, (byte)0x0C, (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE,
			(byte)0x3D, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x48,
			(byte)0x00, (byte)0x30, (byte)0x45, (byte)0x02, (byte)0x20, (byte)0x37, (byte)0x33, (byte)0x53,
			(byte)0xF3, (byte)0x28, (byte)0x12, (byte)0x2D, (byte)0x63, (byte)0xF5, (byte)0x32, (byte)0xB7,
			(byte)0x6F, (byte)0xFF, (byte)0x2F, (byte)0xF5, (byte)0xB9, (byte)0xDA, (byte)0x50, (byte)0xA7,
			(byte)0xA5, (byte)0x84, (byte)0xD8, (byte)0x5C, (byte)0xE1, (byte)0x0B, (byte)0x9B, (byte)0x6C,
			(byte)0xEA, (byte)0xF0, (byte)0xD9, (byte)0xCD, (byte)0x9E, (byte)0x02, (byte)0x21, (byte)0x00,
			(byte)0x9D, (byte)0x1E, (byte)0x3B, (byte)0xBB, (byte)0xBD, (byte)0xF4, (byte)0x02, (byte)0x6E,
			(byte)0xCC, (byte)0x3D, (byte)0x8A, (byte)0xD3, (byte)0x46, (byte)0x7A, (byte)0x06, (byte)0xA8,
			(byte)0x33, (byte)0x45, (byte)0xB4, (byte)0xA2, (byte)0x28, (byte)0x8E, (byte)0xCD, (byte)0x86,
			(byte)0x2A, (byte)0x8B, (byte)0xF2, (byte)0x05, (byte)0xD5, (byte)0x95, (byte)0xCE, (byte)0xE9};



	private SmartCardHSMAppletState state = null;
	private RemoteClient remoteClient = null;
	private int maxCAPDU = MAX_APDU;
	private int maxRAPDU = MAX_APDU;
	private int maxCData;
	private int maxRData;
	private boolean limitedAPDU = false;
	private int fastDeleteThreshold = 0;
	private int fastDeleteCount = 0;
	private String id = null;



	/* Set Algorithms*/
	static {
		HashMap<String, Byte> v15 = new HashMap<String, Byte>();
		v15.put("SHA1withRSA", (byte)0x31);
		v15.put("SHA256withRSA", (byte)0x33);

		HashMap<String, Byte> pss = new HashMap<String, Byte>();
		pss.put("NONEwithRSA", (byte)0x40);
		pss.put("SHA1withRSA", (byte)0x41);
		pss.put("SHA256withRSA", (byte)0x43);

		HashMap<String, Byte> none = new HashMap<String, Byte>();
		none.put("NONEwithRSA", (byte)0x20);
		none.put("NONEwithECDSA", (byte)0x70);

		none.put("SHA1withECDSA", (byte)0x71);
		none.put("SHA224withECDSA", (byte)0x72);
		none.put("SHA256withECDSA", (byte)0x73);

		none.put("DEFAULT_ALGORITHM", (byte)0xA0);


		HashMap<String, Byte> defaultAlg = new HashMap<String, Byte>();
		defaultAlg.put("SHA1withRSA", (byte)0x31);
		defaultAlg.put("SHA256withRSA", (byte)0x33);
		defaultAlg.put("NONEwithRSA", (byte)0x20);
		defaultAlg.put("NONEwithECDSA", (byte)0x70);
		defaultAlg.put("SHA1withECDSA", (byte)0x71);
		defaultAlg.put("SHA224withECDSA", (byte)0x72);
		defaultAlg.put("SHA256withECDSA", (byte)0x73);
		defaultAlg.put("DEFAULT_ALGORITHM", (byte)0xA0);

		ALGORITHM_PADDING.put("PKCS1_V15", v15);
		ALGORITHM_PADDING.put("PKCS1_PSS", pss);
		ALGORITHM_PADDING.put("NONE", none);
		ALGORITHM_PADDING.put("DEFAULT", defaultAlg);
	}



	/**
	 * True if terminal pin pad shall be used.
	 * Default: false
	 */
	private boolean usePinPad = false;


	/**
	 * True if the Device Authentication Certificate and Device Issuer Certificate should be added as alias
	 * Default: false
	 */
	private boolean addDeviceCertificateToAliases = true;


	private ChangeReferenceDataDialog changeRefenceDataDialog;



	public SmartCardHSMCardService() {
		super();
	}



	@Override
	protected void initialize(CardServiceScheduler scheduler, SmartCard card, boolean blocking) throws CardServiceException {
		super.initialize(scheduler, card, blocking);

		try {
			allocateCardChannel();
			CardChannel channel = getCardChannel();
			Hashtable<AppletID, AppletState> channelState = (Hashtable<AppletID, AppletState>) channel.getState();
			this.state = (SmartCardHSMAppletState)channelState.get(AID);

			if (this.state  == null) {
				this.state = new SmartCardHSMAppletState();
				channelState.put(AID, this.state);
			}

			Properties features = channel.getCardTerminal().features();
			if (features.containsKey("maxRAPDUSize")) {
				this.maxRAPDU = Integer.valueOf(features.getProperty("maxRAPDUSize"));
				this.limitedAPDU = true;
			}
			if (features.containsKey("maxCAPDUSize")) {
				this.maxCAPDU = Integer.valueOf(features.getProperty("maxCAPDUSize"));
				this.limitedAPDU = true;
			}

			// 9 Byte CLA|INS|P1|P2|LcEx||LeEx
			// 19 Byte SM overhead (Tag 85, 3 byte length, 1 byte padding indicator, tag 97 02 <Le> and tag 8E 08 <mac>
			// 1 byte required for padding
			this.maxCData = ((this.maxCAPDU - 9 - 19) / 16) * 16 - 1;

			// 19 Byte SM overhead (Tag 85, 3 byte length, 1 byte padding indicator, tag 99 02 SW1SW2 and tag 8E 08 <mac>
			// 2 byte SW1/SW2
			// 1 byte required for padding
			this.maxRData = ((this.maxRAPDU - 18 - 2) / 16) * 16 - 1;

		} finally {
			releaseCardChannel();
		}
	}



	/**
	 * Process response to applet selection and extract version number
	 */
	@Override
	protected void checkSelectResponse(AppletInfo info) {
		ResponseAPDU rsp = (ResponseAPDU)info.getData();
		IsoFileControlInformation fci = new IsoFileControlInformation(rsp.data());
		byte[] pd = fci.getProprietary();

		int version = (pd[pd.length - 2] << 8) | pd[pd.length - 1];
		this.state.setVersion(version);
	}



	/**
	 * Enable or disable the pin pad
	 * @param usePinPad
	 */
	public void useClassThreePinPad(boolean usePinPad) {
		this.usePinPad = usePinPad;
	}



	/**
	 * Enable or disable adding the Device Authentication Certificates to the aliases
	 * @param usePinPad
	 */
	public void addDeviceCertificateToAliases(boolean addDeviceCertificateToAliases) {
		this.addDeviceCertificateToAliases = addDeviceCertificateToAliases;
	}




	@Override
	protected boolean isSelected(CardChannel channel) throws CardTerminalException {
		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU res = new ResponseAPDU(2);

		com.setLength(0);
		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_VERIFY);
		com.append((byte)0);
		com.append((byte)0x81);

		res = channel.sendCommandAPDU(com);

		return res.sw() == 0x9000;
	}



	/**
	 * Calculate credential and set the flag for secure messaging
	 *
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public void initSecureMessaging() throws CardServiceException, CardTerminalException {

		ECPublicKey devAutPubKey = getDevAutPK();

		EAC20 eac = new EAC20(this, devAutPubKey);
		this.state.setSecureChannelCredential(eac.performChipAuthentication());
	}



	/**
	 * Return the unique id for the SmartCard-HSM
	 *
	 * The ID is only available after the secure channel has been established
	 *
	 * @return the id or null if secure messaging has not been started yet
	 */
	public String getId() throws OpenCardException {
		if (id == null) {
			getDevAutPK();
		}
		return id;
	}



	public String getProvisioningURL() {
		try {
			byte[] trustedConfig = read(new CardFilePath(":CB00"), 0, READ_SEVERAL);
			ConstructedTLV tlv = (ConstructedTLV)TLV.factory(trustedConfig);
			return new String(tlv.get(0).getValue());
		} catch (OpenCardException | TLVEncodingException e) {
			log.error("Could not read trusted configuration", e);
			return null;
		}
	}



	public int getVersion() throws CardTerminalException, CardServiceException {
		int version = this.state.getVersion();

		if (version != 0) {
			return version;
		}

		CommandAPDU com = new CommandAPDU(5);

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_INITIALIZE);
		com.append((byte)0);
		com.append((byte)0);
		com.append((byte)0);

		ResponseAPDU res = sendCommandAPDU(com);

		// Feature was first introduced in V2.4
		if ((res.sw() != 0x9000) || (res.getLength() < 4)) {
			return 0;
		}

		version = (res.getByte(res.getLength() - 4) << 8) | res.getByte(res.getLength() - 3);
		this.state.setVersion(version);
		return version;
	}



	/**
	 * Deactivate the use of secure messaging.
	 * All further APDUs will be send in plain until invocation
	 * of initSecureMessaging()
	 */
	public void deactivateSecureMessaging() {
		this.state.setSecureChannelCredential(null);
	}



	/**
	 * Returns true if the card terminal has a pin pad.
	 * @return true if class 3 card terminal
	 */
	private boolean hasSendVerifiedCommandAPDU(){
		allocateCardChannel();
		opencard.core.terminal.CardTerminal ct = getCardChannel().getCardTerminal();
		boolean hasSendVerifiedCommandAPDU = ct instanceof VerifiedAPDUInterface;

		if (ct instanceof ExtendedVerifiedAPDUInterface) {
			ExtendedVerifiedAPDUInterface terminal = (ExtendedVerifiedAPDUInterface) ct;
			hasSendVerifiedCommandAPDU = terminal.hasSendVerifiedCommandAPDU();
		}
		releaseCardChannel();
		return hasSendVerifiedCommandAPDU;
	}



	/**
	 * Send a command with secure messaging to the card.
	 * @param com the command apdu
	 * @return
	 */
	private ResponseAPDU sendSecMsgCommand(CommandAPDU com) throws CardTerminalException, CardServiceException {
		ResponseAPDU res = null;

		SecureChannelCredential credential = this.state.getSecureChannelCredential();

		SecureChannel sc = credential.getSecureChannel();

		com = sc.wrap(com, credential.getUsageQualifier());

		res = sendCommandAPDU(AID, com);

		if (res.getLength() == 2) {				// Secure messaging error, cancel session keys
			this.state.setSecureChannelCredential(null);
			return res;
		}
		res = sc.unwrap(res, credential.getUsageQualifier());
		return res;
	}



	/**
	 * Send a command to the card, potentially using secure messaging
	 *
	 * @param com the command
	 * @return the response
	 *
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public ResponseAPDU sendCommandAPDU(CommandAPDU com) throws CardTerminalException, CardServiceException {
		ResponseAPDU res;

		if ((com.getByte(0) & 0x08) == 0x08) {
			this.state.setSecureChannelCredential(null);
		}
		if (this.state.useSecureChannel()) {
			res = sendSecMsgCommand(com);
		} else {
			res = sendCommandAPDU(AID, com);
		}
		return res;
	}



	/**
	 * Reselect applet, thus removing any authentication state and secure channel
	 *
	 */
	@Override
	public void closeApplication(SecurityDomain domain)
			throws CardServiceException, CardTerminalException {
		deactivateSecureMessaging();
		try {
			allocateCardChannel();
			CardChannel channel = getCardChannel();
			AppletSelector selector = this.getAppletSelector();
			selector.selectApplet(channel, AID);
		} finally {
			releaseCardChannel();
		}
	}



	/**
	 * Not implemented
	 *
	 */
	@Override
	public int getPasswordLength(SecurityDomain domain, int number)
			throws CardServiceException, CardTerminalException {
		return 0;
	}



	/**
	 * Verify biometric template
	 *
	 * @param id
	 *            the template id (0x85 or 0x86)
	 * @param template
	 *            the biometric template
	 *
	 * @return true if authentication was successful
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public boolean verifyBio(byte id, byte[] template) throws CardTerminalException, CardServiceException {
		CommandAPDU com = new CommandAPDU(300);
		ResponseAPDU res = new ResponseAPDU(2);

		com.setLength(0);
		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_VERIFY);
		com.append((byte) 0);
		com.append(id);
		com.append((byte) template.length);

		System.arraycopy(template, 0, com.getBuffer(), 5, template.length);
		com.setLength(5 + template.length);

		sendCommandAPDU(com);
		return getSecurityStatus();
	}



	/**
	 * Get password from a callback mechanism or from a terminal pin pad
	 * and send it to the card.
	 * This method uses default CHVControl settings.
	 * @return true if verification was successful
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 * @throws CardServiceOperationFailedException is operation is cancelled by user or change PIN failed
	 */
	public boolean verifyPassword() throws CardServiceException, CardTerminalException {
		boolean verified = false;
		CardTerminalIOControl ioctl =
				new CardTerminalIOControl(0, 30, CardTerminalIOControl.IS_NUMBERS, "" );
		CHVControl cc =
				new CHVControl( "Enter your password", 1, CHVEncoder.STRING_ENCODING, 0, ioctl);

		// Check if the card is already verified
		PasswordStatus pws = getPasswordStatus(null, 1);
		if (pws == PasswordStatus.VERIFIED) {
			return true;
		} else if (pws == PasswordStatus.TRANSPORTMODE) {
			ChangeReferenceDataDialog dialog = new ChangeReferenceDataDialog();
			dialog.setPasswordStatus(pws);
			setChangeReferenceDataDialog(dialog);
			return changeReferenceData();
		} else if (getPasswordStatus(null, 0x85) != PasswordStatus.NOTINITIALIZED) {
			byte[] template = new byte[] { 0x7F, 0x24, 0x00 };
			return verifyBio((byte) 0x85, template);
		}

		if (usePinPad && hasSendVerifiedCommandAPDU()) {
			// verify pin with the terminal's pin pad
			// after that the secure channel will be
			// re-established if doSecureChannel is set to true
			verified = verifyPassword(null, 0, cc, null);
		} else {
			// Obtain the pin from a given callback.
			// The default callback prompt a gui.
			CHVDialog dialog = getCHVDialog();

			if (dialog == null) {
				dialog = new SmartCardHSMCHVDialog(this);
				setCHVDialog(dialog);
			}

			if (dialog instanceof SmartCardHSMCHVDialog) {
				SmartCardHSMCHVDialog extendedDialog = (SmartCardHSMCHVDialog)dialog;
				extendedDialog.setPasswordStatus(pws);
			}

			String password = dialog.getCHV(-1);
			if (password == null) { // Dialog was canceled or PIN changed
				pws = getPasswordStatus(null, 1);
				if (pws == PasswordStatus.VERIFIED) { // PIN successfully changed
					return true;
				}
				if (pws == PasswordStatus.BLOCKED) {
					throw new CardServiceInvalidCredentialException("PIN is blocked");
				}
				throw new CardServiceOperationFailedException("PIN entry cancelled or change of User PIN failed");
			}
			byte[] passbytes = CHVUtils.encodeCHV(cc, password);
			verified = this.verifyPassword(null, 0, passbytes);
		}

		return verified;
	}



	/**
	 * Get the card's security status
	 *
	 * @return true if the card is in a verified state, false otherwise
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public boolean getSecurityStatus() throws CardServiceException, CardTerminalException {
		PasswordStatus pws = getPasswordStatus(null, 1);
		return pws == PasswordStatus.VERIFIED;
	}



	/**
	 * @param domain not in use, set to null
	 * @param number not in use, set to 0
	 * @param password The password data that has to be verified or null
	 */
	@Override
	public boolean verifyPassword(SecurityDomain domain, int number,
			byte[] password) throws CardServiceException, CardTerminalException {

		if (password == null) {
			return verifyPassword();
		}

		if (getSecurityStatus()) {
			return true;
		}

		boolean result = false;
		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU res = new ResponseAPDU(2);

		com.setLength(0);
		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_VERIFY);
		com.append((byte)0);
		com.append((byte)0x81);	//Local PIN 1
		com.append((byte)password.length);
		System.arraycopy(password, 0, com.getBuffer(), 5, password.length);
		com.setLength(5 + password.length);

		if (this.state.useSecureChannel()) {
			com.append((byte)0x00);
			res = sendSecMsgCommand(com);
		} else {
			res = sendCommandAPDU(AID, com);
		}
		com.clear();

		if (res.sw() == IsoConstants.RC_OK) {
			result = true;
		} else if (((res.sw() & 0xFFF0) == IsoConstants.RC_WARNING0LEFT) ||
				(res.sw() == IsoConstants.RC_AUTHMETHLOCKED)){
			result = false;
		} else {
			throw new CardServiceUnexpectedStatusWordException("VERIFY" ,res.sw());
		}
		return result;
	}



	/**
	 * If there is a class 3 card terminal the pin will be entered on the terminal's pin pad.
	 * Otherwise a callback mechanism will be used.
	 * To guarantee the functionality of the class 3 terminal the command apdu will never send with
	 * secure messaging.
	 *
	 * @param domain not in use, set to null
	 * @param number not in use, set to 0
	 * @param password not in use, set to null
	 */
	@Override
	public boolean verifyPassword(SecurityDomain domain, int number,
			CHVControl cc, byte[] password) throws CardServiceException,
			CardTerminalException {

		// If no class three reader is available use this dialog
		if (!hasSendVerifiedCommandAPDU() && getCHVDialog() == null) {
			SmartCardHSMCHVDialog dialog = new SmartCardHSMCHVDialog(this);
			PasswordStatus status = getPasswordStatus(null, 1);
			dialog.setPasswordStatus(status);
			setCHVDialog(dialog);
		}

		boolean result = false;
		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU res = new ResponseAPDU(2);

		com.setLength(0);
		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_VERIFY);
		com.append((byte)0);
		com.append((byte)0x81);	//Local PIN 1

		try {
			res = sendVerifiedAPDU(getChannel(), AID, com, cc, -1);
		} catch (CardServiceException e) {
			throw e;
		} finally {
			releaseCardChannel();
		}

		if (this.state.useSecureChannel()) {

			/* re-establish secure channel
			 * because it broken up by sending
			 * a plain apdu to the card
			 */
			this.state.setSecureChannelCredential(null);
			initSecureMessaging();
		}

		if (res.sw() == IsoConstants.RC_OK) {
			result = true;
		} else if (((res.sw() & 0xFFF0) == IsoConstants.RC_WARNING0LEFT) ||
				(res.sw() == IsoConstants.RC_AUTHMETHLOCKED)){
			result = false;
		} else {
			throw new CardServiceUnexpectedStatusWordException("VERIFY" ,res.sw());
		}
		return result;
	}



	/**
	 * @param domain not in use, set to null
	 * @param number not in use, set to 0
	 */
	@Override
	public PasswordStatus getPasswordStatus(SecurityDomain domain, int number)
			throws CardServiceException, CardTerminalException {
		PasswordStatus status;
		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU res = new ResponseAPDU(2);

		if (number == 1) {
			status = getPasswordStatus(domain, 0x81);
			if ((status == PasswordStatus.TRANSPORTMODE) || (status == PasswordStatus.NOTINITIALIZED)) {
				if (getPasswordStatus(domain, 0x88) == PasswordStatus.NOTINITIALIZED) {
					return PasswordStatus.NOTINITIALIZED;
				}
				status = PasswordStatus.NOTVERIFIED;
			}
			return status;
		}

		com.setLength(0);
		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_VERIFY);
		com.append((byte)0);
		com.append((byte) number); // Local PIN 1

		if (this.state.useSecureChannel()) {
			com.append((byte)0x00);
			res = sendSecMsgCommand(com);
		} else {
			res = sendCommandAPDU(AID, com);
		}

		if (res.sw() == IsoConstants.RC_OK) {
			status = PasswordStatus.VERIFIED;
		} else if (res.sw() == IsoConstants.RC_WARNING1LEFT) {
			status = PasswordStatus.LASTTRY;
		} else if (res.sw() == IsoConstants.RC_WARNING2LEFT) {
			status = PasswordStatus.RETRYCOUNTERLOW;
		} else if ((res.sw() & 0xFFF0) == IsoConstants.RC_WARNING0LEFT) {
			status = PasswordStatus.NOTVERIFIED;
		} else if (res.sw() == IsoConstants.RC_AUTHFAILED) {
			status = PasswordStatus.NOTVERIFIED;
		} else if (res.sw() == IsoConstants.RC_AUTHMETHLOCKED) {
			status = PasswordStatus.BLOCKED;
		} else if (res.sw() == IsoConstants.RC_REFDATANOTUSABLE) {
			status = PasswordStatus.TRANSPORTMODE;
		} else if ((res.sw() == IsoConstants.RC_RDNOTFOUND) || (res.sw() == IsoConstants.RC_INCP1P2)) {
			status = PasswordStatus.NOTINITIALIZED;
		} else {
			throw new CardServiceUnexpectedStatusWordException("VERIFY" ,res.sw());
		}
		return status;
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public void appendRecord(CardFilePath file, byte[] data)
			throws CardServiceException, CardTerminalException {

		throw new CardServiceInabilityException("appendRecord() ist not implemented");
	}



	/**
	 * Determine if file exists.
	 *
	 * @param file the path to the file
	 * @return true or false if file doesn't exist
	 *
	 * @see opencard.opt.iso.fs.FileAccessCardService#exists(CardFilePath)
	 */
	@Override
	public boolean exists(CardFilePath file) throws CardServiceException,
	CardTerminalException {

		try	{
			getFileInfo(file);
		}
		catch(CardServiceObjectNotAvailableException e) {
			return false;
		}
		return true;
	}



	/**
	 * Queries information about a file. If the file doesn't exists throws a CardServiceObjectNotAvailableException
	 * If the file is an AID, this operation will reset the card's security state.
	 * @return information about the file
	 * @throws CardServiceObjectNotAvailableException if the file doesn't exists
	 * @see opencard.opt.iso.fs.FileAccessCardService#getFileInfo(opencard.opt.iso.fs.CardFilePath)
	 */
	@Override
	public CardFileInfo getFileInfo(CardFilePath file)
			throws CardServiceException, CardTerminalException {

		CommandAPDU com = new CommandAPDU(32);
		ResponseAPDU rsp;

		//Enumeration e = file.components();
		//Object path = e.nextElement();
		Object path = file.tail();
		boolean isAID = path instanceof CardFileAppID;

		byte[] pathBytes;

		if (isAID) {
			pathBytes = ((CardFileAppID)path).toByteArray();
		} else {
			pathBytes = ((CardFileFileID)path).toByteArray();
		}

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_SELECT_FILE);
		com.append(isAID? IsoConstants.SC_AID : IsoConstants.SC_EF);
		com.append(IsoConstants.SO_RETURNFCI);
		com.append((byte)pathBytes.length);
		com.append(pathBytes);
		com.append((byte)0x00);

		if (this.state.useSecureChannel()) {
			if (isAID) {
				// select with plain APDU and re-establish secure channel
				deactivateSecureMessaging();
				rsp = sendCommandAPDU(AID, com);
				initSecureMessaging();
			} else {
				rsp = sendSecMsgCommand(com);
			}
		} else {
			rsp = sendCommandAPDU(AID, com);
		}

		if (rsp.sw() == 0x6A82) {
			throw new CardServiceObjectNotAvailableException(path + " not found.");
		}

		return new IsoFileControlInformation(rsp.data());
	}



	/**
	 * Return the application path.
	 *
	 * @see opencard.opt.iso.fs.FileAccessCardService#getRoot()
	 */
	@Override
	public CardFilePath getRoot() {
		return mf;
	}



	/**
	 * READ BINARY
	 *
	 * @param file the path to the file
	 * @param offset
	 * @param length
	 */
	@Override
	public byte[] read(CardFilePath file, int offset, int length) throws CardServiceException, CardTerminalException {

		// Check parameter
		if ((offset < 0) || ((length != READ_SEVERAL) && (length < 0))) {
			throw new CardServiceInvalidParameterException
			("read: offset = " + offset + ", length = " + length);
		}

		int chunksize = this.maxRData;

		if ((length == READ_SEVERAL) || (length == 0)) {
			length = 0xFFFF;
		}

		ResponseAPDU rsp = null;
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		while (buffer.size() < length) {
			CommandAPDU com = new CommandAPDU(14);

			com.append(IsoConstants.CLA_ISO);
			com.append(IsoConstants.INS_READ_BINARY_ODD);
			CardFileFileID fid = (CardFileFileID)file.tail();	// p1 = msb fid, p2 = lsb fid
			com.append(fid.toByteArray());
			com.append((byte)0x00);								// Three byte Lc
			com.append((byte)0x00);
			com.append((byte)0x04);
			com.append((byte)0x54);								// Data
			com.append((byte)0x02);
			com.append((byte)(offset >> 8));
			com.append((byte)offset);
			com.append((byte)(chunksize >> 8));					// Le
			com.append((byte)chunksize);

			rsp = sendCommandAPDU(com);

			byte[] data = rsp.data();
			if (data != null) {
				buffer.write(data, 0, data.length);
				offset += data.length;
			}

			if (rsp.sw() == IsoConstants.RC_EOF) {
				if ((data == null) || (this.state.getVersion() >= 0x0304)) {
					break;
				}
				if (data.length == 0) {
					break;
				}
			}

			if (rsp.sw() != IsoConstants.RC_OK && rsp.sw() != IsoConstants.RC_EOF) {
				int sw = rsp.sw();
				rsp.clear();
				throw new CardServiceUnexpectedStatusWordException("READ BINARY", sw);
			}
		}

		if (rsp != null) {
			rsp.clear();
		}
		return buffer.toByteArray();
	}




	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public byte[] readRecord(CardFilePath file, int recordNumber)
			throws CardServiceException, CardTerminalException {

		throw new CardServiceInabilityException("readRecord(CardFilePath file, int recordNumber) is not implemented");
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public byte[][] readRecords(CardFilePath file, int number)
			throws CardServiceException, CardTerminalException {

		throw new CardServiceInabilityException("readRecords(CardFilePath file, int number) is not implemented");
	}



	/**
	 * Not implemented, use write(CardFilePath file, int offset, byte[] data)
	 *
	 * @deprecated
	 */
	@Override
	public void write(CardFilePath file, int foffset, byte[] source,
			int soffset, int length) throws CardServiceException,
			CardTerminalException {

		throw new CardServiceInabilityException("write(CardFilePath file, int foffset, byte[] source, int soffset, int length) is not implemented");
	}



	/**
	 * @param file the path to the file
	 * @param offset
	 * @param data
	 */
	@Override
	public void write(CardFilePath file, int offset, byte[] data)
			throws CardServiceException, CardTerminalException {

		CommandAPDU com;
		ResponseAPDU rsp = null;

		// Check parameter
		if ((offset < 0) || offset >  0xFFFF) {
			throw new CardServiceInvalidParameterException
			("write: offset = " + offset);
		}

		if (data == null) {
			data = new byte[0];
		}

		int chunksize = this.maxCData - 8;

		CardFileFileID fid = (CardFileFileID)file.tail();
		int chunkOffs = 0;
		do {
			// Wrapping C-Data

			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			buffer.write(0x54);
			buffer.write(0x02);
			buffer.write(offset >> 8);
			buffer.write(offset);
			try {
				byte[] chunk;
				if (data.length <= chunksize) {
					chunk = data;
				} else if (data.length - chunkOffs < chunksize) {
					chunk = new byte[data.length - chunkOffs];
					System.arraycopy(data, chunkOffs, chunk, 0, chunk.length);
				} else {
					chunk = new byte[chunksize];
					System.arraycopy(data, chunkOffs, chunk, 0, chunksize);
				}
				offset += chunk.length; // Compute EF offset for next chunk
				chunkOffs += chunk.length;
				PrimitiveTLV payload = new PrimitiveTLV(0x53, chunk);
				buffer.write(payload.getBytes());
			} catch (TLVEncodingException | IOException e) {
				// ignore
			}

			// C-APDU

			com = new CommandAPDU(11 + buffer.size());
			com.append((byte)IsoConstants.CLA_ISO);
			com.append((byte)IsoConstants.INS_UPDATE_BINARY_ODD);
			com.append(fid.toByteArray());	// P1 = MSB FID, P2 = LSB FID
			com.append((byte)0x00);			// three byte length field
			com.append((byte)(buffer.size() >> 8));
			com.append((byte)buffer.size());
			com.append(buffer.toByteArray());

			rsp = sendCommandAPDU(com);

			if (rsp.sw() != 0x9000) {
				throw new CardServiceUnexpectedStatusWordException("UPDATE BINARY", rsp.sw());
			}
			if (rsp.getLength() > 2) {
				throw new CardServiceUnexpectedResponseException("No response expected");
			}
		} while (chunkOffs < data.length);
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public void writeRecord(CardFilePath file, int recordNumber, byte[] data)
			throws CardServiceException, CardTerminalException {
		throw new CardServiceInabilityException("writeRecord() is not implemented");
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public void provideCredentials(SecurityDomain domain, CredentialBag creds)
			throws CardServiceException {

		//throw new CardServiceInabilityException("provideCredentials() is not implemented");
	}



	/**
	 * Helper function for getSize() and getLengthFieldSize()
	 *
	 * @param length
	 * @return the size of the length field
	 */
	protected static int getLengthFieldSizeHelper(int length) {
		int size = 1;
		if (length >= 0x80)
			size++;
		if (length >= 0x100)
			size++;
		return size;
	}



	/**
	 * Encode length field in byte array
	 *
	 * @param length
	 * 		Length to be encoded
	 * @param bos
	 * 		ByteArrayOutputStream to copy length into
	 */
	protected static void lengthToByteArrayOutputStream(int length, ByteArrayOutputStream bos) {
		int size = getLengthFieldSizeHelper(length);
		int i = 0;

		if (size > 1) {
			bos.write((byte)(0x80 | (size - 1)));
			i = (size - 2) * 8;
		}

		for (; i >= 0; i -= 8) {
			bos.write((byte)(length >> i));
		}
	}



	/**
	 * Create a new file.
	 * Internal use of write(CardFilePath path, int offset, byte[] data)
	 *
	 * @param parent The parent CardFilePath
	 * @param data File identifier encoded as FCP data object
	 */
	@Override
	public void create(CardFilePath parent, byte[] data)
			throws CardServiceException, CardTerminalException {
		if (data.length != 4) throw new CardServiceException("Unknown data encoding");
		CardFilePath path = new CardFilePath(new byte[] { data[2], data[3] });

		write(path, 0, null);
	}



	/**
	 * Enable fast delete operation without garbage collecting freed memory.
	 *
	 * The garbage collector in the JCVM is triggered if memory is running low
	 * or if an out of memory condition occurs. However, garbage collection only occurs
	 * before executing the next command, so the OOM error is always reported to the
	 * application and must be handled accordingly.
	 *
	 * As a default setting, the DELETE command will trigger garbage collection
	 * on every invocation. By setting a threshold, the specified number of
	 * delete operations will be performed without garbage collection.
	 *
	 * @param threshold the number of delete operations without garbage collection.
	 */
	public void setFastDeleteThreshold(int threshold) {
		this.fastDeleteThreshold = threshold;
		this.fastDeleteCount = threshold;
	}



	/**
	 * Delete elementary files or key objects
	 */
	@Override
	public void delete(CardFilePath file) throws CardServiceException,
	CardTerminalException {

		CommandAPDU com = new CommandAPDU(7);
		ResponseAPDU rsp;

		byte p2 = (byte)0x00;					// Delete with garbage collection
		if (this.fastDeleteCount > 0) {
			p2 = (byte)0x80;					// Delete without garbage collection
			this.fastDeleteCount--;
		} else {
			this.fastDeleteCount = this.fastDeleteThreshold;
		}

		CardFileFileID data = (CardFileFileID)file.tail();
		byte[] fid = data.toByteArray();

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_DELETE_FILE);
		com.append((byte)0x02); //Delete EF under current DF
		com.append(p2);
		com.append((byte)0x02); //Lc
		System.arraycopy(fid, 0, com.getBuffer(), com.getLength(), fid.length);
		com.setLength(5 + fid.length);

		rsp = sendCommandAPDU(com);

		if ((rsp.sw() != IsoConstants.RC_OK) && (rsp.sw() != IsoConstants.RC_FILENOTFOUND)) {
			throw new CardServiceUnexpectedStatusWordException("DELETE FILE", rsp.sw());
		}
		if (rsp.getLength() > 2) {
			throw new CardServiceUnexpectedResponseException("No response expected");
		}
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public void invalidate(CardFilePath file)
			throws CardServiceInabilityException, CardServiceException,
			CardTerminalException {
		throw new CardServiceInabilityException("invalidate(CardFilePath file) is not implemented");
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public void rehabilitate(CardFilePath file)
			throws CardServiceInabilityException, CardServiceException,
			CardTerminalException {
		throw new CardServiceInabilityException("rehabilitate(CardFilePath file) is not implemented");
	}



	/**
	 * Get both passwords, the current password and the new one from a callback mechanism
	 * and send it to the card.
	 * This method uses default CHVControl settings.
	 * @return true if verification was successful
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public boolean changeReferenceData() throws CardServiceException, CardTerminalException {
		boolean modified;

		if (getChangeReferenceDataDialog() == null) {
			this.changeRefenceDataDialog = new ChangeReferenceDataDialog();
		}

		// Add a notification if the card is in transport mode
		PasswordStatus status = getPasswordStatus(null, 1);
		if (status == PasswordStatus.TRANSPORTMODE) {
			changeRefenceDataDialog.setPasswordStatus(status);
		}

		if (!changeRefenceDataDialog.showDialog()) {
			throw new CardServiceInvalidCredentialException("CHV cancelled");
		}
		modified = changeReferenceData(null, 0x81, null, changeRefenceDataDialog.getCurrentPIN(), changeRefenceDataDialog.getNewPIN());

		// If change reference data was not successful
		// a notification will be shown on the next invocation of the dialog
		if (!modified) {
			changeRefenceDataDialog.setPasswordStatus(PasswordStatus.NOTVERIFIED);
		}
		return modified;
	}



	/**
	 * Change the User PIN or SO PIN.
	 *
	 * @param domain Not used
	 * @param number Must be one of 0x81 for User PIN or 0x88 for SO PIN
	 * @param cc Not used
	 * @param currentPassword
	 * @param newPassword
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	@Override
	public boolean changeReferenceData(SecurityDomain domain, int number,
			CHVControl cc, byte[] currentPassword, byte[] newPassword)
					throws CardTerminalException, CardServiceException {

		if ((number != USER_PIN) && (number != SO_PIN)) {
			throw new CardServiceInvalidParameterException("Parameter \"number\" must be one of 0x81 or 0x88");
		}

		CommandAPDU com = new CommandAPDU(5 + currentPassword.length + newPassword.length);
		ResponseAPDU res;
		boolean result = false;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_CHANGE_CHV);
		com.append((byte)0x0);
		com.append((byte)number); //USER_PIN or SO_PIN
		com.append((byte)(currentPassword.length + newPassword.length));
		com.append(currentPassword);
		com.append(newPassword);

		res = sendCommandAPDU(com);

		if (res.sw() == IsoConstants.RC_OK) {
			result = true;
		} else if ((res.sw() & 0xFFF0) == IsoConstants.RC_WARNING0LEFT) {
			result = false;
		} else {
			throw new CardServiceUnexpectedStatusWordException("VERIFY" ,res.sw());
		}
		return result;
	}



	/**
	 * The device is initialized with a User PIN during device initialization.
	 * If this User PIN is blocked it can be reset
	 * using the SO PIN (initialization code) of the device.
	 *
	 *
	 * @param domain Not in use
	 * @param number Set to local PIN '81'
	 * @param cc Not in use
	 * @param unblockingCode The code to unblock the card
	 * @param newPassword The new password or null
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	@Override
	public boolean resetRetryCounter(SecurityDomain domain, int number,
			CHVControl cc, byte[] unblockingCode, byte[] newPassword) throws CardTerminalException, CardServiceException {

		if ((number != USER_PIN) && (number != SO_PIN)) {
			throw new CardServiceInvalidParameterException("Parameter \"number\" must be one of 0x81 or 0x88");
		}

		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU rsp;
		Boolean result = false;

		// CLA
		com.append(IsoConstants.CLA_ISO);
		// INS
		com.append(IsoConstants.INS_UNBLOCK_CHV);
		// If SO PIN followed by new User PIN then P1 is 0x00,
		// otherwise for SO PIN only P1 is 0x01
		com.append(newPassword == null ? (byte)0x01 : (byte)0x00);
		// P2
		com.append((byte)number);
		// Lc
		com.append(newPassword == null ? (byte)0x08 : (byte)(newPassword.length + unblockingCode.length));
		// C-Data
		com.append(unblockingCode);
		if (newPassword != null) {
			com.append(newPassword);
		}
		//com.append((byte)0);
		rsp = sendCommandAPDU(com);

		if (rsp.sw() == IsoConstants.RC_OK) {
			result = true;
		} else if ((rsp.sw() & 0xFFF0) == IsoConstants.RC_WARNING0LEFT) {
			result = false;
		} else {
			throw new CardServiceUnexpectedStatusWordException("VERIFY" ,rsp.sw());
		}

		return result;
	}



	/**
	 * Initialize the SmartCard-HSM.
	 * This clears all cryptographic material and transparent files.
	 * It also sets the user PIN, generate a random Device Key Encryption Key
	 * and defines the basic configuration options.
	 *
	 * @param config The configuration options (default '0001')
	 * @param initPin Set the user pin
	 * @param initCode 8 byte code that protects unauthorized re-initialization
	 * @param retryCounter Initial value for the retry counter
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 * @throws TLVEncodingException
	 */
	public void initialize(byte[] config, byte[] initPin, byte[] initCode, byte retryCounter)
			throws CardTerminalException, CardServiceException, TLVEncodingException {

		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU rsp;
		ConstructedTLV data = new ConstructedTLV(0x30);
		data.add(new PrimitiveTLV(0x80, config));
		data.add(new PrimitiveTLV(0x81, initPin));
		data.add(new PrimitiveTLV(0x82, initCode));
		data.add(new PrimitiveTLV(0x91, new byte[] {retryCounter}));

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_INITIALIZE);
		com.append((byte)0x0); //p1
		com.append((byte)0x0); //p2
		com.append((byte)data.getLength());
		com.append(data.getValue());

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("INITIALIZE" ,rsp.sw());
		}
	}



	/**
	 * Initialize the SmartCard-HSM.
	 * This clears all cryptographic material and transparent files.
	 * It also sets the user PIN, defines the basic configuration options
	 * and the number of Device Key Encryption Key shares for key wrapping/unwrapping.
	 *
	 * @param config the configuration options (default '0001')
	 * @param initPin Set the user pin
	 * @param initCode 8 byte code that protects unauthorized re-initialization
	 * @param retryCounter Initial value for the retry counter
	 * @param noOfShares Number of Device Key Encryption Key shares
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 * @throws TLVEncodingException
	 */
	public void initialize(byte[] config, byte[] initPin, byte[] initCode, byte retryCounter, byte noOfShares)
			throws CardTerminalException, CardServiceException, TLVEncodingException {

		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU rsp;
		ConstructedTLV data = new ConstructedTLV(0x30);
		data.add(new PrimitiveTLV(0x80, config));
		data.add(new PrimitiveTLV(0x81, initPin));
		data.add(new PrimitiveTLV(0x82, initCode));
		data.add(new PrimitiveTLV(0x91, new byte[] {retryCounter}));
		data.add(new PrimitiveTLV(0x92, new byte[] {noOfShares}));

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_INITIALIZE);
		com.append((byte)0x0); //p1
		com.append((byte)0x0); //p2
		com.append((byte)data.getLength());
		com.append(data.getValue());

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("INITIALIZE" ,rsp.sw());
		}
	}



	/**
	 * Initialize the SmartCard-HSM.
	 * This clears all cryptographic material and transparent files
	 * except for the Device Authentication key and its certificate.
	 *
	 * Device initialization allows resetting the User PIN to an initial value
	 * or switching between User PIN and public key authentication.
	 * The first device initialization also sets an Initialization Code
	 * to prevent unauthorized re-initialization.
	 *
	 * Device Initialization allows the user to define that a Device Key Encryption Key
	 * is used and how many key shares are used to split the secret between key custodians.
	 *
	 * Device Initialization allows to enable n-of-m authentication using a threshold scheme
	 * by defining the number (m) of key custodians and the required quota to authentication (n).
	 * User PIN and n-of-m authentication are mutually exclusive.
	 * A successful device authentication sets the security state to authenticated
	 * until the next applet select or card reset.
	 *
	 * @param config how the SmartCard-HSM shall be initialized
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 * @throws TLVEncodingException
	 */
	public void initialize(InitializeConfiguration config)
			throws CardTerminalException, CardServiceException, TLVEncodingException {

		CommandAPDU com = new CommandAPDU(40);
		ResponseAPDU rsp;
		byte[] cdata = config.getCData();

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_INITIALIZE);
		com.append((byte)0x0); //p1
		com.append((byte)0x0); //p2
		com.append((byte)cdata.length);
		com.append(cdata);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("INITIALIZE" ,rsp.sw());
		}
	}



	/**
	 * Initiate the generation of a fresh key pair for the selected key object.
	 *
	 * Generating a new key pair requires a successful verification of the User PIN.
	 * @param keyId the ID for the key to be generated
	 * @param signingId  the ID for signing authenticated request
	 * @param spec the AlgorithmParameterSpec containing the domain parameter
	 * @deprecated Signing with key other than PrK.DevAur dropped in firmware 3.0
	 */
	public byte[] generateKeyPair(byte keyId, byte signingId, SmartCardHSMPrivateKeySpec spec) throws CardTerminalException, CardServiceException, TLVEncodingException {
		byte[] rsp;

		try	{
			rsp = generateKeyPair(keyId, spec);
		}
		catch(OpenCardException e) {
			throw new CardServiceException(e.getMessage());
		}
		return rsp;
	}



	/**
	 * Initiate the generation of a fresh key pair for the selected key object.
	 *
	 * Generating a new key pair requires a successful verification of the User PIN.
	 * @param keyId the ID for the key to be generated
	 * @param spec the AlgorithmParameterSpec containing the domain parameter
	 */
	@Override
	public byte[] generateKeyPair(byte keyId, SmartCardHSMPrivateKeySpec spec) throws OpenCardException {
		CommandAPDU com = new CommandAPDU(1024);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_GENERATE_KEYPAIR);

		//P1: Key identifier of the key to be generated
		com.append(keyId);
		com.append((byte)0x00);

		byte[] data;
		data = spec.getCData();

		//Three byte length field
		int length = data.length;
		com.append((byte)0x00);
		com.append((byte)(length >> 8));
		com.append((byte)length);

		//Copy command data
		System.arraycopy(data, 0, com.getBuffer(), com.getLength(), data.length);
		com.setLength(7 + data.length);

		if (!this.limitedAPDU) {
			// Le
			com.append((byte)0x00);
			com.append((byte)0x00);
		}

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != 0x9000) {
			throw new CardServiceUnexpectedStatusWordException("GENERATE ASYMMETRIC KEY PAIR", rsp.sw());
		}

		// Read the generated CSR from the specific EF using chunks
		if (this.limitedAPDU) {
			data = read(new CardFilePath(new byte[] { EECERTIFICATEPREFIX, keyId }), 0, READ_SEVERAL);
			spec.setStorePublicKey(false);
		} else {
			data = rsp.data();
		}

		return data;
	}



	/**
	 * Generate a new symmetric key
	 *
	 * @param newKeyId the id for the key to be generated
	 * @param spec the key specification
	 * @return
	 */
	public byte[] generateKey(byte newKeyId, SmartCardHSMSecretKeySpec spec) throws OpenCardException {
		CommandAPDU com = new CommandAPDU(512);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_GENERATE_KEY);

		//P1: Key identifier of the key to be generated
		com.append(newKeyId);

		byte algo = (byte)0xB0;

		switch(spec.getKeySize()) {
		case 128:
			algo = (byte)0xB0; break;
		case 192:
			algo = (byte)0xB1; break;
		case 256:
			algo = (byte)0xB2; break;
		}
		com.append(algo);

		byte[] data;
		data = spec.getCData();

		com.append((byte)data.length);
		com.append(data);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != 0x9000) {
			throw new CardServiceUnexpectedStatusWordException("GENERATE SYMMETRIC KEY failed", rsp.sw());
		}

		data = rsp.data();
		return data;
	}



	/**
	 * Import a single key share of the Device Encryption Key.
	 *
	 * @return The total number of shares, outstanding shares and the KCV
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public byte[] importDKEKShare(byte[] keyShare) throws CardTerminalException, CardServiceException {
		CommandAPDU com = new CommandAPDU(300);
		ResponseAPDU rsp;

		if (keyShare.length != 0x20) {
			throw new CardServiceInvalidParameterException("The DKEK share must have a length of 32 bytes.");
		}

		// CLA
		com.append(IsoConstants.CLA_HSM);
		// INS
		com.append((byte)0x52);
		// P1
		com.append((byte)0x00);
		// P2
		com.append((byte)0x00);
		// Lc
		com.append((byte)keyShare.length);
		// C-Data
		com.append(keyShare);
		// Le
		com.append((byte)0x00);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != 0x9000) {
			throw new CardServiceUnexpectedStatusWordException("IMPORT DKEK SHARE", rsp.sw());
		}
		return rsp.data();
	}



	/**
	 * The Wrap command allows the terminal to extract a private or secret key value
	 * encrypted under the Device Key Encryption Key.
	 *
	 * @param kid The key identifier
	 * @return the wrapped key
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public byte[] wrapKey(byte kid) throws CardTerminalException, CardServiceException {
		CommandAPDU com = new CommandAPDU(300);
		ResponseAPDU rsp;

		// CLA
		com.append((byte)0x80);
		// INS
		com.append((byte)0x72);
		// P1
		com.append((byte)kid);
		// P2
		com.append((byte)WRAP);
		// Le
		com.append((byte)0x00);
		com.append((byte)0x00);
		com.append((byte)0x00);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != 0x9000) {
			throw new CardServiceUnexpectedStatusWordException("WRAP KEY", rsp.sw());
		}
		return rsp.data();
	}



	/**
	 * The Unwrap command allows the terminal to import a private or secret key value
	 * and meta data encrypted under the Device Key Encryption Key.
	 *
	 * @param kid The key identifier
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public boolean unwrapKey(byte kid, byte[] key) throws CardTerminalException, CardServiceException {
		CommandAPDU com = new CommandAPDU(7 + key.length);
		ResponseAPDU rsp;

		// CLA
		com.append((byte)0x80);
		// INS
		com.append((byte)0x74);
		// P1
		com.append((byte)kid);
		// P2
		com.append((byte)UNWRAP);
		// Lc
		com.append((byte)0x00);
		com.append((byte)(key.length >> 8));
		com.append((byte)key.length);
		// D-Data
		com.append(key);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != 0x9000) {
			throw new CardServiceUnexpectedStatusWordException("UNWRAP KEY", rsp.sw());
		}
		return true;
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public void generateKeyPair(PrivateKeyRef privateDest,
			PublicKeyRef publicDest, int strength, String keyAlgorithm)
					throws CardServiceException, InvalidKeyException,
					CardTerminalException {
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public PublicKey readPublicKey(PublicKeyRef pulicKey, String keyAlgorithm)
			throws CardServiceException, InvalidKeyException,
			CardTerminalException {
		return null;
	}



	@Override
	public byte[] signData(PrivateKeyRef privateKey, String signAlgorithm,
			byte[] data) throws CardServiceException, CardTerminalException {

		return signData(privateKey, signAlgorithm, "DEFAULT", data);
	}



	/**
	 * Postprocess ECDSA Signature in R|S Format to normalize INTEGER
	 * values contained in the SEQUENCE. Bouncycastle rejects INTEGER
	 * elements with a superfluous leading 00
	 *
	 * @param sig the ECDSA signature
	 * @return the normalized signature
	 * @throws CardServiceOperationFailedException
	 */
	private byte[] normalizeECDSASignature(byte[] sig) throws CardServiceOperationFailedException {
		ConstructedTLV ntlv;
		try {
			ConstructedTLV tlv = new ConstructedTLV(sig);
			ntlv = new ConstructedTLV(new Tag(Tag.SEQUENCE, Tag.UNIVERSAL, true));
			for (int i = 0; i < 2; i++) {
				PrimitiveTLV x = (PrimitiveTLV)tlv.get(i);
				byte[] buf = x.getValue();
				int ofs = 0;
				while ((ofs < buf.length) && (buf[ofs] == 0x00) && ((buf[ofs +1] & 0xFF) < 0x80)) {
					ofs++;
				}
				if (ofs > 0) {
					byte[] nbuf = new byte[buf.length - ofs];
					System.arraycopy(buf, ofs, nbuf, 0, nbuf.length);
					buf = nbuf;
				}
				PrimitiveTLV nx = new PrimitiveTLV(Tag.INTEGER, buf);
				ntlv.add(nx);
			}
		} catch (TLVEncodingException e) {
			throw new CardServiceOperationFailedException("ECDSA signature invalid format");
		}
		return ntlv.getBytes();
	}



	/**
	 * Create a signature.
	 */
	@Override
	public byte[] signData(PrivateKeyRef privateKey, String signAlgorithm,
			String padAlgorithm, byte[] data) throws CardServiceException,
			CardTerminalException {

		int length = data.length;
		CommandAPDU com = new CommandAPDU(9 + length);
		ResponseAPDU rsp;

		if (signAlgorithm.contains("RSA") && !(privateKey instanceof SmartCardHSMKey)
				|| (signAlgorithm.contains("ECDSA") && !(privateKey instanceof SmartCardHSMKey))) {
			throw new CardServiceOperationFailedException("Algorithm and key don't match.");
		}

		if (ALGORITHM_PADDING.containsKey(padAlgorithm)) {
			if (ALGORITHM_PADDING.get(padAlgorithm).containsKey(signAlgorithm)) {
				com.append((byte)0x80);
				com.append(IsoConstants.INS_SIGN);
				//P1: Key identifier
				int keyNo = ((SmartCardHSMKey)privateKey).getKeyRef();
				com.append((byte)keyNo);
				//P2:Algorithm Identifier
				com.append(ALGORITHM_PADDING.get(padAlgorithm).get(signAlgorithm));
				//Three byte length field
				com.append((byte)0x00);
				com.append((byte)(length >> 8));
				com.append((byte)length);
				//Copy command data
				com.append(data);
				// Two byte Le
				com.append((byte)0x00);
				com.append((byte)0x00);

				rsp = sendCommandAPDU(com);

				if (rsp.sw() != 0x9000) {
					throw new CardServiceUnexpectedStatusWordException("SIGN", rsp.sw());
				}

				if (signAlgorithm.contains("RSA")) {
					return rsp.data();
				}
				return normalizeECDSASignature(rsp.data());
			}
		}
		throw new CardServiceOperationFailedException("There is no matching algorithm.");
	}



	/**
	 * Create a signature.
	 *
	 * If the referenced key type is RSA then the hash will be padded according
	 * to the EMSA-PKCS1-v1_5 encoding.
	 * The data will be send to the card which performs a Plain RSA signature operation.
	 *
	 * If the key is of type ECC then the hash will be send to the card which performs
	 * a Plain ECDSA operation.
	 *
	 * @param privateKey the SmartCardHSMKey
	 * @param signAlgorithm String containing the signing algorithm
	 * @param hash
	 */
	@Override
	public byte[] signHash(PrivateKeyRef privateKey, String signAlgorithm,
			byte[] hash) throws CardServiceException, InvalidKeyException,
			CardTerminalException {

		if (signAlgorithm.equals("NONEwithECDSA")) {
			return signData(privateKey, "NONEwithECDSA", hash);
		} else if (signAlgorithm.equals("SHA1withRSA") || signAlgorithm.equals("SHA256withRSA")) {
			return signHash(privateKey, signAlgorithm, "PKCS1_V15", hash);
		} else if (signAlgorithm.equals("NONEwithRSA")) {
			return signHash(privateKey, signAlgorithm, "PKCS1_V15", hash);
		} else {
			throw new CardServiceOperationFailedException("Algorithm for hash object required.");
		}
	}



	/**
	 * Create a signature.
	 *
	 * RSASSA-PSS:
	 * If using a SmartCard-HSM with version 2.00 or newer, PSS padding performed by the card is supported.
	 * The SmartCard-HSM supports padding according to PSS for the hash algorithm SHA1 and SHA256.
	 * SHA384 and SHA512 hashes will still be padded externally by this card service.
	 *
	 * If the key is of type ECC then the hash will be send to the card which performs
	 * a Plain ECDSA operation.
	 *
	 * @param privateKey the SmartCardHSMKey
	 * @param signAlgorithm String containing the signing algorithm
	 * @param padAlgorithm String containing the padding algorithm
	 * @param hash
	 */
	@Override
	public byte[] signHash(PrivateKeyRef privateKey, String signAlgorithm,
			String padAlgorithm, byte[] hash) throws CardServiceException,
			CardTerminalException {

		if (padAlgorithm.equals("PKCS1_V15")) {
			if (privateKey instanceof SmartCardHSMKey) {
				byte[] em;
				ObjectIdentifier oid = null;
				if (signAlgorithm.equals("SHA1withRSA")) {
					oid = new ObjectIdentifier("1.3.14.3.2.26");
				} else if (signAlgorithm.equals("SHA256withRSA")) {
					oid = new ObjectIdentifier("2.16.840.1.101.3.4.2.1");
				} else if (signAlgorithm.equals("SHA384withRSA")) {
					oid = new ObjectIdentifier("2.16.840.1.101.3.4.2.2");
				} else if (signAlgorithm.equals("SHA512withRSA")) {
					oid = new ObjectIdentifier("2.16.840.1.101.3.4.2.3");
				} else if (signAlgorithm.equals("NONEwithRSA")) {
					em = padWithPKCS1v15(hash, ((SmartCardHSMKey)privateKey).getKeySize());
					return signData(privateKey, "NONEwithRSA", "NONE", em);
				} else {
					throw new CardServiceOperationFailedException("There is no matching algorithm.");
				}
				try {
					byte[] digestInfo = buildDigestInfo(oid, hash);
					em = padWithPKCS1v15(digestInfo, ((SmartCardHSMKey)privateKey).getKeySize());
					return signData(privateKey, "NONEwithRSA", "NONE", em);
				} catch (TLVEncodingException e) {
					log.error("signHash", e);
				}

			}
			else {
				throw new CardServiceOperationFailedException("Algorithm and key don't match.");
			}
		} else if (padAlgorithm.equals("PKCS1_PSS")) {
			if (privateKey instanceof SmartCardHSMKey) {
				String id = "";
				MessageDigest md = null;
				if (signAlgorithm.equals("SHA1withRSA")) {
					id = "SHA1";
				} else if (signAlgorithm.equals("SHA256withRSA")) {
					id = "SHA256";
				} else if (signAlgorithm.equals("SHA384withRSA")) {
					id = "SHA384";
				} else if (signAlgorithm.equals("SHA512withRSA")) {
					id = "SHA512";

					/*
					 * EMSA-PSS encoding will not work for this combination
					 *
					 * The key must be at least 8*hLen + 8*sLen + 9 bits long.
					 *
					 * This fails for SHA-512 and RSA-1024: 8*64 + 8*64 + 9 = 1033 bits
					 */
					if (((SmartCardHSMKey) privateKey).getKeySize() < 1033) {
						throw new CardServiceOperationFailedException("Key size too small for specified hash algorithm.");
					}

				} else {
					throw new CardServiceOperationFailedException("There is no matching algorithm.");
				}

				if (this.state.getVersion() >= 0x0200 && (id.equals("SHA1") || id.equals("SHA256"))) { // Padding is done by the SmartCard-HSM
					return signData(privateKey, "NONEwithRSA", "PKCS1_PSS", hash);
				} else { // External padding
					try {
						md = MessageDigest.getInstance(id);
					} catch (NoSuchAlgorithmException e) {
						throw new CardServiceOperationFailedException("Unable to get instance of message digest : " + e.getLocalizedMessage());
					}

					EMSAPSSEncoder encoder = new EMSAPSSEncoder(md, ((SmartCardHSMKey) privateKey).getKeySize());

					byte[] pssblock = null;

					try {
						pssblock = encoder.encode(hash);
					} catch (IOException e) {
						throw new CardServiceOperationFailedException("Unable to create PSS encoding : " + e.getLocalizedMessage());
					}

					return signData(privateKey, "NONEwithRSA", "NONE", pssblock);
				}
			} else {
				throw new CardServiceOperationFailedException("Algorithm and key don't match.");
			}


		} else if (padAlgorithm.equals("NONE")) {
			if (signAlgorithm.equals("NONEwithECDSA")) {
				if (privateKey instanceof SmartCardHSMKey) {
					hash = verifyHashLength(((SmartCardHSMKey) privateKey).getKeySize(), hash);
					return signData(privateKey, "NONEwithECDSA", "NONE", hash);
				}
				else {
					throw new CardServiceOperationFailedException("Alogrithm and key don't match.");
				}
			} else {
				throw new CardServiceOperationFailedException("There is no matching algorithm.");
			}


		} else {
			throw new CardServiceOperationFailedException("There is no matching algorithm.");
		}

		return null;
	}



	/*
	 * This helper method verifies that the hash length matches the length
	 * of the key order.
	 *
	 * The hash will be filled up with leading zeros if it is too short
	 * or it will be shortened MSB first if it is too long.
	 */
	private byte[] verifyHashLength(int keySize, byte[] hash) {
		int length = keySize / 8;
		byte[] paddedHash = new byte[length];
		if (hash.length == length) {
			// Valid hash
			return hash;
		} else if (hash.length < length) {
			// Hash too short. Fill up hash with leading 0
			System.arraycopy(hash, 0, paddedHash, paddedHash.length - hash.length, hash.length);
			return paddedHash;
		} else {
			// Hash too long. Shorten hash to key order length - MSB first
			System.arraycopy(hash, 0, paddedHash, 0, paddedHash.length);
			return paddedHash;
		}
	}



	/*
	 * Helper to encode the hash according to EMSA-PKCS1-v1_5
	 */
	private byte[] buildDigestInfo(ObjectIdentifier oid, byte[] hash) throws TLVEncodingException {

		//build the digest info
		ConstructedTLV digestInfo = new ConstructedTLV(0x30);

		ConstructedTLV algorithmID = new ConstructedTLV(0x30);
		algorithmID.add(oid);
		algorithmID.add(new PrimitiveTLV(Tag.NULL, null));

		PrimitiveTLV digest = new PrimitiveTLV(Tag.OCTET_STRING, hash);

		digestInfo.add(algorithmID);
		digestInfo.add(digest);
		byte[] t = digestInfo.getBytes();

		return t;
	}



	private byte[] padWithPKCS1v15(byte[] t, int keySize) throws CardServiceOperationFailedException {

		int emLen = keySize / 8;
		if (emLen < t.length + 11) {
			throw new CardServiceOperationFailedException("Intended encoded message length too short.");
		}

		/* pad t into em
		   em = 0x00 || 0x01 || ps || 0<00 || t */
		byte[] em = new byte[emLen];
		em[0] = 0x00;
		em[1] = 0x01;

		int psLen = emLen - t.length - 3;
		int j = 2;
		for (int i = 0; i < psLen; i++, j++) {
			em[j] = (byte)0xFF;
		}
		em[j] = 0x0;

		System.arraycopy(t, 0, em, j + 1, t.length);
		return em;
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public boolean verifySignedData(PublicKeyRef publicKey,
			String signAlgorithm, byte[] data, byte[] signature)
					throws CardServiceException, InvalidKeyException,
					CardTerminalException {
		throw new CardServiceInabilityException
		("verifySignedData(PublicKeyRef publicKey, String signAlgorithm, byte[] data, byte[] signature)");
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public boolean verifySignedData(PublicKeyRef publicKey,
			String signAlgorithm, String padAlgorithm, byte[] data,
			byte[] signature) throws CardServiceException, InvalidKeyException,
			CardTerminalException {
		throw new CardServiceInabilityException
		("verifySignedData(PublicKeyRef publicKey, String signAlgorithm, String padAlgorithm, byte[] data, byte[] signature)");
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public boolean verifySignedHash(PublicKeyRef publicKey,
			String signAlgorithm, byte[] hash, byte[] signature)
					throws CardServiceException, InvalidKeyException,
					CardTerminalException {
		throw new CardServiceInabilityException
		("verifySignedHash(PublicKeyRef publicKey, String signAlgorithm, byte[] hash, byte[] signature)");
	}



	/**
	 * Not implemented
	 *
	 * @deprecated
	 */
	@Override
	public boolean verifySignedHash(PublicKeyRef publicKey,
			String signAlgorithm, String padAlgorithm, byte[] hash,
			byte[] signature) throws CardServiceException, InvalidKeyException,
			CardTerminalException {
		throw new CardServiceInabilityException
		("verifySignedHash(PublicKeyRef publicKey, String signAlgorithm, String padAlgorithm, byte[] hash, byte[] signature)");
	}



	/**
	 * Enumerate all currently used file and key identifier.
	 *
	 * @return Even number of bytes that compose a list of 16 bit file identifier
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public byte[] enumerateObjects() throws CardTerminalException, CardServiceException {
		CommandAPDU com = new CommandAPDU(7);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_ENUM_OBJECTS);
		//P1
		com.append((byte)0x00);
		//P2
		com.append((byte)0x00);
		//Three byte Le for extended length APDU
		com.append((byte)0x00);
		com.append((byte)0x00);
		com.append((byte)0x00);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("ENUMERATE OBJECTS" ,rsp.sw());
		}
		return rsp.data();
	}



	/**
	 * Request random byte values generated by the build in random number generator.
	 *
	 * @param length
	 * @return Random bytes
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public byte[] generateRandom(int length) throws CardTerminalException, CardServiceException {
		CommandAPDU com = new CommandAPDU(7);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_GET_CHALLENGE);
		//P1
		com.append((byte)0x00);
		//P2
		com.append((byte)0x00);
		//Three byte Le for extended length APDU
		com.append((byte)0x00);
		com.append((byte)(length >> 8));
		com.append((byte)length);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("GET CHALLENGE" ,rsp.sw());
		}
		return rsp.data();
	}



	/**
	 * The device decrypts using the private key a cryptogram
	 * enciphered with the public key and returns the plain value.
	 *
	 * @param privateKey the private SmartCardHSMKey
	 * @param cryptogram
	 * @return the plain value
	 */
	@Override
	public byte[] decipher(SmartCardHSMKey privateKey, byte[] cryptogram, byte algorithmID) throws CardTerminalException, CardServiceException {

		CommandAPDU com = new CommandAPDU(530);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_DECIPHER);
		//P1: Key Id
		com.append((byte)privateKey.getKeyRef());
		//P2: Alg Id
		com.append(algorithmID);
		//Lc
		com.append((byte)0x00);
		com.append((byte)(cryptogram.length >> 8));
		com.append((byte)cryptogram.length);
		com.append(cryptogram);
		//Le
		com.append((byte)0x00);
		com.append((byte)0x00);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			rsp.clear();
			throw new CardServiceUnexpectedStatusWordException("DECIPHER" ,rsp.sw());
		}
		byte[] data = rsp.data();
		rsp.clear();
		return data;
	}



	/**
	 * The device decrypts using the private key a cryptogram
	 * enciphered with the public key and returns the plain value.
	 *
	 * @param privateKey the private SmartCardHSMKey
	 * @param cryptogram
	 * @return the plain value
	 */
	@Override
	public byte[] decipher(SmartCardHSMKey privateKey, byte[] cryptogram) throws CardTerminalException, CardServiceException {

		return decipher(privateKey, cryptogram, DecipherCardService.RSA_DECRYPTION_PLAIN);
	}



	/**
	 * The device calculates a shared secret point using an EC Diffie-Hellman
	 * operation. The public key of the sender must be provided as input to the command.
	 * The device returns the resulting point on the curve associated with the private key.
	 *
	 * @param privateKey Key identifier of the SmartCardHSM private key
	 * @param pkComponents Concatenation of '04' || x || y point coordinates of ECC public Key
	 * @return Concatenation of '04' || x || y point coordinates on EC curve
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	@Override
	public byte[] performECCDH(SmartCardHSMKey privateKey, byte[] pkComponents)
			throws CardServiceException, CardTerminalException {

		CommandAPDU com = new CommandAPDU(200);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_DECIPHER);
		//P1: Key Id
		com.append((byte)privateKey.getKeyRef());
		//P2: Alg Id
		com.append(ECDH);
		//Lc
		com.append((byte)0x00);
		com.append((byte)(pkComponents.length >> 8));
		com.append((byte)pkComponents.length);
		com.append(pkComponents);
		//Le
		com.append((byte)0x00);
		com.append((byte)0x00);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			rsp.clear();
			throw new CardServiceUnexpectedStatusWordException("PERFORM ECCDH" ,rsp.sw());
		}
		byte[] data = rsp.data();
		rsp.clear();
		return data;
	}



	/**
	 * Present a card verifiable certificate in order to establish a trusted public key in the device.
	 *
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 */
	public void verifyCertificate(CardVerifiableCertificate cvc) throws CardTerminalException, CardServiceException {
		byte[] certificateBody = cvc.getBody();
		byte[] certificateSignature = cvc.getSignature();
		int length = certificateBody.length + certificateSignature.length;
		CommandAPDU com = new CommandAPDU(9 + length);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_PSO);
		com.append((byte)0x00);							// P1
		com.append((byte)0xBE);							// P2
		if (length > 0xFF) {
			com.append((byte)0x00);						// Three byte Lc
			com.append((byte)(length >> 8));
			com.append((byte)length);
			//com.append((byte)0x00);					// Two byte Le
			//com.append((byte)0x00);
		} else {
			com.append((byte)length);					// One byte Lc
			//com.append((byte)0x00);					// One byte Le
		}
		com.append(certificateBody);					// C-Data
		com.append(certificateSignature);				// C-Data

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("VERIFY CERTIFICATE" ,rsp.sw());
		}
	}



	/**
	 * Manage Security Environment APDU for Certificate and Public Key Verification
	 *
	 * @param chr
	 * @throws OpenCardException
	 */
	public boolean selectPubKeyForSignature(byte[] chr) throws OpenCardException {
		PrimitiveTLV tlv = new PrimitiveTLV(new Tag(0x03, Tag.CONTEXT, false), chr);
		byte[] cdata = tlv.getBytes();

		byte p1 = (IsoConstants.UQ_VER_ENC_EXTAUT |	IsoConstants.P1_MSE_SET);	// SET for Verification, Encryption and External Authentication
		byte p2 = (IsoConstants.CRT_DST);	// CRT for digital signature

		return manageSE(p1, p2, cdata);
	}



	/**
	 * Ensure that the issuer of the certificate or request in chain[0] is validated.
	 * The issuer public key is selected as result of performing chain validation
	 *
	 * @param chain the list of authenticated public key (CSR), device certificate and device issuer CA certificate
	 * @throws OpenCardException
	 */
	public void verifyCertificateChain(CardVerifiableCertificate[] chain) throws OpenCardException {

		int i = 0;
		byte[] car = chain[i].getOuterCAR();
		while (!selectPubKeyForSignature(car) && (i < chain.length - 1)) {
			i++;
			car = chain[i].getCAR();
		}
		while (i > 0) {
			verifyCertificate(chain[i]);
			byte[] chr = chain[i].getCHR();
			if (!selectPubKeyForSignature(chr)) {
				throw new CardServiceException("Invalid certificate chain: CAR not found");
			}
			i--;
		}
	}



	/**
	 * Manage Security Environment APDU for External Authenticate
	 *
	 * @param chr
	 * @throws TLVEncodingException
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public boolean selectPubKeyForAuthentication(byte[] chr) throws CardTerminalException, CardServiceException {
		PrimitiveTLV tlv = new PrimitiveTLV(new Tag(0x03, Tag.CONTEXT, false), chr);
		byte[] cdata = tlv.getBytes();

		byte p1 = (IsoConstants.UQ_VER_ENC_EXTAUT |	IsoConstants.P1_MSE_SET);	// SET for Verification, Encryption and External Authentication
		byte p2 = (IsoConstants.CRT_AT);	// CRT for authentication

		return manageSE(p1, p2, cdata);
	}



	/**
	 * Select algorithms and keys for security operations.
	 *
	 * @param data
	 * @throws InvalidCardChannelException
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public boolean manageSE(byte p1, byte p2, byte[] cdata) throws CardTerminalException, CardServiceException {

		CommandAPDU com = new CommandAPDU(100);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_MANAGE_SE);
		com.append(p1);
		com.append(p2);
		com.append((byte)cdata.length);
		com.append(cdata);

		rsp = sendCommandAPDU(com);

		if ((rsp.sw() != IsoConstants.RC_OK) && (rsp.sw() != IsoConstants.RC_RDNOTFOUND)) {
			throw new CardServiceUnexpectedStatusWordException("MANAGE SE" ,rsp.sw());
		}

		return rsp.sw() == IsoConstants.RC_OK;
	}




	/**
	 * Select algorithms and keys for security operations.
	 *
	 * @param data
	 * @throws InvalidCardChannelException
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public void manageSE(byte[] data) throws CardTerminalException, CardServiceException {

		CommandAPDU com = new CommandAPDU(100);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_MANAGE_SE);
		com.append((byte)(IsoConstants.UQ_COM_DEC_INTAUT |	IsoConstants.P1_MSE_SET));	// SET for computation, verification, decipherment and key agreement
		com.append(IsoConstants.CRT_AT);	// CRT for authentication
		com.append((byte)0x0C);
		com.append(data);

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("MANAGE SE" ,rsp.sw());
		}
	}



	/**
	 * Derive XKEK usingt the exchange key referenced by keyId and the peer public key
	 *
	 * The device certificate for validating the public key must have been selected
	 * with verifyCertificateChain() before.
	 *
	 * @param keyId the key id of the EC exchange private key
	 * @param puk the public key of the peer
	 * @return
	 * @throws OpenCardException
	 */
	public void deriveXKEK(byte keyId, CardVerifiableCertificate puk) throws OpenCardException {
		byte[] cvc = null;
		byte[] ocar = null;
		byte[] osig = null;
		try {
			cvc = puk.getCVC();
			ocar = puk.getOuterCARTLV();
			osig = puk.getOuterSignature();
		} catch (CertificateException e) {
			throw new CardServiceException("The Card Verifiable Certificate is not an Authenticated Certificate Signing Request");
		}
		int length = cvc.length + ocar.length + osig.length;

		ByteBuffer bb = new ByteBuffer(length);
		bb.append(cvc);
		bb.append(ocar);
		bb.append(osig);

		if (length > this.maxCData) {
			write(new CardFilePath(":2F10"), 0, bb.getBytes());
		}

		CommandAPDU com = new CommandAPDU(9 + length);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_DECIPHER);
		com.append(keyId);								// P1
		com.append((byte)0x84);							// P2

		if (length <= this.maxCData) {
			com.append((byte)0x00);						// Three byte Lc
			com.append((byte)(length >> 8));
			com.append((byte)length);
			com.append(bb.getBytes());
			com.append((byte)0x00);						// Two byte Le
			com.append((byte)0x00);
		} else {
			com.append((byte)0x00);						// Le
		}

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("DERIVE XKEK" ,rsp.sw());
		}
	}



	/**
	 * Import public keys for authentication.
	 *
	 * Public keys can only be imported after initialization of the device.
	 * Once the number of different public keys defined in the
	 * INITIALIZE DEVICE command are imported, then further imports are impossible.
	 * Until all public keys are imported, public key authentication is disabled.
	 *
	 * Only ECC keys can be imported as public keys for authentication.
	 * Before importing the key, the public key used to verify the signature
	 * applied to the public key must be selected using the selectPubKeyForSignature method.
	 *
	 * @param cert an Authenticated Certificate Signing Request
	 * @return the import status as returned by the card
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public byte[] importPublicKey(CardVerifiableCertificate cert) throws CardTerminalException, CardServiceException {
		byte[] cvc = null;
		byte[] ocar = null;
		byte[] osig = null;
		try {
			cvc = cert.getCVC();
			ocar = cert.getOuterCARTLV();
			osig = cert.getOuterSignature();
		} catch (CertificateException e) {
			throw new CardServiceException("The Card Verifiable Certificate is not an Authenticated Certificate Signing Request");
		}
		int length = cvc.length + ocar.length + osig.length;

		ByteBuffer bb = new ByteBuffer(length);
		bb.append(cvc);
		bb.append(ocar);
		bb.append(osig);

		if (length > this.maxCData) {
			write(new CardFilePath(":2F10"), 0, bb.getBytes());
		}

		CommandAPDU com = new CommandAPDU(9 + length);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_MANAGE_PKA);
		com.append((byte)0x00);							// P1
		com.append((byte)0x00);							// P2

		if (length <= this.maxCData) {
			com.append((byte)0x00);						// Three byte Lc
			com.append((byte)(length >> 8));
			com.append((byte)length);
			com.append(bb.getBytes());
			com.append((byte)0x00);						// Two byte Le
			com.append((byte)0x00);
		} else {
			com.append((byte)0x00);						// Le
		}

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("MANAGE PKA" ,rsp.sw());
		}
		return rsp.data();
	}



	/**
	 * Public Key Authentication is the mechanism by which an external entity
	 * can use its private key to authenticate. Public key authentication is
	 * an alternative to user authentication using the PIN.
	 * Public key authentication is the basis for n-of-m authentication,
	 * which requires that n of the previously register m public keys have
	 * performed the authentication procedure within the current session.
	 * The external entity needs to obtain an 8 byte challenge, and sign the
	 * concatenation of device id and the challenge.
	 * The device id must be extracted from the CHR field of the device certificate.
	 *
	 * @param signature over the concatenation of the device id and an 8 byte challenge
	 * @return true is authentication successful
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public boolean externalAuthenticate(byte[] signature) throws CardTerminalException, CardServiceException {

		CommandAPDU com = new CommandAPDU(9 + signature.length);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_EXTAUTHENTICATE);
		com.append((byte)0x00);							// P1
		com.append((byte)0x00);							// P2
		com.append((byte)signature.length);				// Lc
		com.append(signature);							// C-Data

		rsp = sendCommandAPDU(com);

		if (rsp.sw() == IsoConstants.RC_OK) {
			return true;
		} else if (rsp.sw() == IsoConstants.RC_AUTHFAILED) {
			return false;
		} else {
			throw new CardServiceUnexpectedStatusWordException("EXTERNAL AUTHENTICATE" ,rsp.sw());
		}

	}



	/**
	 * The GENERAL AUTHENTICATE command allows the terminal to perform an
	 * explicit authentication of the device and
	 * agree secret session keys KS_ENC and KS_MAC for secure messaging.
	 *
	 * @param data the dynamic authentication data template
	 * @return Dynamic Authentication Template
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public byte[] generalAuthenticate(byte[] data) throws CardTerminalException, CardServiceException {

		CommandAPDU com = new CommandAPDU(100);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_ISO);
		com.append(IsoConstants.INS_GENERAL_AUTH1);
		com.append((byte)0x00);			// P1
		com.append((byte)0x00);			// P2
		com.append((byte)data.length);	// Lc
		com.append(data);				// C-Data
		com.append((byte)0x00);			// Le

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("GENERAL AUTHENTICATE" ,rsp.sw());
		}
		return rsp.data();
	}



	/**
	 * Use the secret key referenced in keyId to derive a secret using the algorithm selected
	 * in algo and the derivation parameter in data
	 *
	 * @param keyId the secret key id
	 * @param algo the derivation algorithm
	 * @param data the derivation data
	 * @return
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public byte[] deriveSymmetricKey(byte keyId, byte algo, byte[] data) throws CardTerminalException, CardServiceException {

		CommandAPDU com = new CommandAPDU(100);
		ResponseAPDU rsp;

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_DERIVE_SYMMETRIC_KEY);
		com.append(keyId);				// P1
		com.append(algo);				// P2
		com.append((byte)data.length);	// Lc
		com.append(data);				// C-Data
		com.append((byte)0x00);			// Le

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			throw new CardServiceUnexpectedStatusWordException("DERIVE SYMMETRIC KEY" ,rsp.sw());
		}
		return rsp.data();
	}



	/**
	 * Return a Vector containing all aliases
	 * that are used on the SmartCardHSM.
	 *
	 * @return Vector of aliases
	 * @throws TLVEncodingException
	 * @throws CertificateException
	 * @throws OpenCardException
	 */
	public Vector<String> getAliases() throws OpenCardException, CertificateException, TLVEncodingException {
		if (this.namemap.isEmpty()) {
			enumerateEntries();
		}
		Set<String> set = this.namemap.keySet();
		Vector<String> v = new Vector<String>(set);
		return v;
	}



	/**
	 * Add a new key to the map of keys
	 * @param key the SmartCardHSMKey
	 */
	public void addKeyToMap(SmartCardHSMKey key) {
		String label = key.getLabel();
		byte id = key.getKeyRef();

		SmartCardHSMEntry entry = namemap.get(label);
		if (entry == null) {
			entry = new SmartCardHSMEntry(key);
			namemap.put(label, entry);
		} else {
			entry.setKey(key);
		}

		idmap.put(id, key);
	}



	/**
	 * Add a certificate to the map
	 *
	 * @param cert the certificate
	 * @param isEECertificate true for EE certificates, false for CA certificates
	 * @param id
	 * @param label
	 */
	public void addCertToMap(Certificate cert, boolean isEECertificate, byte id, String label) {
		SmartCardHSMEntry entry = namemap.get(label);
		if (entry == null) {
			entry = new SmartCardHSMEntry(cert, isEECertificate, id);
			namemap.put(label, entry);
		} else {
			entry.setCert(cert, isEECertificate, id);
		}
	}



	/**
	 * Remove an entry both from map and card.
	 *
	 * @param label
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 * @throws CardIOException
	 */
	public void removeEntry(String label) throws CardServiceException, CardTerminalException, CardIOException {
		SmartCardHSMEntry entry = namemap.get(label);

		if (entry == null) throw new CardServiceResourceNotFoundException("Entry " + label + " not found.");

		if (entry.isKeyEntry()) {
			byte keyID = entry.getKey().getKeyRef();

			// Remove private key
			delete(new CardFilePath(new byte[] { KEYPREFIX, keyID } ));

			// Remove public key certificate
			delete(new CardFilePath(new byte[] { PRKDPREFIX, keyID } ));
		}
		if (entry.isCertificateEntry()) {
			byte certID = entry.getId();

			if (entry.isEECertificate()) {
				// Remove EE Certificate
				delete(new CardFilePath(new byte[] { EECERTIFICATEPREFIX, certID } ));
			} else {
				// Remove CA Certificate
				delete(new CardFilePath(new byte[] { CACERTIFICATEPREFIX, certID } ));
				delete(new CardFilePath(new byte[] { CERTDESCRIPTIONPREFIX, certID } ));
			}
			certIDMap.remove(certID);
		}

		idmap.remove(entry.getId());
		namemap.remove(label);
	}



	public void renameEntry(String oldlabel, String newlabel) throws CardServiceResourceNotFoundException {
		SmartCardHSMEntry entry = namemap.get(oldlabel);

		if (entry == null) throw new CardServiceResourceNotFoundException("Entry " + oldlabel + " not found.");

		namemap.remove(oldlabel);
		namemap.put(newlabel, entry);
	}



	/**
	 * Check if the label exists.
	 *
	 * @param label the key label
	 * @return true if label is available
	 */
	public boolean containsLabel(String label) {
		return namemap.containsKey(label);
	}



	/**
	 * Get a Entry object
	 *
	 * @param label
	 * @return SmartCardHSMEntry
	 */
	public SmartCardHSMEntry getSmartCardHSMEntry(String label) {
		try	{
			if (this.namemap.isEmpty()) {
				enumerateEntries();
			}
		}
		catch(Exception e) {
			log.error("Inconsistent PKCS#15 structure: ", e);
			return null;
		}
		SmartCardHSMEntry entry = namemap.get(label);
		return entry;
	}



	/**
	 * Add a key from device including a certificate
	 *
	 * @param kid the key id
	 * @throws OpenCardException
	 */
	public SmartCardHSMKey addKey(byte kid)  throws OpenCardException {
		CardFilePath file = new CardFilePath(new byte[] { PRKDPREFIX, kid });

		KeyDescription desc = null;
		try	{
			byte[] descbin = read(file, 0, READ_SEVERAL);
			desc = new KeyDescription(descbin);
			desc.setKeyRef(kid);
		}
		catch(Exception e) {
			log.debug("Error reading key description" + e.getMessage());
		}

		SmartCardHSMKey key;
		if (desc == null) {
			key = new SmartCardHSMKey(kid, "(" + kid + ")", (short)0);
		} else {
			switch(desc.getType()) {
				case RSA:
					key = new SmartCardHSMRSAKey(kid, desc.getTranslatedLabel(), (short)desc.getSize());
					break;
				case EC:
					key = new SmartCardHSMECKey(kid, desc.getTranslatedLabel(), (short)desc.getSize());
					break;
				case AES:
					key = new SmartCardHSMSecretKey(kid, desc.getTranslatedLabel(), (short)desc.getSize(), "AES");
					break;
				default:
					throw new IllegalArgumentException("Unknown key type");
			}

		}
		addKeyToMap(key);

		IsoFileControlInformation cfi = (IsoFileControlInformation)getFileInfo(new CardFilePath(new byte[] { KEYPREFIX, kid }));
		byte[] a5 = cfi.getProprietary();
		if (a5 != null) {
			key.processKeyInfo(keyDomains, a5);
		}

		idmap.put(kid, key);
		log.debug("Added key #" + kid + " " + key);

		file = new CardFilePath(new byte[] { EECERTIFICATEPREFIX, kid });
		try	{
			byte[] certBin = read(file, 0, READ_SEVERAL);
			Certificate cert;

			if (certBin[0] == 0x30) {
				ByteArrayInputStream inStream = new ByteArrayInputStream(certBin);
				CertificateFactory cf = null;
				cf = CertificateFactory.getInstance("X.509");
				cert = (X509Certificate)cf.generateCertificate(inStream);
			} else {
				cert = new CardVerifiableCertificate("CVC", certBin);
			}

			if ((key instanceof SmartCardHSMPrivateKey) && (key.getKeySize() == -1)) {
				((SmartCardHSMPrivateKey)key).deriveKeySizeFromPublicKey(cert);
			}
			addCertToMap(cert, true, kid, key.getLabel());
		}
		catch(Exception e) {
			log.debug("Error reading and parsing certificate : " + e.getMessage());
		}

		return key;
	}



	/**
	 * Enumerate SmartCardHSM entries.
	 *
	 * @return the aliases of all SmartCardHSM entries
	 * @throws OpenCardException
	 * @throws TLVEncodingException
	 * @throws CertificateException
	 */
	private void enumerateEntries() throws OpenCardException {
		byte[] fobs = enumerateObjects();
		if (Arrays.equals(fobs, lastobjectlist)) {
			return;
		}

		lastobjectlist = fobs;

		if (keyDomains == null) {
			enumerateKeyDomains();
		}

		byte kid;

		if (this.addDeviceCertificateToAliases) {
			// 	Add Device Authentication Certificate
			try {
				byte[] certBin = read(new CardFilePath(":2F02"), 0, READ_SEVERAL);
				CardVerifiableCertificate cert = new CardVerifiableCertificate("CVC", certBin);
				addCertToMap(cert, true, (byte) 0x00, "DeviceAuthenticationCertificate");
				int cvcofs = cert.getCVC().length;
				int cvclen = certBin.length - cvcofs;
				if (cvclen > 0) {
					byte[] dicacert = new byte[cvclen];
					System.arraycopy(certBin, cvcofs, dicacert, 0, cvclen);
					cert = new CardVerifiableCertificate("CVC", dicacert);
					addCertToMap(cert, false, (byte) 0x00, "DeviceIssuerCertificate");
				}
			} catch (CardServiceUnexpectedStatusWordException | CertificateException e) {
				log.error("Decode DevAut certificates", e);
				throw new CardServiceException("Decoding device certificate failed: " + e.getMessage());
			}
		}

		// Process keys
		for (int i = 0; i < fobs.length; i += 2) {
			if (fobs[i] == KEYPREFIX) {
				if (fobs[i + 1] == 0) {
					continue;			// Skip PrK.DevAut
				}
				kid = fobs[i + 1];
				addKey(kid);
			}
		}

		// Add CA certificates to the name map
		for (int i = 0; i < fobs.length; i += 2) {
			if (fobs[i] == CACERTIFICATEPREFIX) {
				byte id = fobs[i + 1];
				caid.add(id);
				CardFilePath file = new CardFilePath(new byte[] { CACERTIFICATEPREFIX, id });
				byte[] certBin = read(file, 0, READ_SEVERAL);
				try {
					ByteArrayInputStream inStream = new ByteArrayInputStream(certBin);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
					inStream.close();

					// The label will be obtained in later step

					certIDMap.put(id, cert);
				} catch (Exception e) {
					log.error("Parsing certificate", e);
				}
			}
		}

		// Find the corresponding label to the CA certificate and add it to the name map
		for (int i = 0; i < fobs.length; i += 2) {
			if (fobs[i] == CERTDESCRIPTIONPREFIX) {
				byte id = fobs[i + 1];
				CardFilePath file = new CardFilePath(new byte[] { CERTDESCRIPTIONPREFIX, id });
				byte[] encLabel = read(file, 0, READ_SEVERAL);
				CertificateDescription cd = new CertificateDescription();
				String label = "not found";
				try	{
					label = cd.getLabel(encLabel);
				}
				catch(TLVEncodingException e) {
					log.error("Error parsing certificate description", e);
				}

				Certificate cert = certIDMap.get(id);
				if (cert == null) {
					throw new CardServiceException("No corresponding CA certificate for this certificate description found");
				}
				addCertToMap(cert, false, id, label);
			}
		}
	}



	/**
	 * Determine an unused CA identifier
	 *
	 * @return a free CA identifier or -1 if all identifier in use
	 * @throws TLVEncodingException
	 * @throws CertificateException
	 * @throws OpenCardException
	 */
	public byte determineFreeCAId () throws OpenCardException {
		if (this.namemap.isEmpty()) {
			enumerateEntries();
		}

		if (caid.isEmpty()) {
			return 0;
		} else {
			byte id = (byte) (caid.lastElement() + 1);
			if (id > 0xFF) {
				return -1;
			} else {
				return id;
			}
		}
	}



	/**
	 * Determine an unused key identifier
	 *
	 * @return a free key identifier or -1 if all key identifier in use
	 */
	public byte determineFreeKeyId () throws OpenCardException {
		if (this.namemap.isEmpty()) {
			enumerateEntries();
		}

		for (int i = 1; i < KEY_CAPACITY; i++) {
			if (idmap.get((byte)i) == null) {
				return (byte)i;
			}
		}
		return -1;
	}



	/**
	 * Store the private key description on the card
	 *
	 * @throws CardIOException
	 * @throws CardTerminalException
	 * @throws CardServiceException
	 */
	public void storePRKD(byte kid, KeyDescription prkd) throws CardServiceException, CardTerminalException, CardIOException {
		write(new CardFilePath(new byte[] { (byte)0xC4, kid }), 0, prkd.getEncoded());
	}



	private void enumerateKeyDomains() throws OpenCardException {
		if (keyDomains == null) {
			keyDomains = new ArrayList<KeyDomain>();
		}

		byte kid = 0;

		ResponseAPDU rsp;
		while (true) {
			CommandAPDU com = new CommandAPDU(5);

			com.append(IsoConstants.CLA_HSM);
			com.append(IsoConstants.INS_MANAGE_KEY_DOMAIN);
			com.append((byte)0x00);			// P1
			com.append(kid);				// P2
			com.append((byte)0x00);			// Le

			rsp = sendCommandAPDU(com);

			if (rsp.sw() == IsoConstants.RC_INCP1P2 || rsp.sw1() == IsoConstants.RC_INVINS) {
				return;
			}

			KeyDomain kd;
			if (kid >= keyDomains.size()) {
				kd = new KeyDomain(kid);
			} else {
				kd = keyDomains.get(kid);
			}
			kd.update(rsp.data());
			if (kid >= keyDomains.size()) {
				keyDomains.add(kd);
			}
			kid++;
		}
	}



	public List<KeyDomain> getKeyDomains() throws OpenCardException {
		enumerateKeyDomains();
		return keyDomains;
	}



	public boolean deleteKeyDomain(KeyDomain kd)  throws OpenCardException {
		ResponseAPDU rsp;
		CommandAPDU com = new CommandAPDU(5);

		com.append(IsoConstants.CLA_HSM);
		com.append(IsoConstants.INS_MANAGE_KEY_DOMAIN);
		com.append((byte)0x03);			// P1
		com.append(kd.getId());			// P2
		com.append((byte)0x00);			// Le

		rsp = sendCommandAPDU(com);

		if (rsp.sw() != IsoConstants.RC_OK) {
			return false;
		}

		kd.update(rsp.data());
		return true;
	}



	private CardChannel getChannel() {
		this.allocateCardChannel();
		return this.getCardChannel();
	}



	@Override
	public ResponseAPDU sendCommandAPDU(CardFilePath path, CommandAPDU com,
			int usageQualifier) throws CardServiceException,
			CardTerminalException {
		ResponseAPDU rsp;

		rsp = sendCommandAPDU(com);

		return rsp;
	}



	/**
	 * Return the Device Authentication Certificate Chain
	 * as CardVerifiableCertificate array.
	 * <ul>
	 * 	<li>At position 0 there is the DevAutCertifiacte</li>
	 * 	<li>At position 1 there is the IssuerCertifiacte if it exits.
	 * 		Otherwise the array has a length of 1</li>
	 * </ul>
	 *
	 * @return CardVerifiableCertificate[]
	 * @throws CardServiceException
	 * @throws CardTerminalException
	 * @throws CardIOException
	 * @throws TLVEncodingException
	 * @throws CertificateException
	 */
	private CardVerifiableCertificate[] getCertificateChain() throws CardServiceException, CardTerminalException {
		CardVerifiableCertificate[] certs;
		byte[] devAutEnc;
		CardVerifiableCertificate devAutCert;
		CardVerifiableCertificate issuerCert;

		// Read certificate(s)
		byte[] certBytes = read(new CardFilePath(":2F02"), 0, READ_SEVERAL);

		try {
			devAutEnc = new ConstructedTLV(certBytes).getBytes();
		} catch (TLVEncodingException e) {
			log.error("Parsing CVC", e);
			throw new CardServiceException("Unexptected TLV encoding error");
		}

		try {
			devAutCert = new CardVerifiableCertificate("CVC", devAutEnc);
		} catch (CertificateException e) {
			log.error("Parsing CVC", e);
			throw new CardServiceException("Unexptected CardVerifiableCertificate error");
		}

		if (devAutEnc.length == certBytes.length){
			// Only the Device Authentication Certificate is stored on the card
			certs = new CardVerifiableCertificate[1];
			certs[0] = devAutCert;
		} else {
			// The Device Authentication Certificate and
			// the Issuer Certificate are read
			certs = new CardVerifiableCertificate[2];
			certs[0] = devAutCert;

			// The Issuer Cert starts directly after the DevAutCert
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			bos.write(certBytes, devAutEnc.length, certBytes.length - devAutEnc.length);

			try {
				issuerCert = new CardVerifiableCertificate("CVC", bos.toByteArray());
			} catch (CertificateException e) {
				log.error("Parsing CVC", e);
				throw new CardServiceException("Unexpected CardVerifiableCertificate error");
			}
			certs[1] = issuerCert;
		}
		return certs;
	}



	public ECPublicKey getDevAutPK() throws CardServiceException, CardTerminalException {

		CardVerifiableCertificate[] certs = getCertificateChain();

		if (certs.length == 1) {
			// Read Issuer Certificate
			ByteArrayInputStream bis = new ByteArrayInputStream(issuerCert);

			PublicKey issuerPK;
			try {
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				issuerPK = cf.generateCertificate(bis).getPublicKey();
			} catch (Exception e) {
				log.error("Parsing issuer certificate", e);
				throw new CardServiceException("Unexpected CertificateException");
			}


			// Verify Device Authentication Certificate
			try {
				certs[0].verify(issuerPK);
			} catch (CertificateException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("The Device Authentication Certificate isn't valid.");
			} catch (InvalidKeyException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected InvalidKeyException");
			} catch (NoSuchAlgorithmException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected NoSuchAlgorithmException");
			} catch (NoSuchProviderException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected NoSuchProviderException");
			} catch (SignatureException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected SignatureException");
			}
			return (ECPublicKey)certs[0].getPublicKey();
		} else {
			// Find matching authority reference for the Device Authentication Certificate
			byte[] car = certs[1].getCAR();
			CardVerifiableCertificate rootCVC;
			if (java.util.Arrays.equals(car, ROOT_CA)) {
				try {
					rootCVC = new CardVerifiableCertificate("CVC", rootCert);
				} catch (CertificateException e) {
					log.error("Verify certificate", e);
					throw new CardServiceException("Unexpected CertificateException");
				}
			} else if (java.util.Arrays.equals(car, UT_CA)){
				try {
					rootCVC = new CardVerifiableCertificate("CVC", utCert);
				} catch (CertificateException e) {
					log.error("Verify certificate", e);
					throw new CardServiceException("Unexpected CertificateException");
				}
			} else {
				throw new CardServiceException("No matching authority reference found for Device Authentication Certificate");
			}

			// Get domain parameter from Root CA
			byte[] domainParam = rootCVC.getDomainParameter();

			PublicKey rootPK = rootCVC.getPublicKey();

			try {
				// Verify Root Certificate
				rootCVC.verify(rootPK);

				// Verify Issuer Certificate
				certs[1].verify(rootPK);

				// Verify Device Authentication Certificate
				certs[0].verify(certs[1].getPublicKey(domainParam));


				id = 	"/" + new PublicKeyReference(rootCVC.getCHR()).getHolder() +
						"/" + new PublicKeyReference(certs[1].getCHR()).getHolder() +
						"/" + new PublicKeyReference(certs[0].getCHR()).getHolder();

			} catch (CertificateException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("The Device Authentication Certificate isn't valid.");
			} catch (InvalidKeyException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected InvalidKeyException");
			} catch (NoSuchAlgorithmException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected NoSuchAlgorithmException");
			} catch (NoSuchProviderException e) {
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected NoSuchProviderException");
			} catch (SignatureException e) {
				e.printStackTrace();
				log.error("Verify certificate", e);
				throw new CardServiceException("Unexpected SignatureException");
			}
			return (ECPublicKey)certs[0].getPublicKey(domainParam);
		}
	}



	public ChangeReferenceDataDialog getChangeReferenceDataDialog() {
		return this.changeRefenceDataDialog;
	}



	public void setChangeReferenceDataDialog(ChangeReferenceDataDialog dialog){
		this.changeRefenceDataDialog = dialog;
	}



	@Override
	public void update(String url, String sessionId, RemoteNotificationListener notificationListener)
			throws CardServiceException {

		boolean smactive = this.state.getSecureChannelCredential() != null;

		remoteClient = new RemoteClient(this, url, sessionId);
		remoteClient.update(notificationListener);
		remoteClient = null;

		if (smactive) {
			try	{
				initSecureMessaging();
			} catch(CardTerminalException cte) {
				throw new CardServiceException("Could not reestablish secure channel");
			}
		}
	}



	@Override
	public void cancel() {
		if (remoteClient != null) {
			remoteClient.cancel();
			remoteClient = null;
		}
	}
}
