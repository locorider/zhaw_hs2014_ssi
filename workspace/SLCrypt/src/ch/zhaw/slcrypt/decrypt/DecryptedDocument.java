package ch.zhaw.slcrypt.decrypt;

import java.io.InputStream;

import ch.zhaw.slcrypt.decrypt.HybridDecryption.MACState;

/**
 * The DecryptedDocument serves to hold various information about decrypted
 * documents for informational reasons.
 */
public class DecryptedDocument {
	private InputStream document;
	private byte[] sessionKey;
	private byte[] iv;
	private String cipherName;
	private int fileVersion;
	private MACState macState;
	private byte[] macDoc;
	private byte[] macComp;

	public String getCipherName() {
		return cipherName;
	}

	public void setCipherName(String cipherName) {
		this.cipherName = cipherName;
	}

	public InputStream getDocument() {
		return document;
	}

	public void setDocument(InputStream document) {
		this.document = document;
	}

	public int getFileVersion() {
		return fileVersion;
	}

	public void setFileVersion(int version) {
		this.fileVersion = version;
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

	public byte[] getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(byte[] sessionKey) {
		this.sessionKey = sessionKey;
	}

	public MACState getMacState() {
		return macState;
	}

	public void setMacState(MACState macState) {
		this.macState = macState;
	}
	
	public byte[] getMacDoc() {
		return macDoc;
	}

	public void setMacDoc(byte[] macDoc) {
		this.macDoc = macDoc;
	}

	public byte[] getMacComp() {
		return macComp;
	}

	public void setMacComp(byte[] macComp) {
		this.macComp = macComp;
	}


}
