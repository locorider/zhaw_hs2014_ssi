package ch.zhaw.slcrypt.decrypt;

import java.io.InputStream;

import ch.zhaw.slcrypt.FileHeader;
import ch.zhaw.slcrypt.InvalidFormatException;
import ch.zhaw.slcrypt.SessionKey;

/**
 * The abstract HybridDecryption class allows hybrid decryption of a document.
 * It provides implemented functionality to decrypt the document based on a
 * hybrid encrypted document and a private key (both available as InputStreams).
 * It also checks the MAC over the decrypted document. To use the class, a
 * subclass must implement the getFileHeader, getDecryptedSessionKey,
 * decryptDocument, and checkMAC methods.
 */
public abstract class HybridDecryption {

	public enum MACState {
		valid, invalid
	}

	/**
	 * Decrypts an encrypted document that is available from an InputStream.
	 * 
	 * @param encryptedDocument
	 *            The document to decrypt
	 * @param privateKey
	 *            The private key corresponding to the public key that was used
	 *            to encrypt the document
	 * @param macPassword
	 *            The password to use for the MAC
	 * @return The decrypted document
	 */
	public DecryptedDocument decryptDocumentStream(
			InputStream encryptedDocument, InputStream privateKey,
			byte[] macPassword) throws InvalidFormatException {
		DecryptedDocument decryptedDocument;

		// get the file header
		FileHeader header = getFileHeader(encryptedDocument);

		// get the session key from the file header and decrypt it
		SessionKey sessionKey = getDecryptedSessionKey(header, privateKey);

		// decrypt the document with the symmetric key
		InputStream decryptedStream = decryptDocument(encryptedDocument,
				sessionKey);

		// check the HMAC
		decryptedDocument = checkMAC(decryptedStream, macPassword);

		// create a decryptedDocument object and set the fields
		decryptedDocument.setCipherName(new String(sessionKey
				.getTransformationName()));
		decryptedDocument.setIv(sessionKey.getIV());
		decryptedDocument.setSessionKey(sessionKey.getKey());
		decryptedDocument.setFileVersion(header.getVersion());
		return decryptedDocument;
	}

	/**
	 * Gets the file header.
	 * 
	 * @param encryptedDocument
	 *            The encrypted document, including the file header
	 * @return The file header
	 */
	protected abstract FileHeader getFileHeader(InputStream encryptedDocument)
			throws InvalidFormatException;

	/**
	 * Gets the decrypted session key.
	 * 
	 * @param fileHeader
	 *            The file header
	 * @param privateKey
	 *            The private key to decrypt the session key
	 * @return The decrypted session key
	 */
	protected abstract SessionKey getDecryptedSessionKey(FileHeader fileHeader,
			InputStream privateKey) throws InvalidFormatException;

	/**
	 * Decrypts the document.
	 * 
	 * @param encryptedDocument
	 *            The document to decrypt
	 * @param sessionKey
	 *            The session key to decrypt the document
	 * @return The decrypted document
	 */
	protected abstract InputStream decryptDocument(
			InputStream encryptedDocument, SessionKey sessionKey)
			throws InvalidFormatException;

	/**
	 * Check the MAC (HMAC-SHA1) over a document.
	 * 
	 * @param documentMAC
	 *            The document and the MAC concatenated
	 * @param macPassword
	 *            The password to use for the MAC
	 * @return A DecryptedDocument object containing the rsult of the MAC-check
	 *         and the encrypted document
	 */
	public abstract DecryptedDocument checkMAC(InputStream documentMAC,
			byte[] macPassword) throws InvalidFormatException;
}
