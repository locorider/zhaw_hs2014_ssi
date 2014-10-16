package ch.zhaw.slcrypt.encrypt;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.SequenceInputStream;

import ch.zhaw.slcrypt.FileHeader;
import ch.zhaw.slcrypt.SessionKey;

/**
 * The abstract HybridEncryption class allows producing a MAC over a document
 * and subsequent hybrid encryption of the document and the MAC. It provides
 * implemented functionality to generate the encrypted document based on a
 * document and a certificate (both available as InputStreams). To use the
 * class, a subclass must implement the generateMAC, generateSessionKey,
 * encryptDocumentMAC, enryptSessionKey, and generateFileHeader methods.
 */
public abstract class HybridEncryption {

	/**
	 * Encrypts a document that is available from an InputStream.
	 * 
	 * @param document
	 *            The document to encrypt
	 * @param cert
	 *            The certificate of which the public key is used to encrypt the
	 *            document
	 * @param macPassword
	 *            The password to use for the HMAC
	 * @return The encrypted document including the file header. Note: The
	 *         actual encryption is done when the returned stream is read.
	 */
	public InputStream encryptDocumentStream(InputStream document,
			InputStream cert, byte[] macPassword) {

		// Generate the MAC over the document
		InputStream documentMAC = generateMAC(document, macPassword);

		// Generate a new random session key
		SessionKey sessionKey = generateSessionKey();

		// Encrypt the document and MAC with the session key
		InputStream encryptedDocumentMAC = encryptDocumentMAC(documentMAC,
				sessionKey);

		// Encrypt the session key with the public key in the certificate
		byte[] encryptedSessionKey = encryptSessionKey(sessionKey, cert);

		// Generate the file header
		FileHeader fileHeader = generateFileHeader(encryptedSessionKey);
		ByteArrayInputStream fileHeaderStream = new ByteArrayInputStream(
				fileHeader.encode());

		// Return the concatenated streams (file header and
		// encryptedDocumentMAC)
		return new SequenceInputStream(fileHeaderStream, encryptedDocumentMAC);
	}

	/**
	 * Create the MAC (HMAC-SHA1) over a document.
	 * 
	 * @param document
	 *            The document to encrypt
	 * @param macPassword
	 *            The password to use for the MAC
	 * @return An InputStream representing the document and the MAC
	 */
	protected abstract InputStream generateMAC(InputStream document,
			byte[] macPassword);

	/**
	 * Create a new session key (and possibly iv).
	 * 
	 * @return The new session key
	 */
	protected abstract SessionKey generateSessionKey();

	/**
	 * Encrypts a document.
	 * 
	 * @param documentMAC
	 *            The document to encrypt
	 * @param sessionKey
	 *            The symmetric session key to use
	 * @return An InputStream representing the encrypted document
	 */
	protected abstract InputStream encryptDocumentMAC(InputStream documentMAC,
			SessionKey sessionKey);

	/**
	 * Encrypts a session key.
	 * 
	 * @param sessionKey
	 *            The session key to encrypt
	 * @param cert
	 *            The certificate of which public key is used for the encryption
	 * @return The encrypted session key
	 */
	protected abstract byte[] encryptSessionKey(SessionKey sessionKey,
			InputStream cert);

	/**
	 * Generates the encrypted file header.
	 * 
	 * @param encryptedSessionKey
	 *            The encrypted session key
	 * @return The encrypted file header
	 */
	protected abstract FileHeader generateFileHeader(byte[] encryptedSessionKey);
}
