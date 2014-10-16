package ch.zhaw.slcrypt.encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ch.zhaw.slcrypt.SessionKey;
import ch.zhaw.slcrypt.FileHeader;

/**
 * A concrete implementation of the abstract class HybridEncryption that uses
 * AES-128-CBC with PKCS5 Padding, RSA and X.509 certificates. For the MAC, 
 * HMAC-SHA1 is used.
 */
public class HybridEncryptionImpl extends HybridEncryption {

	/**
	 * Create the HMAC (HMAC-SHA1) over a document.
	 * 
	 * @param document
	 *            The document to encrypt
	 * @param passwordMAC
	 *            The password to use for the MAC
	 * @return An InputStream representing the document and the MAC
	 */
	@Override
	protected InputStream generateMAC(InputStream document, byte[] passwordMAC) {
		ByteArrayOutputStream documentBackup = new ByteArrayOutputStream();
		InputStream documentMac = null;
		byte[] macBytes = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			SecretKey key = new SecretKeySpec(passwordMAC, "HmacSHA1");
			mac.init(key);
			int read = -1;
			while(-1 != (read = document.read())) {
				byte readByte = (byte) read;
				documentBackup.write(readByte);
				mac.update(readByte);
			}
			macBytes = mac.doFinal();
		} catch (NoSuchAlgorithmException | InvalidKeyException | IllegalStateException | IOException e) {
			e.printStackTrace();
		}
		documentMac = new SequenceInputStream(new ByteArrayInputStream(macBytes), new ByteArrayInputStream(documentBackup.toByteArray()));
		return documentMac;
	}

	/**
	 * Create a new session key (and possibly iv).
	 * 
	 * @return The new session key
	 */
	@Override
	protected SessionKey generateSessionKey() {
		SessionKey sessionKey = null;
		try {
			byte[] randomBytes = new byte[16];
			SecureRandom secureRandom = new SecureRandom();
			secureRandom.nextBytes(randomBytes);
			sessionKey = new SessionKey();
			sessionKey.setTransformationName("AES/CBC/PKCS5PADDING".getBytes());
			sessionKey.setIV(randomBytes);
			KeyGenerator keyGen;
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey key = keyGen.generateKey();
			sessionKey.setKey(key.getEncoded());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return sessionKey;
	}

	/**
	 * Encrypts a document.
	 * 
	 * @param documentMAC
	 *            The document (including the MAC) to encrypt
	 * @param sessionKey
	 *            The symmetric session key to use
	 * @return An InputStream representing the encrypted document
	 */
	@Override
	protected InputStream encryptDocumentMAC(InputStream documentMAC, SessionKey sessionKey) {
		final String transformationName = new String(sessionKey.getTransformationName());
		InputStream encryptedDocumentMac = null;
		try {
			AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("AES");
			algorithmParameters.init(new IvParameterSpec(sessionKey.getIV()));
			SecretKey secretKey = new SecretKeySpec(sessionKey.getKey(), "AES");
			Cipher cipher = Cipher.getInstance(transformationName);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameters);
			System.out.println("Going to use Cipher [" + transformationName + "]");
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			int read = -1;
			while(-1 != (read = documentMAC.read())) {
				byte readByte = (byte) read;
				byteArrayOutputStream.write(readByte);
			}
			byte[] encMessage = cipher.doFinal(byteArrayOutputStream.toByteArray());
			encryptedDocumentMac = new ByteArrayInputStream(encMessage);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidParameterSpecException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IOException e) {
			e.printStackTrace();
		}
		
		return encryptedDocumentMac;
	}

	/**
	 * Encrypts a session key.
	 * 
	 * @param sessionKey
	 *            The session key to encrypt
	 * @param certificate
	 *            The certificate of which public key is used for the encryption
	 * @return The encrypted session key
	 */
	@Override
	protected byte[] encryptSessionKey(SessionKey sessionKey, InputStream certificate) {
		final byte[] transformationName = sessionKey.getTransformationName();
		final byte[] iv = sessionKey.getIV();
		final byte[] key = sessionKey.getKey();
		final int totalLength = (transformationName.length + iv.length + key.length) + 3;
		ByteBuffer buffer = ByteBuffer.allocate(totalLength);
		buffer.put((byte) transformationName.length).put(transformationName).put((byte) iv.length).put(iv)
			.put((byte) key.length).put(key);
		byte[] sessionKeyBytes = buffer.array();
		byte[] encrytpedSessionKey = encryptSessionKeyBytes(sessionKeyBytes, certificate);
		return encrytpedSessionKey;
	}

	private byte[] encryptSessionKeyBytes(byte[] sessionKeyBytes, InputStream certFile) {
		byte[] encryptedSessionKey = null;
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			Certificate certificate = certificateFactory.generateCertificate(certFile);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, certificate);
			encryptedSessionKey = cipher.doFinal(sessionKeyBytes);
		} catch (CertificateException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return encryptedSessionKey;
	}

	/**
	 * Generates the encrypted file header.
	 * 
	 * @param encryptedSessionKey
	 *            The encrypted session key
	 * @return The encrypted file header
	 */
	@Override
	protected FileHeader generateFileHeader(byte[] encryptedSessionKey) {
		FileHeader fileHeader = new FileHeader();
		fileHeader.setVersion(0x01);
		fileHeader.setEncryptedSessionKey(encryptedSessionKey);
		return fileHeader;
	}
}
