package ch.zhaw.slcrypt.encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
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

		SecretKeySpec sKeySpec2 = new SecretKeySpec(passwordMAC, "HmacSHA1");
		
		Mac m = null;
		try {
			m = Mac.getInstance("HmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			m.init(sKeySpec2);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		ByteArrayOutputStream documentBackup = new ByteArrayOutputStream();
		int len;
		byte[] tmpBuf = new byte[10];
		try {
			while ((len = document.read(tmpBuf, 0, 10)) >= 0) {
				documentBackup.write(tmpBuf, 0, len);
				m.update(tmpBuf);
			}
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] hmac = m.doFinal();

		
		// mac contains the byte-Array with the computed MAC
		return new SequenceInputStream(new ByteArrayInputStream(hmac),
				new ByteArrayInputStream(documentBackup.toByteArray()));

	}

	/**
	 * Create a new session key (and possibly iv).
	 * 
	 * @return The new session key
	 */
	@Override
	protected SessionKey generateSessionKey() {

		SessionKey sk = new SessionKey();
		
		SecureRandom random = null;
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte bytes[] = new byte[16];
		random.nextBytes(bytes);

		byte transformation[] = "AES/CBC/PKCS5Padding".getBytes();
		sk.setTransformationName(transformation);
		sk.setKey(bytes); // 128 Bits
		random.nextBytes(bytes);
		sk.setIV(bytes); // 128 Bits

		
		return sk;
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
	protected InputStream encryptDocumentMAC(InputStream documentMAC,
			SessionKey sessionKey) {
		
		Cipher c1 = null;
		try {
			c1 = Cipher.getInstance("DES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			c1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey.getKey(), "DES"));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		CipherInputStream cis = new CipherInputStream(documentMAC, c1);
		
		return cis;
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
	protected byte[] encryptSessionKey(SessionKey sessionKey,
			InputStream certificate) {

		CertificateFactory cf = null;
		Certificate cert = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			cert = cf.generateCertificate(certificate);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			cipher.init(Cipher.ENCRYPT_MODE, cert);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		byte[] ciphertext = null;
		try {
			ciphertext = cipher.doFinal();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return ciphertext;
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

		FileHeader fh = new FileHeader();
		fh.setEncryptedSessionKey(encryptedSessionKey);
		fh.setVersion(1);
		
		return fh;
	}
}
