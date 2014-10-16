package ch.zhaw.slcrypt.decrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ch.zhaw.slcrypt.FileHeader;
import ch.zhaw.slcrypt.InvalidFormatException;
import ch.zhaw.slcrypt.SessionKey;

public class HybridDecryptionImpl extends HybridDecryption {

	/**
	 * Gets the file header.
	 * 
	 * @param encryptedDocument
	 *            The encrypted document, including the file header
	 * @return The file header<
	 */
	@Override
	protected FileHeader getFileHeader(InputStream encryptedDocument)
			throws InvalidFormatException {
		
		return new FileHeader(encryptedDocument);
	}

	/**
	 * Gets the decrypted session key.
	 * 
	 * @param fileHeader
	 *            The file header
	 * @param privateKey
	 *            The private key to decrypt the session key
	 * @return The decrypted session key
	 */
	@Override
	protected SessionKey getDecryptedSessionKey(FileHeader fileHeader,
			InputStream privateKey) throws InvalidFormatException {
		
		try {
			// read the private key and generate a PrivateKey object
			ByteArrayOutputStream rawPrivateKey = new ByteArrayOutputStream();
			byte[] buffer = new byte[128];
			for (int len; (len = privateKey.read(buffer)) != -1;){
				rawPrivateKey.write(buffer, 0, len);
			}
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(rawPrivateKey.toByteArray());
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey privKey = kf.generatePrivate(keySpec);
					
			// create the RSA cipher with the private key 
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			
			// decrypt and return the header
			return new SessionKey(cipher.doFinal(fileHeader.getEncryptedSessionKey()));
		} catch (IOException e) {
			throw new InvalidFormatException("[Private Key] Cannot read: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			throw new InvalidFormatException("[Session Key] No such algorithm: " + e.getMessage());
		} catch (NoSuchPaddingException e) {
			throw new InvalidFormatException("[Session Key] No such padding: " + e.getMessage());
		} catch (InvalidKeySpecException e) {
			throw new InvalidFormatException("[Session Key] Invalid key spec: " + e.getMessage());
		} catch (InvalidKeyException e) {
			throw new InvalidFormatException("[Session Key] Invalid key: " + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			throw new InvalidFormatException("[Session Key] Illegal block size: " + e.getMessage());
		} catch (BadPaddingException e) {
			throw new InvalidFormatException("[Session Key] Bad padding: " + e.getMessage());
		} catch (InvalidFormatException e) {
			throw new InvalidFormatException("[Session Key] Invalid format: " + e.getMessage());
		}
	}

	/**
	 * Decrypts the document.
	 * 
	 * @param encryptedDocument
	 *            The document to decrypt
	 * @param sessionKey
	 *            The session key to decrypt the document
	 * @return The decrypted document
	 */
	@Override
	protected InputStream decryptDocument(InputStream encryptedDocument,
			SessionKey sessionKey) throws InvalidFormatException {
		
		try {
			// get the used transformation and create the Cipher object
			String cipherName = new String(sessionKey.getTransformationName());
			Cipher cipher = Cipher.getInstance(cipherName);

			// init the cipher correctly
			String[] cipherNameTokens = cipherName.split("/");
			SecretKeySpec skeySpec = new SecretKeySpec(sessionKey.getKey(),
					cipherNameTokens[0]);			
			if (sessionKey.getIV() != null) {
				AlgorithmParameters algParam = AlgorithmParameters
						.getInstance(cipherNameTokens[0]);
				algParam.init(new IvParameterSpec(sessionKey.getIV()));
				cipher.init(Cipher.DECRYPT_MODE, skeySpec, algParam);
			} else {
				cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			}
			
			// return the CipherInputStream from which the decrypted document can be read
			return new CipherInputStream(encryptedDocument, cipher);			
		} catch (NoSuchAlgorithmException e) {
			throw new InvalidFormatException("[Document] No such algorithm: " + e.getMessage());
		} catch (InvalidParameterSpecException e) {
			throw new InvalidFormatException("[Document] Invalid parameter spec: " + e.getMessage());
		} catch (NoSuchPaddingException e) {
			throw new InvalidFormatException("[Document] No such padding: " + e.getMessage());
		} catch (InvalidKeyException e) {
			throw new InvalidFormatException("[Document] Invalid key: " + e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			throw new InvalidFormatException("[Document] Invalid algorithm parameter: " + e.getMessage());
		}
	}

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
	@Override
	public DecryptedDocument checkMAC(InputStream documentMAC,
			byte[] passwordMAC) throws InvalidFormatException {
		DecryptedDocument decryptedDocument = new DecryptedDocument();
		
		try {
			// generate the mac using HMAC-SHA1 and the specified password as
			// the key
			SecretKeySpec keySpec = new SecretKeySpec(passwordMAC, "HmacSHA1");
			Mac hmac = Mac.getInstance(keySpec.getAlgorithm());
			hmac.init(keySpec);
			
			// read the HMAC from the InputStream
			byte[] macDoc = new byte[20];
			documentMAC.read(macDoc);
			
			// use an OutputStream to regenerate the document stream later
			ByteArrayOutputStream documentBackup = new ByteArrayOutputStream();
			
			// read from the InputStream and put them into hmac_comp and documentBackup
			int len;
			byte[] tmpBuf = new byte[10];
			while ((len = documentMAC.read(tmpBuf, 0, 10)) >= 0) {
				documentBackup.write(tmpBuf, 0, len);
				hmac.update(tmpBuf, 0, len);
			}
			
			// compute the hash and compare it with the hash in documentMAC
			byte[] macComp = hmac.doFinal();
			if(Arrays.equals(macDoc, macComp)) {
				decryptedDocument.setMacState(MACState.valid);
			} else {
				decryptedDocument.setMacState(MACState.invalid);
			}
			decryptedDocument.setMacDoc(macDoc);
			decryptedDocument.setMacComp(macComp);
			
			// set the document InputStream in decryptedDocument
			decryptedDocument.setDocument(new ByteArrayInputStream(documentBackup.toByteArray()));
			return decryptedDocument;
		} catch (IOException e) {
			throw new InvalidFormatException("[MAC] IO Exception: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			throw new InvalidFormatException("[MAC] No such algorithm: " + e.getMessage());
		} catch (InvalidKeyException e) {
			throw new InvalidFormatException("[MAC] Invalid Key: " + e.getMessage());
		}
	}
}
