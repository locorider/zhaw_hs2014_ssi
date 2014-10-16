package ch.zhaw.slcrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * The SessionKey class supports encoding and decoding of session keys. Encoding
 * means that the session key is built based on the transformationName, iv,
 * (optional) and key. Decoding means that a session key is read and the
 * transformationName, iv, (optional) and key are extracted.
 */
public class SessionKey {
	
	private byte[] transformationName;
	private byte[] iv;
	private byte[] key;

	/**
	 * Constructor. Empty default constructor.
	 */
	public SessionKey() {
	}

	/**
	 * Constructor. Decodes a session key that is stored in a byte array. The
	 * three parts of the session key are written to transformationName, iv
	 * (optional) and key.
	 * 
	 * @param sessionKey
	 *            The session key to decode
	 * @throws InvalidFormatException
	 */
	public SessionKey(byte[] sessionKey) throws InvalidFormatException {
		decode(new ByteArrayInputStream(sessionKey));
	}

	/**
	 * Constructor. Decodes a session key that can be read from an InputStream.
	 * The three parts of the session key are written to transformationName, iv
	 * (optional) and key.
	 * 
	 * @param is
	 *            The stream from which the session key can be read
	 * @throws InvalidFormatException
	 */
	private void decode(InputStream is) throws InvalidFormatException {
		int tmpLen = 0;

		try {
			// read cipher name
			tmpLen = is.read();
			transformationName = new byte[tmpLen];
			is.read(transformationName);

			// read optional iv
			tmpLen = is.read();
			if (tmpLen != 0) {
				iv = new byte[tmpLen];
				is.read(iv);
			}

			// read key
			tmpLen = is.read();
			key = new byte[tmpLen];
			is.read(key);
		} catch (IOException e) {
			throw new InvalidFormatException(e.getMessage());
		}
	}

	/**
	 * Returns the transformation name.
	 * 
	 * @return The name of the transformation to use
	 */
	public byte[] getTransformationName() {
		return transformationName;
	}

	/**
	 * Sets the transformation name.
	 * 
	 * @param transformationName
	 *            The name of the transformation to use
	 */
	public void setTransformationName(byte[] transformationName) {
		this.transformationName = transformationName;
	}

	/**
	 * Returns the IV.
	 * 
	 * @return The IV
	 */
	public byte[] getIV() {
		return iv;
	}

	/**
	 * Sets the IV.
	 * 
	 * @param iv
	 *            The IV
	 */
	public void setIV(byte[] iv) {
		this.iv = iv;
	}

	/**
	 * Returns the symmetric key.
	 * 
	 * @return The key
	 */
	public byte[] getKey() {
		return key;
	}

	/**
	 * Sets the symmetric key.
	 * 
	 * @param key
	 *            The key
	 */
	public void setKey(byte[] key) {
		this.key = key;
	}

	/**
	 * Encodes the session key using the currently stored values of
	 * transformationName, iv (optional) and key.
	 * 
	 * @return The encoded session key
	 */
	public byte[] encode() {
		ByteArrayOutputStream os = new ByteArrayOutputStream();

		try {
			// write cipher name
			os.write(transformationName.length & 0xff);
			os.write(transformationName);

			// write optional iv
			if (iv != null) {
				os.write(iv.length & 0xff);
				os.write(iv);
			} else {
				os.write(0);
			}

			// write key
			os.write(key.length & 0xff);
			os.write(key);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return os.toByteArray();
	}
}
