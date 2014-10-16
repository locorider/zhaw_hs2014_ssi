package ch.zhaw.slcrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * The FileHeader class supports encoding and decoding of file headers. 
 * Encoding means that the file header is built based on the version
 * and encrypted session key. Decoding means that a file header is read 
 * and the version and encrypted session key are extracted.
 */
public class FileHeader {
	
	private static final byte[] FORMAT_STRING = { 'S', 'L', 'C', 'R', 'Y',
			'P', 'T' };
	private int version;
	private byte[] encryptedSessionKey;

	/**
	 * Constructor. Empty default constructor.
	 */
	public FileHeader() {
	}

	/**
	 * Constructor. Decodes an existing file header that is stored in a byte 
	 * array. The values (version and encrypted session key) are written 
	 * to the instance variables version and encryptedSessionKey.
	 * 
	 * @param fileHeader
	 *            The file header to decode
	 * @throws InvalidFormatException
	 */
	public FileHeader(byte[] fileHeader) throws InvalidFormatException {
		decode(new ByteArrayInputStream(fileHeader));
	}

	/**
	 * Constructor. Decodes an existing file header that can be read from an 
	 * InputStream. The values (version and encrypted session key) are written 
	 * to the instance variables version and encryptedSessionKey.
	 * 
	 * @param fileHeaderStream
	 *            The stream from which the file header can be read
	 * @throws InvalidFormatException
	 */
	public FileHeader(InputStream fileHeaderStream)
			throws InvalidFormatException {
		decode(fileHeaderStream);
	}

	/**
	 * Decodes a file header that can be read from an InputStream. The values 
	 * (version and encrypted session key) are written to the instance 
	 * variables version and encryptedSessionKey.
	 * 
	 * @param is
	 *            The InputStream from which file header can be read
	 * @throws InvalidFormatException
	 */
	private void decode(InputStream is) throws InvalidFormatException {
		int tmpLen = FORMAT_STRING.length;
		byte[] formatString = new byte[FORMAT_STRING.length];

		try {
			// read SLCrypt file type
			is.read(formatString);
			if (!Arrays.equals(FORMAT_STRING, formatString)) {
				throw new InvalidFormatException("Not an SLCrypt file");
			}

			// read file version
			version = is.read();
			if (version != 1) {
				throw new InvalidFormatException("Unknown file version");
			}

			// read encrypted session key
			tmpLen = is.read();
			encryptedSessionKey = new byte[tmpLen];
			is.read(encryptedSessionKey);
		} catch (IOException e) {
			throw new InvalidFormatException("Invalid format");
		}
	}

	/**
	 * Returns the version.
	 * 
	 * @return The version
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Sets the version.
	 * 
	 * @param version
	 *            The version
	 */
	public void setVersion(int version) {
		this.version = version;
	}

	/**
	 * Returns the encrypted session key.
	 * 
	 * @return The encrypted session key
	 */
	public byte[] getEncryptedSessionKey() {
		return encryptedSessionKey;
	}

	/**
	 * Sets the encrypted session key.
	 * 
	 * @param sessionKey
	 *            The encrypted session key
	 */
	public void setEncryptedSessionKey(byte[] sessionKey) {
		this.encryptedSessionKey = sessionKey;
	}

	/**
	 * Encodes the file header using the currently stored values (version and 
	 * encrypted session key) from the instance variables version and 
	 * encryptedSessionKey.
	 * 
	 * @return The file header
	 */
	public byte[] encode() {
		ByteArrayOutputStream os = new ByteArrayOutputStream();

		try {
			os.write(FORMAT_STRING);
			os.write(version);
			os.write(encryptedSessionKey.length & 0xff);
			os.write(encryptedSessionKey);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return os.toByteArray();
	}
}
