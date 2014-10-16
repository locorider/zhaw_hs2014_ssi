package ch.zhaw.slcrypt.encrypt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * The main class to produce a MAC over a document and subsequent hybrid 
 * encryption of the document.
 */
public class SLEncrypt {

	/**
	 * The main method to hybrid encrypt a document.
	 * 
	 * @param args
	 *            The command line parameters
	 */
	public static void main(String[] args) {
		if (args.length < 4) {
			System.out.println("Not enough arguments\n");
			System.out
					.println("Usage: java SLEncrypt plain_file encrypted_file "
							+ "certificate_file mac_password");
			System.exit(-1);
		}
		new SLEncrypt(args[0], args[1], args[2], args[3]);
	}

	/**
	 * Constructor. Hybrid encrypts a document.
	 * 
	 * @param inFilename
	 *            The file to encrypt
	 * @param outFilename
	 *            The filename to use for the encrypted document
	 * @param keyFilename
	 *            The filename of the certificate
	 * @param macPassword
	 *            The password for the MAC
	 */
	public SLEncrypt(String inFilename, String outFilename,
			String certFilename, String macPassword) {

		FileInputStream in = null;
		FileInputStream cert = null;
		FileOutputStream out = null;

		try {
			// create streams for all files to read/write
			File inFile = new File(inFilename);
			in = new FileInputStream(inFile);
			File outFile = new File(outFilename);
			out = new FileOutputStream(outFile);
			File keyFile = new File(certFilename);
			cert = new FileInputStream(keyFile);

			// encrypt the document
			encrypt(in, out, cert, macPassword);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			
			// close the streams
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
				}
			}
			if (cert != null) {
				try {
					cert.close();
				} catch (IOException e) {
				}
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
				}
			}
		}
	}

	/**
	 * Hybrid encrypts a document.
	 * 
	 * @param in
	 *            The InputStream from which to read the document
	 * @param out
	 *            The OutputStream to which to write the encrypted document
	 * @param cert
	 *            The InputStream from which to read the certificate
	 * @param mac_password
	 *            The password to use for computing the HMAC
	 * @throws IOException
	 */
	public void encrypt(InputStream in, OutputStream out, InputStream cert, 
			String macPassword) throws IOException {
		
		// hybrid encrypt the document
		HybridEncryption he = new HybridEncryptionImpl();
		InputStream encrypted = he.encryptDocumentStream(in, cert, 
				macPassword.getBytes());

		// save the encrypted document
		byte[] buffer = new byte[128];
		for (int len; (len = encrypted.read(buffer)) != -1;) {
			out.write(buffer, 0, len);
		}
	}
}
