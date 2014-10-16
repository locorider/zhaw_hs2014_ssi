package ch.zhaw.slcrypt.decrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import ch.zhaw.slcrypt.Helpers;
import ch.zhaw.slcrypt.InvalidFormatException;
import ch.zhaw.slcrypt.decrypt.HybridDecryption.MACState;

/**
 * The main class to hybrid decrypt (including checking the MAC) a document.
 */
public class SLDecrypt {

	/**
	 * The main method to hybrid decrypt a document.
	 * 
	 * @param args
	 *            The command line parameters
	 */
	public static void main(String[] args) {
		if(args.length < 4){
			System.out.println("Not enough arguments\n");
			System.out.println("Usage: java SLDecrypt encrypted_file " +
					"decrypted_file private_key_file mac_password");
			System.exit(-1);
		}
		new SLDecrypt(args[0], args[1], args[2], args.length < 4 ? null : args[3]);
	}

	/**
	 * Constructor. Hybrid decrypts a document.
	 * 
	 * @param inFilename
	 *            The file to decrypt
	 * @param outFilename
	 *            The filename to use for the decrypted document
	 * @param keyFilename
	 *            The filename of the private key
	 * @param macPassword
	 *            The password for the MAC
	 */
	public SLDecrypt(String inFilename, String outFilename, String keyFilename, String passwd) {
		FileInputStream in = null;
		FileInputStream key = null;
		FileOutputStream out = null;
		
		try {
			// create streams for all files to read/write
			File inFile = new File(inFilename);
			in = new FileInputStream(inFile);
			File outFile = new File(outFilename);
			out = new FileOutputStream(outFile);
			File keyFile = new File(keyFilename);
			key = new FileInputStream(keyFile);
			
			// decrypt the document	
			decrypt(in, out, key, passwd);
		} catch (FileNotFoundException e) {
			System.out.println("File not found: " +e.getMessage());
		} catch (InvalidFormatException e) {
			System.out.println("Error decrypting file! " + e.getMessage());
		} catch (IOException e) {
			System.out.println("I/O error: " + e.getMessage());
		} finally {
			
			// close the streams
			if(in != null){
				try {
					in.close();
				} catch (IOException e) {
				}
			}
			if(key != null){
				try {
					key.close();
				} catch (IOException e) {
				}
			}
			if(out != null){
				try {
					out.close();
				} catch (IOException e) {
				}
			}
		}
	}
	
	/**
	 * Hybrid endecrypts a document.
	 * 
	 * @param in
	 *            The InputStream from which to read the encrypted document
	 * @param out
	 *            The OutputStream to which to write the decrypted document
	 * @param key
	 *            The InputStream from which to read the private key
	 * @param mac_password
	 *            The password to use for computing the HMAC
	 * @throws IOException
	 */
	public void decrypt(FileInputStream in, FileOutputStream out, 
			FileInputStream key, String passwd) 
	throws InvalidFormatException, IOException{
		
		// hybrid decrypt the document
		HybridDecryption he = new HybridDecryptionImpl();
		DecryptedDocument document = he.decryptDocumentStream(in, key, passwd.getBytes());
		
		// display general information
		System.out.println("File version: " + 
				(document.getFileVersion()));
		
		// display information about MAC check
		System.out.println("MacDoc:  " + Helpers.asHex(document.getMacDoc()));
		System.out.println("MacComp: " + Helpers.asHex(document.getMacComp()));
		if(document.getMacState() == MACState.valid){
			System.out.println("MAC: Successfully authenticated");
		} else if(document.getMacState() == MACState.invalid){
			System.out.println("MAC: Warning, wrong MAC!");
		}
		
		// display information about algorithm, key and IV
		System.out.println("Algorithm: " + document.getCipherName());
		System.out.println("Keylength: " + document.getSessionKey().length * 8);
		System.out.println("Key: " + Helpers.asHex(document.getSessionKey()));
		System.out.println("IV: " + Helpers.asHex(document.getIv()));
		
		// save the decrypted document
		InputStream documentStream = document.getDocument();
		byte[] buffer = new byte[128];
		for (int len; (len = documentStream.read(buffer)) != -1;) {
			out.write(buffer, 0, len);
		}
	}
}
