package ch.zhaw.securitylab;

/**
 * This class serves to test SSL/TLS servers.
 * @author Marc Rennhard
 */
public class TLSTester {

	/* Variables specified via the command line parameters */
	private static String host;	
	private static int port;
	private static String trustStore = null;
	private static String password = null;

	/**
	 * The run method that executes all tests
	 * - Check if the server can be reached
	 * - Print the highest TLS version supported by the server
	 * - Print the certificate chain including details about the certificates
	 * - Check which cipher suite the server supports and list the secure and 
	 *   insecure ones
	 * @throws Exception An exception occurred
	 */
	private void run() throws Exception {
		TLSCheck tlsCheck = new TLSCheck(trustStore, password, null, host, port);
		tlsCheck.check();
	}
	
	/**
	 * The main method.
	 * @param argv The command line parameters
	 * @throws Exception If an exception occurred
	 */
	public static void main (String argv[]) throws Exception { 

		/* Create a TLSTester object, and execute the test */
		try {
			host = argv[0];
			port = Integer.parseInt(argv[1]);
			if ((port < 1) || (port > 65535)) {
				throw (new Exception());
			}
			if (argv.length > 2) {
				trustStore = argv[2];
				password = argv[3];
			}
		} catch (Exception e) {
			System.out.println("\nUsage: java TLSTester host port {truststore password}\n");
			System.exit(0);
		}
		TLSTester tlst = new TLSTester();           
		tlst.run();                                             
	}
}
