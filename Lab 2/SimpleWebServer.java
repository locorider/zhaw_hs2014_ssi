package ch.zhaw.securitylab;



import java.io.*;                                         

import java.net.*;                                                                              

import java.nio.CharBuffer;



public class SimpleWebServer {                            



	// Run the HTTP server on this TCP port

	private static final int PORT = 8080;                 



	// Some HTTP status messages

	private static final String STATUS_200 = "HTTP/1.0 200 OK\n\n";

	private static final String STATUS_201 = "HTTP/1.0 201 Created\n\n";

	private static final String STATUS_400 = "HTTP/1.0 400 Bad Request\n\n";

	private static final String STATUS_403 = "HTTP/1.0 403 Forbidden\n\n";

	private static final String STATUS_404 = "HTTP/1.0 404 Not Found\n\n";

	private static final String STATUS_500 = "HTTP/1.0 500 Internal Error\n\n";

	private static final String STATUS_501 = "HTTP/1.0 501 Not Implemented\n\n";



	// The maximum length for requests and downloaded files

	private static final int MAX_REQUEST_LENGTH = 8192;  

	private static final int MAX_DOWNLOAD_LENGTH = 10000000;

	

	// The directory that contains the web resources

	private static final String WEBROOT = "data"; 



	// The upload directory

	private static String UPLOAD_DIR = "upload";



	// The socket used to process incoming connections from web clients

	private static ServerSocket dServerSocket;

	

	

	/* Constructor */

	public SimpleWebServer() throws IOException {          

		dServerSocket = new ServerSocket (PORT);          

	}                                                     



	/* This method starts the actual web server */

	private void run() throws IOException {                 

		while (true) {

			

			// Wait for a connection from a client

			Socket s = dServerSocket.accept();           



			// Process the client's request

			processRequest(s);

		}                                                

	}                                                    



	/* Reads the HTTP request from the client and responds with the file

	   the user requested or a HTTP error code. */

	private void processRequest(Socket s) throws IOException {

		

		// Used to read data from the client

		BufferedReader br = new BufferedReader (new InputStreamReader (s.getInputStream())); 

		

		// Read the HTTP request from the client

		String request = null;

//		StringBuilder stringBuffer = new StringBuilder();

//		int totalRead = 0, read = 0;

//		char[] buffer = new char[256];

//		while (-1 != (read = br.read()) && totalRead <= MAX_REQUEST_LENGTH) {

//			totalRead += read;

//			stringBuffer.append(buffer, 0, read);

//		}

//		request = stringBuffer.toString();

		CharBuffer buffer = CharBuffer.allocate(MAX_REQUEST_LENGTH);

		br.read(buffer);

		buffer.flip();

		request = buffer.toString();

		System.out.println("REQUEST [" + request + "]");

		// Used to write data to the client

		OutputStreamWriter osw =                            

			new OutputStreamWriter (s.getOutputStream());

		

		// Parse the HTTP request

		String command = null;                             

		String pathname = null;

		if(null != request && !request.isEmpty()) {

			String[] tokens = request.split(" ");

			int tokenLength = tokens.length;

			if(tokenLength > 0) {

				command = tokens[0];

				if(tokenLength > 1) {

					pathname = tokens[1];

					pathname = pathname.replaceAll("\n", "");

				}

			} else {

				command = request;

			}

		}



		/* If the request is a GET, try to respond with the file

		   the user is requesting. If it's a PUT, store the file. */

		if(null == command || command.isEmpty() || null == pathname || pathname.isEmpty()) {

			osw.write(STATUS_400);

		} else if (command.equals("GET")) {

			serveFile (osw,pathname);                   

		} else if (command.equals("PUT")) {

			storeFile(br,osw,pathname);                   

		} else {                                         

			/* If the request is neither GET nor PUT, return an error saying 

			   this server does not implement the requested command */

			osw.write (STATUS_501);

		}                                               



		// Close the connection to the client

		osw.close();                                    

	}                                                   



	/* serveFile is used to return a requested resource */

	private void serveFile (OutputStreamWriter osw,      

			String pathname) throws IOException {

		FileReader fr = null;                                 

		int c = -1;                                           

		StringBuffer sb = new StringBuffer();

		

		// Remove the initial slash at the beginning of the pathname in the request

		if (pathname.charAt(0)=='/') {                        

			pathname=pathname.substring(1);

		}



		// If there was no filename specified by the client, serve the "index.html" file

		if (pathname.equals("")) {                            

			pathname="index.html";

		}

		

		// Make sure that the file is read from the webroot directory

		pathname = WEBROOT + "/" + pathname;

		File fileWebroot = new File(WEBROOT);

		File file = new File(pathname);

		if(checkPath(pathname)) {

			// Try to open file specified by pathname

			try {                                               

				fr = new FileReader (file);                 

				c = fr.read();                                  

			} catch (Exception e) { 

				// If the file is not found, return the appropriate HTTP response code

				osw.write (STATUS_404);         

				return;                                         

			}                                                   



			/* If the requested file can be successfully opened and read, then return an 

			   OK response code and send the contents of the file */

			osw.write (STATUS_200); 

			int totalRead = 0;

			while (c != -1 && totalRead <= MAX_DOWNLOAD_LENGTH) {       

				sb.append((char)c);                            

				c = fr.read();

				totalRead++;

			}        

			fr.close();

			osw.write (sb.toString());  

		} else {

			osw.write(STATUS_404);

		}

	}                                                       



	private boolean checkPath(String pathname) {

		file.getCanonicalPath().startsWith(fileWebroot.getCanonicalPath())

		return false;

	}



	/* storeFile is used to store a resource */

	private void storeFile(BufferedReader br, OutputStreamWriter osw, 

			String pathname) throws IOException {

		FileWriter fw = null;



		// Remove the initial slash at the beginning of the pathname in the request

		if (pathname.charAt(0)=='/') {

			pathname=pathname.substring(1);

		}



		// If there was no filename specified by the client, store the file with file name default

		if (pathname.equals("")) {                          

			pathname="default";

		}

		

		// Make sure that the file is written below the webroot directory

		pathname = WEBROOT + "/" + UPLOAD_DIR + "/" + pathname;

		File filePathname = new File(pathname);

		File fileWebroot = new File(WEBROOT + "/" + UPLOAD_DIR);

		if(filePathname.getCanonicalPath().startsWith(fileWebroot.getCanonicalPath())) {

			// Try to write the file

			try {

				fw = new FileWriter(pathname);

				

				// Absorb input until there's an empty line

				String s = br.readLine();

				while ((s != null) && (!s.equals(""))) {

					s = br.readLine();

				}

				

				// Read file content

				s = br.readLine();

				while ((s != null) && (!s.equals(""))) {

					fw.write(s + "\n");

					s = br.readLine();

				}

				fw.close();

				osw.write(STATUS_201);

			} catch (Exception e) {

				e.printStackTrace();

				osw.write(STATUS_500);

			}

		} else {

			osw.write(STATUS_403);

		}

	}



	/* main method */

	public static void main (String argv[]) throws IOException { 



		// Create a SimpleWebServer object and run it

		SimpleWebServer sws = new SimpleWebServer();           

		sws.run();                                             

	}                                                          

}                                                              

