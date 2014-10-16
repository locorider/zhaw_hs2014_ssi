package ch.zhaw.securitylab;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class TLSCheck {

	private TrustManagerFactory trustManagerFactory;
	private final String trustStore;
	private final String password;
	private SSLContext sslContext;
	private final String tlsVersion;
	private final String host;
	private final int port;
	private SSLSocket sslSocket;
	private volatile boolean initialized = false;
	
	private List<X509Certificate> acceptedIssuers;
	private X509Certificate rootCertificate;
	private SSLSession sslSession;
	
	public TLSCheck(String trustStore, String password, String tlsVersion, String host, int port) {
		this.trustStore = trustStore;
		this.password = password;
		this.host = host;
		this.port = port;
		this.tlsVersion = (null == tlsVersion) ? "TLSv1.2" : tlsVersion;
	}
	
	public void init() {
		if(!initialized) {
			trustManagerFactory = TrustManagerFactoryHelper.createTrustManagerFactory(trustStore, password);
			initSSLContext();
			initialized = true;
		}
	}
	
	public synchronized void check() {
		init();
		printTrustStoreInfo();
		startHandshake();
		printCATrusted();
		printHighestTLSVersion();
		printCertificateChain();
		checkSupportedCipherSuites();
		close();
	}
	
	private void checkSupportedCipherSuites() {
		SSLParameters sslParameters = sslContext.getSupportedSSLParameters();
		final String[] cipherSuites = sslSocket.getEnabledCipherSuites();
		final String[] localCipherSuites = sslParameters.getCipherSuites();
		int localCipherSuitesCount = (null == localCipherSuites) ? 0 : localCipherSuites.length;
		List<String> secureCiphers = new ArrayList<>();
		List<String> unsecureCiphers = new ArrayList<>();
		System.out.println("Check supported cipher suites (test program supports " + localCipherSuitesCount + " cipher suites)");
		for(int i = 0; i < localCipherSuites.length; i++) {
			System.out.print(".");
			final String cipherSuite = localCipherSuites[i];
			final boolean supported = testCipherSuite(cipherSuite);
			if(supported && isCipherSecure(cipherSuite)) {
				secureCiphers.add(cipherSuite);
			} else if (supported) {
				unsecureCiphers.add(cipherSuite);
			}
		}
		System.out.println(" DONE, " + localCipherSuitesCount + " cipher suites tested\n");
		
		System.out.println("The following " + secureCiphers.size() + " SECURE cipher suites are supported by the server:");
		printCiphers(secureCiphers);
		if(unsecureCiphers.size() > 0) {
			System.out.println("\nThe following " + unsecureCiphers.size() + " INSECURE cipher suites are supported by the server");
			printCiphers(unsecureCiphers);
		} else {
			System.out.println("\nNo INSECURE cipher suites are supported by the server");
		}
	}

	private void printCiphers(List<String> secureCiphers) {
		for(String cipher : secureCiphers) {
			System.out.println(cipher);
		}		
	}

	private boolean testCipherSuite(final String cipherSuite) {
		SSLSocket sslSocket = null;
		boolean supported = false;
		try {
			SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
			sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
//			System.out.println("Checking " + cipherSuite);
			sslSocket.setEnabledCipherSuites(new String[] { cipherSuite });
			sslSocket.startHandshake();
			supported = true;
		} catch (IOException e) { } finally {
			if(null != sslSocket) {
				try {
					sslSocket.close();
				} catch (IOException e) { }
			}
		}
		return supported;
	}

	private boolean isCipherSecure(final String cipher) {
		if(cipher.startsWith("TLS_RSA_WITH_AES_128") || cipher.startsWith("TLS_ECDHE_RSA_WITH_AES_256") || cipher.startsWith("TLS_ECDHE_RSA_WITH_AES_128")
				|| cipher.startsWith("TLS_DHE_RSA_WITH_AES_256") || cipher.startsWith("TLS_DHE_RSA_WITH_AES_128") || cipher.equals("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")) {
			return true;
		}
		if((cipher.contains("_128_") || cipher.contains("_256_")) && !cipher.contains("_DES") && !cipher.contains("RC4") && !cipher.contains("MD5") && !cipher.contains("KRB5")) {
			return true;
		}
		return false;
	}

	private void printCertificateChain() {
		List<X509Certificate> certificateList = getCertificateList();
		Collections.reverse(certificateList);
		System.out.println("Information about certificates from " + host + ":" + port + "\n");
		System.out.println(certificateList.size() + " certificate(s) in chain\n");
		int index = 1;
		for(X509Certificate certificate : certificateList) {
			System.out.println("Certificate " + index++ + ":");
			printCertificate(certificate);
		}
	}

	private void printCertificate(X509Certificate certificate) {
		final PublicKey publicKey = certificate.getPublicKey();
		System.out.println("Subject: " + certificate.getSubjectDN());
		System.out.println("Issuer: " + certificate.getIssuerDN());
		System.out.println("Algorithm: " + certificate.getSigAlgName());
		System.out.println("Validity: " + certificate.getNotBefore() + " - " + certificate.getNotAfter());
		if(publicKey instanceof RSAPublicKey) {
			final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
			System.out.print("Public key length (modulus): " + rsaPublicKey.getModulus().bitLength() + "\n\n");
		}
	}

	private List<X509Certificate> getCertificateList() {
		List<X509Certificate> certificateList = new ArrayList<>();
		try {
			Certificate[] certificates = sslSession.getPeerCertificates();
			if(null != certificates) {
				for(int i = 0; i < certificates.length; i++) {
					Certificate oldCert = certificates[i];
					X509Certificate certificate = (X509Certificate) oldCert;
					certificateList.add(certificate);
				}
			}
		} catch (SSLPeerUnverifiedException e) {
			e.printStackTrace();
		}
		return certificateList;
	}

	private void printHighestTLSVersion() {
		final String[] tlsVersions = sslSocket.getEnabledProtocols();
		final List<String> tlsVersionList = Arrays.asList(tlsVersions);
		String tlsVersion = sslSession.getProtocol();
		if(tlsVersionList.contains("TLSv1.2")) {
			tlsVersion = "TLSv1.2";
		} else if (tlsVersionList.contains("TLSv1.1")) {
			tlsVersion = "TLSv1.1";
		} else if(tlsVersionList.contains("TLSv1")) {
			tlsVersion = "TLSv1";
		} else if(tlsVersionList.contains("SSLv3")) {
			tlsVersion = "SSLv3";
		}
		System.out.println("Highest TLS Version supported by server: " + tlsVersion + "\n");
	}

	public void close() {
		try {
			if(null != sslSocket) {
				sslSocket.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void startHandshake() {
		try {
			sslSocket = createSocket();
			sslSocket.startHandshake();
			System.out.println("Check connectivity to " + host + ":" + port + " - OK\n");
		} catch (IOException e) {
			System.out.println("Check connectivity to " + host + ":" + port + " - ERROR\n");
		}
	}

	private void printCATrusted() {
		sslSession = sslSocket.getSession();
		rootCertificate = getRootCertificate(sslSession);
		boolean trusted = acceptedIssuers.contains(rootCertificate);
		if(trusted) {
			System.out.println("The root CA is trusted\n");
		} else {
			System.out.println("The root CA is UNTRUSTED\n");
		}
	}

	private X509Certificate getRootCertificate(SSLSession sslSession) {
		X509Certificate rootCertificate = null;
		try {
			Certificate[] certificates = sslSession.getPeerCertificates();
			if(null != certificates && certificates.length > 0) {
				Certificate certificate = certificates[certificates.length - 1];
				rootCertificate = (X509Certificate) certificate;
			}
		} catch (SSLPeerUnverifiedException e) {
			e.printStackTrace();
		}
		return rootCertificate;
	}

	private void printTrustStoreInfo() {
		int totalCerts = countTotalCerts();
		if(null != trustStore && null != password) {
			System.out.println("Use specified truststore with (" + trustStore + ") " + totalCerts + " certificates\n");
		} else {
			System.out.println("Use default truststore with " + totalCerts + " certificates\n");
		}		
	}

	private int countTotalCerts() {
		int totalCerts = 0;
		final TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		acceptedIssuers = new ArrayList<>();
		if(null != trustManagers) {
			for(int i = 0; i < trustManagers.length; i++) {
				X509TrustManager trustManager = (X509TrustManager) trustManagers[i];
				X509Certificate[] certificates = trustManager.getAcceptedIssuers();
				if(null != certificates) {
					acceptedIssuers.addAll(Arrays.asList(certificates));
					totalCerts = certificates.length;
				}
			}
		}
		return totalCerts;
	}

	private SSLContext initSSLContext() {
		if(null == sslContext) {
			try {
				sslContext = SSLContext.getInstance(tlsVersion);
				sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
			} catch (NoSuchAlgorithmException | KeyManagementException e) {
				e.printStackTrace();
			}
		}
		return sslContext;
	}
	
	private SSLSocket createSocket() throws UnknownHostException, IOException {
		SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
		return sslSocket;
	}
}
