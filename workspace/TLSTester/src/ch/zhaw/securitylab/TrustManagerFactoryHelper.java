package ch.zhaw.securitylab;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.TrustManagerFactory;

public class TrustManagerFactoryHelper {

	public static TrustManagerFactory createTrustManagerFactory() {
		KeyStore keyStore = getKeyStore(null, null);
		TrustManagerFactory trustManagerFactory = createTrustManagerFactory(keyStore);
		return trustManagerFactory;
	}
	
	public static TrustManagerFactory createTrustManagerFactory(final String trustStore, final String password) {
		KeyStore keyStore = getKeyStore(trustStore, password);
		TrustManagerFactory trustManagerFactory = createTrustManagerFactory(keyStore);
		return trustManagerFactory;
	}
	
	private static TrustManagerFactory createTrustManagerFactory(final KeyStore keyStore) {
		TrustManagerFactory trustManagerFactory = null;
		try {
			trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
			trustManagerFactory.init(keyStore);
		} catch (NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}
		return trustManagerFactory;
	}
	
	private static KeyStore getKeyStore(final String trustStore, final String password) {
		KeyStore keyStore = null;
		if(null != trustStore && null != password) {
			try {
				keyStore = KeyStore.getInstance("JKS");
				keyStore.load(new FileInputStream(trustStore), password.toCharArray());
			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
				e.printStackTrace();
			}
		}
		return keyStore;
	}
}