package dev.svero.tools;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Implements methods for handling SSL/TLS contexts.
 *
 * @author Sven Roeseler
 */
public class SSLUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSLUtils.class);

    /**
     * Creates a new SSL context using the default key managers and trust managers.
     *
     * @return Created SSL context instance
     */
    public SSLContext createSSLContext() {
        return createSSLContext(null, null, null);
    }

    /**
     * Creates a new SSL context using a trust manager based on the specified trust store.
     *
     * @param trustStore Trust store to use
     * @return Created SSL context instance
     */
    public SSLContext createSSLContext(KeyStore trustStore) {
        return createSSLContext(null, null, trustStore);
    }

    /**
     * Creates a SSL context.
     *
     * @return SSL context or null
     */
    public SSLContext createSSLContext(KeyStore keyStore, String keyStorePassword, KeyStore trustStore) {
        SSLContext context;

        try {
            context = SSLContext.getInstance("TLS");

            TrustManager[] trustManagers;
            KeyManager[] keyManagers = null;

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            if (trustStore != null) {
                LOGGER.debug("Using specified trust store");
                tmf.init(trustStore);
            } else {
                LOGGER.debug("Using default JVM trust store");
                tmf.init((KeyStore) null);
            }

            trustManagers = tmf.getTrustManagers();

            for (TrustManager tm : trustManagers) {
                if (tm instanceof X509TrustManager x509TrustManager) {
                    X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();
                    LOGGER.debug("Has {} accepted issueres", acceptedIssuers.length);
                } else {
                    LOGGER.debug("Unexpected trust manager instance found: {}", tm.getClass());
                }
            }

            if (keyStore != null) {
                if (StringUtils.isBlank(keyStorePassword)) {
                    throw new IllegalArgumentException("Keystore password may not be blank");
                }

                KeyManagerFactory kmf;
                try {
                    kmf = KeyManagerFactory.getInstance("PKIX");
                } catch (NoSuchAlgorithmException ex) {
                    kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                }

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Used algorithm for key manager factory: {}", kmf.getAlgorithm());
                }

                kmf.init(keyStore, keyStorePassword.toCharArray());
                keyManagers = kmf.getKeyManagers();
            } else {
                LOGGER.info("No keystore will be used for SSL context");
            }

            context.init(keyManagers, trustManagers, new SecureRandom());
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | KeyManagementException e) {
            throw new RuntimeException("Could not create SSL context instance", e);
        }

        return context;
    }
}
