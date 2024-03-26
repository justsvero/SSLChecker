package dev.svero.tools;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Implements methods for handling keystores.
 *
 * @author Sven Roeseler
 */
public class KeyStoreUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreUtils.class);

    private final CertificateUtils certificateUtils;

    /**
     * Creates a new instance using the specified instance of CertificateUtils.
     *
     * @param certificateUtils Instance of CertificateUtils
     */
    public KeyStoreUtils(final CertificateUtils certificateUtils) {
        Objects.requireNonNull(certificateUtils);

        this.certificateUtils = certificateUtils;
    }

    /**
     * Creates a keystore using the specified array of certificates
     *
     * @param certificates Array with X.509 certificates
     * @return Created keystore
     * @throws KeyStoreException If the keystore instance in PKCS.12 format could not be loaded
     */
    public KeyStore createKeyStore(X509Certificate[] certificates) throws KeyStoreException {
        Objects.requireNonNull(certificates);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");

        try {
            trustStore.load(null);

            if (certificates.length > 0) {
                int i = 0;
                for (X509Certificate certificate : certificates) {
                    i++;
                    trustStore.setCertificateEntry(String.valueOf(i), certificate);
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException("Could not create a keystore", ex);
        }

        return trustStore;
    }

    /**
     * Creates a keystore using the specified file with X.509 certificates in PEM format.
     *
     * @param certificateFile File with one or more X.509 certificates in PEM format.
     * @return Created keystore with the certificates from the specified file
     * @throws KeyStoreException If no keystore in PKCS.12 format could be loaded.
     */
    public KeyStore createKeyStoreFromCertificateFile(Path certificateFile) throws KeyStoreException {
        X509Certificate[] certificates = certificateUtils.importCertificates(certificateFile);
        return createKeyStore(certificates);
    }

    /**
     * Tries to load a key store using the specified format.
     *
     * @param keyStoreFilename Filename of the key store
     * @param keyStorePassword Password for accessing the key store
     * @param keyStoreType Type (JKS, PKCS.12)
     * @return Created KeyStore instance
     */
    public KeyStore loadKeyStore(final String keyStoreFilename, final String keyStorePassword, final String keyStoreType) {
        if (StringUtils.isBlank(keyStoreFilename)) {
            throw new IllegalArgumentException("keyStoreFilename should not be blank");
        }

        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("keyStorePassword should not be blank");
        }

        if (StringUtils.isBlank(keyStoreType)) {
            return loadKeyStore(keyStoreFilename, keyStorePassword);
        }

        KeyStore keyStore;

        try {
            keyStore = KeyStore.getInstance(keyStoreType);

            if (Files.notExists(Path.of(keyStoreFilename))) {
                throw new IllegalArgumentException("The specified key store file \"" + keyStoreFilename
                        + "\" does not exist");
            }

            LOGGER.debug("Try to load key store from {}", keyStoreFilename);

            keyStore.load(new FileInputStream(keyStoreFilename), keyStorePassword.toCharArray());
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not create a KeyStore instance", e);
        }

        return keyStore;
    }

    /**
     * Tries to load a key store using the PKCS.12 format.
     *
     * @param keyStoreFilename Filename of the key store
     * @param keyStorePassword Password for accessing the key store
     * @return Created KeyStore instance
     */
    public KeyStore loadKeyStore(final String keyStoreFilename, final String keyStorePassword) {
        return loadKeyStore(keyStoreFilename, keyStorePassword, "PKCS12");
    }
}
