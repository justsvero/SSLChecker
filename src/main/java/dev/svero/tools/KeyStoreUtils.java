package dev.svero.tools;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Implements methods for handling keystores.
 *
 * @author Sven Roeseler
 */
public class KeyStoreUtils {
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
}
