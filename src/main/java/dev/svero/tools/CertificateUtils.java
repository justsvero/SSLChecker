package dev.svero.tools;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Implements methods for handling X.509 certificates.
 *
 * @author Sven Roeseler
 */
public class CertificateUtils {
    /**
     * Reads one or more X.509 certificates from the specified PEM file.
     *
     * @param certificatesFile File with certificates in PEM format
     * @return Array with found certificates
     */
    public X509Certificate[] importCertificates(Path certificatesFile) {
        Objects.requireNonNull(certificatesFile);

        if (!Files.exists(certificatesFile)) {
            throw new IllegalArgumentException("File not found: " + certificatesFile);
        }

        List<X509Certificate> certificates = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(certificatesFile.toFile()))) {
            String line = reader.readLine();
            while (line != null && !line.contains("BEGIN CERTIFICATE")) {
                line = reader.readLine();
            }

            if (line == null || !line.contains("BEGIN CERTIFICATE")) {
                throw new RuntimeException("The specified file does not contain a valid certificate in PEM format");
            }

            final CertificateFactory factory = CertificateFactory.getInstance("X.509");

            StringBuilder sb = new StringBuilder();
            while (line != null) {
                if (line.contains("END CERTIFICATE")) {
                    String hexString = sb.toString();
                    final byte[] bytes = Base64.getDecoder().decode(hexString);

                    Certificate certificate = factory.generateCertificate(new ByteArrayInputStream(bytes));
                    if (certificate instanceof X509Certificate x509Certificate) {
                        certificates.add(x509Certificate);
                    }

                    sb = new StringBuilder();
                } else if (!line.startsWith("----")) {
                    sb.append(line);
                }

                line = reader.readLine();
            }
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }

        return certificates.toArray(new X509Certificate[0]);
    }
}
