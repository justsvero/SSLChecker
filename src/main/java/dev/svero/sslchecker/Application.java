package dev.svero.sslchecker;

import dev.svero.tools.CertificateUtils;
import dev.svero.tools.KeyStoreUtils;
import dev.svero.tools.SSLUtils;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

/**
 * Implements the entry point for the application.
 *
 * @author Sven Roeseler
 */
public class Application {
    private static final Logger LOGGER = LoggerFactory.getLogger(Application.class);

    /**
     * Entry point.
     *
     * @param args String array with command-line arguments
     */
    public static void main(String[] args) {
        Application application = new Application();

        try {
            application.run(args);
        } catch (Exception ex) {
            LOGGER.error("An error occurred", ex);
        }
    }

    private final CertificateUtils certificateUtils = new CertificateUtils();
    private final KeyStoreUtils keyStoreUtils = new KeyStoreUtils(certificateUtils);
    private final SSLUtils sslUtils = new SSLUtils();

    /**
     * Defines the available command-line options.
     *
     * @return Options instance
     */
    private Options createOptions() {
        Options options = new Options();

        options.addOption(null, "certs", true, "File with certificates (PEM)");
        options.addOption(null, "trustStore", true, "Trust store file");
        options.addOption(null, "trustStorePassword", true, "Trust store password");

        options.addOption(null, "keyStore", true, "Key store file");
        options.addOption(null, "keyStorePassword", true, "Key store password");

        options.addOption(null, "serverName", true, "Server name");
        options.addOption(null, "port", true, "Port");

        return options;
    }

    /**
     * Runs the application logic.
     *
     * @param args String array with command-line arguments
     * @throws ParseException If the command-line arguments could not be parsed successfully
     */
    private void run(String[] args) throws ParseException, KeyStoreException {
        final Options options = createOptions();
        final CommandLine cmd = DefaultParser.builder().build().parse(options, args);

        KeyStore trustStore = null;
        if (cmd.hasOption("certs")) {
            final String caCertsFilename = cmd.getOptionValue("certs");
            if (StringUtils.isBlank(caCertsFilename)) {
                LOGGER.error("The parameter \"certs\" has no valid value");
                return;
            }

            X509Certificate[] certificates = certificateUtils.importCertificates(Path.of(caCertsFilename));
            if (certificates.length == 0) {
                LOGGER.warn("No certificates found in {} - using default JVM trust store", caCertsFilename);
            } else {
                trustStore = keyStoreUtils.createKeyStore(certificates);
            }
        } else if (cmd.hasOption("trustStore")) {
            if (!cmd.hasOption("trustStorePassword")) {
                LOGGER.error("You need to specify the password for the trust store");
                return;
            }

            final String trustStoreFilename = cmd.getOptionValue("trustStore");
            final String trustStorePassword = cmd.getOptionValue("trustStorePassword");
            if (StringUtils.isAnyBlank(trustStoreFilename, trustStorePassword)) {
                LOGGER.error("Either the specified trust store filename or the trust store password are invalid");
                return;
            }

            LOGGER.debug("Using trust store {}", trustStoreFilename);

            trustStore = keyStoreUtils.loadKeyStore(trustStoreFilename, trustStorePassword);
        }

        KeyStore keyStore = null;
        String keyStorePassword = null;

        if (cmd.hasOption("keyStore")) {
            if (!cmd.hasOption("keyStorePassword")) {
                LOGGER.error("You need to specified a key store password");
                return;
            }

            final String keyStoreFilename = cmd.getOptionValue("keyStore");
            keyStorePassword = cmd.getOptionValue("keyStorePassword");
            if (StringUtils.isAnyBlank(keyStoreFilename, keyStorePassword)) {
                LOGGER.error("Either the specified key store filename or the key store password are invalid");
                return;
            }

            keyStore = keyStoreUtils.loadKeyStore(keyStoreFilename, keyStorePassword);
        }

        SSLContext context = sslUtils.createSSLContext(trustStore, keyStore, keyStorePassword);
        LOGGER.debug("Protocol: {}", context.getProtocol());
    }
}
