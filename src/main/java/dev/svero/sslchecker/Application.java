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

        options.addOption(null, "CAcerts", true, "Path and name of the CA certificates file");

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
        if (cmd.hasOption("CAcerts")) {
            final String caCertsFilename = cmd.getOptionValue("CAcerts");
            if (StringUtils.isBlank(caCertsFilename)) {
                LOGGER.error("The parameters CAcerts has no valid value");
                throw new IllegalArgumentException("The specified value for CAcerts may not be blank");
            }

            X509Certificate[] certificates = certificateUtils.importCertificates(Path.of(caCertsFilename));
            if (certificates.length == 0) {
                LOGGER.warn("No certificates found in {}", caCertsFilename);
            } else {
                trustStore = keyStoreUtils.createKeyStore(certificates);
            }
        }

        SSLContext context = sslUtils.createSSLContext(trustStore);
        LOGGER.debug("Protocol: {}", context.getProtocol());
    }
}
