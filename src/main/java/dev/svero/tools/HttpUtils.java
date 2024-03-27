package dev.svero.tools;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Implements methods for handling HTTP requests.
 * 
 * @author Sven Roeseler
 */
public class HttpUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpUtils.class);

    private SSLContext sslContext;

    /**
     * Creates a new instance.
     */
    public HttpUtils() {
        this(null);
    }

    /**
     * Creates a new instance using the specified SSL context.
     *
     * @param sslContext SSL context.
     */
    public HttpUtils(final SSLContext sslContext) {
        this.sslContext = sslContext;
    }
    
    /**
     * Sets the SSL context to the specified value.
     * 
     * @param sslContext New value for SSL context
     */
    public void setSSLContext(final SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    /**
     * Gets the SSL context if set. Otherwise it returns null.
     * 
     * @return SSL context or null
     */
    public SSLContext getSSLContext() {
        return sslContext;
    }

    /**
     * Creates a HTTP client. If a SSL context is set it is used here.
     *
     * @return HTTP client.
     */
    private HttpClient createHttpClient() {
        HttpClient client;

        if (sslContext == null) {
            client = HttpClient.newBuilder().build();
        } else {
            client = HttpClient.newBuilder().sslContext(sslContext).build();
        }

        return client;
    }

    /**
     * Performs the specified request and returns the response as string if the status code was 200.
     *
     * @param request Request to perform
     * @return Response body as string
     * @throws IOException          If an I/O error happened
     * @throws InterruptedException If the request was interrupted before the response was received
     */
    protected String processRequestWithTextResponse(HttpRequest request) throws IOException, InterruptedException {
        if (request == null) {
            throw new IllegalArgumentException("request may not be null");
        }

        HttpClient client = createHttpClient();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        String result;

        if (response.statusCode() == 200) {
            result = response.body();
        } else {
            LOGGER.error("Unexpected response received:\n* Status Code: {}\n* Headers: {}\n* Body: {}",
                    response.statusCode(), response.headers().toString(), response.body());

            throw new RuntimeException("Unexpected status code received while processing POST request");
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Raw result: {}", result);
        }

        return result;
    }

    /**
     * Performs a GET request.
     *
     * @param url Target URL for the request.
     * @return The server response as string.
     * @throws IOException          If an I/O error occurred.
     * @throws InterruptedException If the request was interrupted before the response was received.
     */
    public String getRequest(final String url) throws IOException, InterruptedException {
        if (StringUtils.isBlank(url)) {
            throw new IllegalArgumentException("url may not be blank");
        }

        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();

        return processRequestWithTextResponse(request);
    }
}
