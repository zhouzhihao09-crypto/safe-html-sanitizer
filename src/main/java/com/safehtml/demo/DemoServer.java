package com.safehtml.demo;

import com.safehtml.SafeHtmlSanitizer;
import com.safehtml.SanitizationPolicy;
import com.safehtml.SanitizationResult;
import com.safehtml.SecurityReport;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * A minimal HTTP server that demonstrates the SafeHTML sanitizer in a browser.
 *
 * <p>This demo is for educational/portfolio purposes only. It is not designed
 * for production deployment. The server uses Java's built-in HTTP server
 * ({@code com.sun.net.httpserver}) so no additional dependencies are required.</p>
 *
 * <p>Routes:</p>
 * <ul>
 *   <li>{@code GET /}           &ndash; serves the demo UI (index.html)</li>
 *   <li>{@code POST /sanitize}  &ndash; sanitizes HTML, returns JSON</li>
 * </ul>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * DemoServer server = new DemoServer(8080);
 * server.start();
 * }</pre>
 */
public class DemoServer {

    private static final int DEFAULT_PORT = 8080;
    private static final int MAX_REQUEST_SIZE = 1_048_576;
    private static final int MAX_BODY_BYTES = MAX_REQUEST_SIZE;
    private static final SafeHtmlSanitizer SANITIZER =
            new SafeHtmlSanitizer(SanitizationPolicy.getDefault());

    private final HttpServer server;
    private final int port;

    /**
     * Creates and starts a demo server on port 8080.
     */
    public DemoServer() {
        this(DEFAULT_PORT);
    }

    /**
     * Creates a demo server on the specified port. The server is not
     * started until {@link #start()} is called.
     *
     * @param port the TCP port to listen on; 0 selects an ephemeral port
     */
    public DemoServer(int port) {
        int actualPort = port;
        try {
            this.server = HttpServer.create(new InetSocketAddress(actualPort), 0);
            actualPort = server.getAddress().getPort();
            server.createContext("/", new IndexHandler());
            server.createContext("/sanitize", new SanitizeHandler(SANITIZER));
            server.setExecutor(null);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create demo server on port " + port, e);
        }
        this.port = actualPort;
    }

    /**
     * Starts the HTTP server on its configured port.
     */
    public void start() {
        server.start();
    }

    /**
     * Stops the HTTP server.
     */
    public void stop() {
        server.stop(0);
    }

    /**
     * @return the actual port the server is listening on
     */
    public int getPort() {
        return port;
    }

    private static byte[] loadResource(String path) {
        InputStream is = DemoServer.class.getClassLoader().getResourceAsStream(path);
        if (is == null) {
            return ("Resource not found: " + path).getBytes(StandardCharsets.UTF_8);
        }
        try {
            return is.readAllBytes();
        } catch (IOException e) {
            return ("Error reading resource: " + e.getMessage()).getBytes(StandardCharsets.UTF_8);
        }
    }

    private static void sendText(HttpExchange exchange, String response,
                                 String contentType) throws IOException {
        byte[] data = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", contentType);
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(data);
        }
    }

    private static void sendError(HttpExchange exchange, int statusCode,
                                  String message) throws IOException {
        exchange.sendResponseHeaders(statusCode, 0);
        exchange.getResponseBody().close();
    }

    /**
     * Serves the demo index.html for all GET requests to {@code /}.
     */
    static class IndexHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }
            byte[] data = loadResource("demo/index.html");
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, data.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(data);
            }
        }
    }

    /**
     * Accepts a POST with an HTML body and returns a JSON object containing
     * the sanitized HTML and the security report.
     */
    static class SanitizeHandler implements HttpHandler {
        private final SafeHtmlSanitizer sanitizer;

        SanitizeHandler(SafeHtmlSanitizer sanitizer) {
            this.sanitizer = sanitizer;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }

            try {
                String body = readLimitedRequestBody(exchange);

                SanitizationResult result = sanitizer.sanitize(body);
                String json = buildJsonResponse(result);
                sendText(exchange, json, "application/json; charset=utf-8");
            } catch (PayloadTooLargeException e) {
                sendError(exchange, 413, "Payload too large");
            } catch (Exception e) {
                sendText(exchange,
                        "{\"error\":\"Internal server error\"}",
                        "application/json; charset=utf-8");
            }
        }

        private static String readLimitedRequestBody(HttpExchange exchange)
                throws IOException, PayloadTooLargeException {
            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int total = 0;
            int read;
            while ((read = is.read(chunk)) != -1) {
                total += read;
                if (total > MAX_BODY_BYTES) {
                    throw new PayloadTooLargeException();
                }
                buffer.write(chunk, 0, read);
            }
            return buffer.toString(StandardCharsets.UTF_8.name());
        }

        private String buildJsonResponse(SanitizationResult result) {
            SecurityReport report = result.report();
            StringBuilder sb = new StringBuilder(256);
            sb.append("{\n");
            sb.append("  \"sanitizedHtml\": ").append(jsonEscape(result.html())).append(",\n");
            sb.append("  \"wasModified\": ").append(result.wasModified()).append(",\n");
            sb.append("  \"report\": {\n");
            sb.append("    \"totalModifications\": ").append(report.totalModifications()).append(",\n");
            sb.append("    \"isClean\": ").append(report.isClean()).append(",\n");

            appendJsonArray(sb, "removedElements", report.removedElements(), e ->
                    "{\"tagName\": " + jsonEscape(e.tagName()) +
                    ", \"parentName\": " + jsonEscape(e.parentName()) + "}");

            appendJsonArray(sb, "removedAttributes", report.removedAttributes(), a ->
                    "{\"attrName\": " + jsonEscape(a.attrName()) +
                    ", \"elementName\": " + jsonEscape(a.elementName()) + "}");

            appendJsonArray(sb, "blockedUrls", report.blockedUrls(), u ->
                    "{\"url\": " + jsonEscape(u.url()) +
                    ", \"attrName\": " + jsonEscape(u.attrName()) +
                    ", \"elementName\": " + jsonEscape(u.elementName()) +
                    ", \"blockedScheme\": " + jsonEscape(u.blockedScheme()) + "}");

            appendJsonArray(sb, "removedComments", report.removedComments(), c ->
                    jsonEscape(c.content()));

            sb.append("  }\n");
            sb.append("}\n");
            return sb.toString();
        }

        private <T> void appendJsonArray(StringBuilder sb, String name,
                                         List<T> items, java.util.function.Function<T, String> mapper) {
            sb.append("    \"").append(name).append("\": [");
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\n      ").append(mapper.apply(items.get(i)));
            }
            if (!items.isEmpty()) sb.append("\n    ");
            sb.append("],\n");
        }

        /**
         * Escapes a string for inclusion as a JSON string literal (including
         * the surrounding quotes).
         */
        private String jsonEscape(String s) {
            if (s == null) return "null";
            StringBuilder sb = new StringBuilder(s.length() + 2);
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"':  sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n");  break;
                    case '\r': sb.append("\\r");  break;
                    case '\t': sb.append("\\t");  break;
                    case '\b': sb.append("\\b");  break;
                    case '\f': sb.append("\\f");  break;
                    default:
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                }
            }
            sb.append('"');
            return sb.toString();
        }
    }

    /**
     * Entry point — starts the demo server.
     *
     * @param args optional first argument is the port number
     */
    public static void main(String[] args) {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        DemoServer server = new DemoServer(port);
        server.start();
        System.out.println("SafeHTML Demo running at http://localhost:" + server.getPort() + "/");
        System.out.println("Press Ctrl+C to stop.");
    }

    static class PayloadTooLargeException extends Exception {
    }
}
