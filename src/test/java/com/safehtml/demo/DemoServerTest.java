package com.safehtml.demo;

import com.safehtml.SafeHtmlSanitizer;
import com.safehtml.SanitizationPolicy;
import com.safehtml.SanitizationResult;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

class DemoServerTest {

    private static DemoServer server;
    private static HttpClient client;
    private static String baseUrl;

    @BeforeAll
    static void setUpServer() {
        server = new DemoServer(0);
        server.start();
        client = HttpClient.newHttpClient();
        baseUrl = "http://127.0.0.1:" + server.getPort();
    }

    @AfterAll
    static void tearDownServer() {
        server.stop();
    }

    private HttpResponse<String> post(String body) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/sanitize"))
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .header("Content-Type", "text/plain")
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create(baseUrl + path))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test @DisplayName("GET / serves the demo HTML page")
    void indexPageServed() throws Exception {
        HttpResponse<String> resp = get("/");
        assertEquals(200, resp.statusCode());
        assertTrue(resp.headers().firstValue("Content-Type").orElse("").contains("text/html"));
        String html = resp.body();
        assertTrue(html.contains("SafeHTML Sanitizer Demo"));
        assertTrue(html.contains("Sanitize HTML"));
        assertTrue(html.contains("example-buttons"));
        assertTrue(html.contains("Security Report"));
    }

    @Test @DisplayName("POST /sanitize returns JSON with sanitized HTML and report")
    void sanitizeReturnsJson() throws Exception {
        HttpResponse<String> resp = post("<p>Hello <strong>world</strong></p>");
        assertEquals(200, resp.statusCode());
        assertTrue(resp.headers().firstValue("Content-Type").orElse("").contains("application/json"));
        String json = resp.body();
        assertTrue(json.contains("\"sanitizedHtml\""));
        assertTrue(json.contains("\"wasModified\""));
        assertTrue(json.contains("\"report\""));
        assertTrue(json.contains("\"totalModifications\""));
        assertTrue(json.contains("\"isClean\""));
        assertTrue(json.contains("\"removedElements\""));
        assertTrue(json.contains("\"removedAttributes\""));
        assertTrue(json.contains("\"blockedUrls\""));
        assertTrue(json.contains("\"removedComments\""));
    }

    @Test @DisplayName("Script injection is blocked in output")
    void scriptInjectionBlocked() throws Exception {
        String payload = "<p>Hello</p><script>alert('XSS')</script>"
                + "<a href=\"javascript:alert(1)\">Click</a>"
                + "<img src=\"x\" onerror=\"alert(1)\">";
        HttpResponse<String> resp = post(payload);
        assertEquals(200, resp.statusCode());
        String json = resp.body();
        assertFalse(json.contains("<script"));
        assertFalse(json.contains("alert('XSS')"));
        assertTrue(json.contains("\"wasModified\": true"));
    }

    @Test @DisplayName("javascript: URLs are blocked")
    void javascriptUrlBlocked() throws Exception {
        String payload = "<a href=\"javascript:alert(1)\">dangerous</a>";
        HttpResponse<String> resp = post(payload);
        assertEquals(200, resp.statusCode());
        String json = resp.body();
        assertFalse(json.contains("\"sanitizedHtml\": \"<a href=\""));
        assertTrue(json.contains("\"blockedScheme\": \"javascript\""));
    }

    @Test @DisplayName("Empty input is handled gracefully")
    void emptyInputHandled() throws Exception {
        HttpResponse<String> resp = post("");
        assertEquals(200, resp.statusCode());
        String json = resp.body();
        assertTrue(json.contains("\"sanitizedHtml\": \"\""));
        assertTrue(json.contains("\"isClean\": true"));
        assertTrue(json.contains("\"totalModifications\": 0"));
    }

    @Test @DisplayName("Malformed HTML does not crash the server")
    void malformedHtmlHandled() throws Exception {
        String payload = "<scr ipt>alert(1)</scr ipt><<<bad>>><img src=x onerror=alert(1)>";
        HttpResponse<String> resp = post(payload);
        assertEquals(200, resp.statusCode());
        String json = resp.body();
        assertFalse(json.contains("alert(1)"));
        assertFalse(json.contains("<script"));
    }

    @Test @DisplayName("Safe HTML passes through unchanged")
    void safeHtmlPassesThrough() throws Exception {
        String payload = "<p>Hello <strong>world</strong></p>";
        HttpResponse<String> resp = post(payload);
        assertEquals(200, resp.statusCode());
        String json = resp.body();
        assertTrue(json.contains("<p>Hello <strong>world</strong></p>"));
        assertTrue(json.contains("\"wasModified\": false"));
        assertTrue(json.contains("\"isClean\": true"));
    }

    @Test @DisplayName("Harmless HTML with event handlers is sanitized")
    void eventHandlerStripped() throws Exception {
        String payload = "<p onclick=\"alert(1)\">text</p>";
        HttpResponse<String> resp = post(payload);
        assertEquals(200, resp.statusCode());
        String json = resp.body();
        assertTrue(json.contains("\"sanitizedHtml\": \"<p>text</p>\""));
        assertTrue(json.contains("\"attrName\": \"onclick\""));
        assertTrue(json.contains("\"wasModified\": true"));
    }

    @Test @DisplayName("GET /sanitize returns 405")
    void getSanitizeReturns405() throws Exception {
        HttpResponse<String> resp = get("/sanitize");
        assertEquals(405, resp.statusCode());
    }

    @Test @DisplayName("Comments in HTML are removed and reported")
    void commentsRemovedAndReported() throws Exception {
        String payload = "<!-- secret --><!-- <script>alert(1)</script> -->";
        HttpResponse<String> resp = post(payload);
        assertEquals(200, resp.statusCode());
        String json = resp.body();
        assertFalse(json.contains("<!--"));
        assertFalse(json.contains("-->"));
        assertTrue(json.contains("\"removedComments\""));
        assertTrue(json.contains("secret"));
        assertTrue(json.contains("\"wasModified\": true"));
    }

    @Test @DisplayName("Server responds on ephemeral port")
    void serverPortIsAvailable() {
        assertTrue(server.getPort() > 0);
    }
}
