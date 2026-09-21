package com.safehtml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import static org.junit.jupiter.api.Assertions.*;

class SafeHtmlSanitizerTest {

    private SafeHtmlSanitizer sanitizer;
    private SanitizationPolicy defaultPolicy;

    @BeforeEach
    void setUp() {
        defaultPolicy = SanitizationPolicy.getDefault();
        sanitizer = new SafeHtmlSanitizer(defaultPolicy);
    }

    @Nested
    @DisplayName("Basic sanitization")
    class BasicSanitization {

        @Test @DisplayName("Normal safe HTML remains intact")
        void safeHtmlIntact() {
            String input = "<p>Hello <strong>world</strong></p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("<p>"));
            assertTrue(result.html().contains("<strong>world</strong>"));
            assertFalse(result.wasModified());
        }

        @Test @DisplayName("<script> is removed")
        void scriptRemoved() {
            String input = "<p>Hello</p><script>alert(1)</script>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("<script"));
            assertFalse(result.html().contains("alert(1)"));
            assertTrue(result.wasModified());
        }

        @Test @DisplayName("Event handler onclick is removed")
        void onclickRemoved() {
            String input = "<p onclick=\"alert(1)\">Hello</p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().toLowerCase().contains("onclick"));
            assertTrue(result.report().removedAttributes().stream()
                    .anyMatch(a -> a.attrName().equals("onclick")));
        }

        @Test @DisplayName("Event handler onerror is removed")
        void onerrorRemoved() {
            String input = "<img src=\"x\" onerror=\"alert(1)\">";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().toLowerCase().contains("onerror"));
        }

        @Test @DisplayName("javascript: URL in href is removed")
        void javascriptUrlRemoved() {
            String input = "<a href=\"javascript:alert(1)\">click</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("javascript"));
            assertFalse(result.html().contains("alert(1)"));
            assertTrue(result.report().blockedUrls().stream()
                    .anyMatch(u -> u.url().contains("javascript")));
        }

        @Test @DisplayName("vbscript: URL in href is removed")
        void vbscriptUrlRemoved() {
            String input = "<a href=\"vbscript:alert(1)\">click</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("vbscript"));
            assertTrue(result.wasModified());
        }

        @Test @DisplayName("data: URL in href is rejected")
        void dataUrlRejected() {
            String input = "<a href=\"data:text/html,<script>alert(1)</script>\">click</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("data:"));
        }

        @Test @DisplayName("https URL is allowed")
        void httpsUrlAllowed() {
            String input = "<a href=\"https://example.com\">safe link</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("href=\"https://example.com\""));
            assertTrue(result.html().contains("safe link"));
        }

        @Test @DisplayName("http URL is allowed")
        void httpUrlAllowed() {
            String input = "<a href=\"http://example.com\">safe link</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("href=\"http://example.com\""));
        }

        @Test @DisplayName("Disallowed tags are removed (unwrap keeps content)")
        void disallowedTagsRemoved() {
            String input = "<div><p>Hello</p></div>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("<div"));
            assertTrue(result.html().contains("<p>"));
            assertTrue(result.html().contains("Hello"));
        }

        @Test @DisplayName("Disallowed attributes are removed")
        void disallowedAttributesRemoved() {
            String input = "<p style=\"color: red;\">Hello</p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("style"));
            assertTrue(result.html().contains("Hello"));
            assertTrue(result.report().removedAttributes().stream()
                    .anyMatch(a -> a.attrName().equals("style")));
        }

        @Test @DisplayName("Nested malicious HTML is handled")
        void nestedMaliciousHtml() {
            String input = "<div><p onclick=\"alert(1)\"><script>alert(2)</script>Hello</p></div>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("<script"));
            assertFalse(result.html().toLowerCase().contains("onclick"));
            assertTrue(result.html().contains("Hello"));
        }

        @Test @DisplayName("Malformed HTML is handled safely")
        void malformedHtmlHandled() {
            String input = "<p><strong>Unclosed</p></strong>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertNotNull(result.html());
            assertDoesNotThrow(() -> result.html());
        }

        @Test @DisplayName("Multiple malicious elements are handled")
        void multipleMaliciousElements() {
            String input = "<script>alert(1)</script>" +
                    "<p onclick=\"steal()\">text</p>" +
                    "<iframe src=\"javascript:alert(1)\"></iframe>" +
                    "<a href=\"vbscript:alert(1)\">link</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("<script"));
            assertFalse(result.html().contains("<iframe"));
            assertFalse(result.html().toLowerCase().contains("onclick"));
            assertFalse(result.html().contains("javascript"));
            assertFalse(result.html().contains("vbscript"));
            assertTrue(result.html().contains("text"));
            assertTrue(result.html().contains("link"));
        }

        @Test @DisplayName("Custom policy works")
        void customPolicyWorks() {
            SanitizationPolicy policy = SanitizationPolicy.builder()
                    .allowElement("p")
                    .allowElement("div")
                    .allowAttribute("class", "*")
                    .allowUrl("href", "a")
                    .allowUrlProtocol("https")
                    .build();
            SafeHtmlSanitizer custom = new SafeHtmlSanitizer(policy);
            String input = "<div class=\"container\"><p style=\"x\" onclick=\"y\">text</p></div>";
            SanitizationResult result = custom.sanitize(input);
            assertTrue(result.html().contains("<div"));
            assertTrue(result.html().contains("class=\"container\""));
            assertFalse(result.html().contains("style"));
            assertFalse(result.html().toLowerCase().contains("onclick"));
            assertTrue(result.html().contains("text"));
        }

        @Test @DisplayName("Empty input works")
        void emptyInput() {
            SanitizationResult result = sanitizer.sanitize("");
            assertEquals("", result.html());
            assertFalse(result.wasModified());
        }

        @Test @DisplayName("Null input works")
        void nullInput() {
            SanitizationResult result = sanitizer.sanitize(null);
            assertEquals("", result.html());
        }

        @Test @DisplayName("Plain text works")
        void plainText() {
            String input = "Just some plain text without HTML";
            SanitizationResult result = sanitizer.sanitize(input);
            assertEquals("Just some plain text without HTML", result.html());
            assertFalse(result.wasModified());
        }

        @Test @DisplayName("Comments are removed")
        void commentsRemoved() {
            String input = "<!-- secret comment --><p>Hello</p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("<!--"));
            assertFalse(result.html().contains("secret comment"));
            assertTrue(result.report().removedComments().stream()
                    .anyMatch(c -> c.content().contains("secret comment")));
        }

        @Test @DisplayName("Case variations of javascript: are handled")
        void caseVariationsJavascript() {
            String input = "<a href=\"JAVASCRIPT:alert(1)\">x</a>" +
                    "<a href=\"javascript:alert(2)\">y</a>" +
                    "<a href=\"JaVaScRiPt:alert(3)\">z</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().toLowerCase().contains("javascript:"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("Whitespace and obfuscation around URLs is handled")
        void obfuscatedUrls() {
            String input = "<a href=\"  javascript:alert(1)  \">x</a>" +
                    "<a href=\"java\tscript:alert(2)\">y</a>" +
                    "<a href=\"java\nscript:alert(3)\">z</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("javascript:"));
            assertFalse(result.html().contains("alert"));
            assertTrue(result.wasModified());
        }

        @Test @DisplayName("HTML entity obfuscation in URLs is handled")
        void entityObfuscationInUrls() {
            String input = "<a href=\"&#106;avascript:alert(1)\">x</a>" +
                    "<a href=\"javascript&colon;alert(2)\">y</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertFalse(result.html().contains("javascript:"));
            assertFalse(result.html().contains("alert"));
        }
    }

    @Nested
    @DisplayName("XSS payloads")
    class XssPayloads {

        @Test @DisplayName("Standard script injection")
        void standardScriptInjection() {
            String payload = "<script>alert('XSS')</script>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("<script"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("Img onerror injection")
        void imgOnerror() {
            String payload = "<img src=x onerror=alert('XSS')>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("onerror"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("SVG onload injection")
        void svgOnload() {
            String payload = "<svg onload=alert('XSS')>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("onload"));
            assertFalse(result.html().contains("alert"));
            assertFalse(result.html().contains("<svg"));
        }

        @Test @DisplayName("Iframe injection")
        void iframeInjection() {
            String payload = "<iframe src=\"javascript:alert('XSS')\"></iframe>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("<iframe"));
            assertFalse(result.html().contains("javascript"));
        }

        @Test @DisplayName("Anchor javascript: URL injection")
        void anchorJavascriptUrl() {
            String payload = "<a href=\"javascript:alert('XSS')\">click</a>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("javascript"));
            assertTrue(result.html().contains("click"));
            assertTrue(result.html().contains("<a"));
        }

        @Test @DisplayName("Form action injection")
        void formActionInjection() {
            String payload = "<form action=\"javascript:alert('XSS')\"><input type=submit></form>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("javascript"));
            assertFalse(result.html().toLowerCase().contains("action"));
        }

        @Test @DisplayName("Object data injection")
        void objectDataInjection() {
            String payload = "<object data=\"javascript:alert('XSS')\"></object>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("javascript"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("Nested script in noscript")
        void nestedScriptInNoscript() {
            String payload = "<noscript><p><script>alert('XSS')</script></p></noscript>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("<script"));
            assertFalse(result.html().contains("alert"));
            assertFalse(result.html().contains("noscript"));
        }

        @Test @DisplayName("Script with broken tags")
        void brokenScriptTags() {
            String payload = "<scr<script>ipt>alert('XSS')</scr</script>ipt>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("javascript"));
            assertFalse(result.html().contains("<script"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("Img src with javascript protocol")
        void imgSrcJavascript() {
            String payload = "<img src=\"javascript:alert('XSS')\">";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("javascript"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("SVG with embedded script")
        void svgWithScript() {
            String payload = "<svg><script>alert('XSS')</script></svg>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("<svg"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("Multiple event handlers")
        void multipleEventHandlers() {
            String payload = "<p onclick=\"a()\" onerror=\"b()\" onload=\"c()\" onmouseover=\"d()\">text</p>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().toLowerCase().contains("onclick"));
            assertFalse(result.html().toLowerCase().contains("onerror"));
            assertFalse(result.html().toLowerCase().contains("onload"));
            assertFalse(result.html().toLowerCase().contains("onmouseover"));
            assertEquals(4, result.report().removedAttributes().size());
        }

        @Test @DisplayName("SVG animate with onload")
        void svgAnimateOnload() {
            String payload = "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("<svg"));
            assertFalse(result.html().toLowerCase().contains("onbegin"));
            assertFalse(result.html().contains("alert"));
        }

        @Test @DisplayName("Tab in javascript URL scheme")
        void tabInJavascriptScheme() {
            String payload = "<a href=\"java\tscript:alert(1)\">x</a>";
            SanitizationResult result = sanitizer.sanitize(payload);
            assertFalse(result.html().contains("alert(1)"));
        }
    }

    @Nested
    @DisplayName("Report functionality")
    class ReportFunctionality {

        @Test @DisplayName("Report tracks removed elements")
        void reportTracksRemovedElements() {
            String input = "<script>alert(1)</script><p>safe</p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.report().removedElements().stream()
                    .anyMatch(e -> e.tagName().equals("script")));
        }

        @Test @DisplayName("Report tracks removed attributes")
        void reportTracksRemovedAttributes() {
            String input = "<p onclick=\"alert(1)\">text</p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.report().removedAttributes().stream()
                    .anyMatch(a -> a.attrName().equals("onclick")));
            assertEquals(1, result.report().totalModifications());
        }

        @Test @DisplayName("Report tracks blocked URLs")
        void reportTracksBlockedUrls() {
            String input = "<a href=\"javascript:alert(1)\">x</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.report().blockedUrls().stream()
                    .anyMatch(u -> u.url().contains("javascript")));
        }

        @Test @DisplayName("Report total modifications is correct")
        void reportTotalModifications() {
            String input = "<script>alert(1)</script>" +
                    "<p onclick='x()' style='y'>text</p>" +
                    "<a href='javascript:alert(2)'>link</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.report().totalModifications() >= 4);
        }

        @Test @DisplayName("Clean HTML produces clean report")
        void cleanHtmlReport() {
            String input = "<p>Hello <strong>world</strong></p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.report().isClean());
            assertEquals(0, result.report().totalModifications());
        }
    }

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test @DisplayName("Deeply nested safe content is preserved")
        void deeplyNestedSafe() {
            String input = "<ul><li><p>Hello</p></li></ul>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("Hello"));
            assertTrue(result.html().contains("<li>"));
            assertTrue(result.html().contains("<ul>"));
        }

        @Test @DisplayName("Mixed safe and unsafe attributes")
        void mixedSafeAndUnsafeAttrs() {
            String input = "<p class=\"safe\" onclick=\"evil()\" title=\"info\">text</p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("class=\"safe\""));
            assertTrue(result.html().contains("title=\"info\""));
            assertFalse(result.html().toLowerCase().contains("onclick"));
        }

        @Test @DisplayName("Href with spaces is trimmed")
        void hrefWithSpaces() {
            String input = "<a href=\"  https://example.com  \">link</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("https://example.com"));
        }

        @Test @DisplayName("mailto link is preserved")
        void mailtoPreserved() {
            String input = "<a href=\"mailto:test@example.com\">email</a>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("mailto:test@example.com"));
            assertTrue(result.html().contains("email"));
        }

        @Test @DisplayName("Self-closing tags work")
        void selfClosingTags() {
            String input = "<p>Hello<br>World</p>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("Hello"));
            assertTrue(result.html().contains("World"));
            assertTrue(result.html().contains("<br"));
        }

        @Test @DisplayName("Heading levels preserved")
        void headingsPreserved() {
            String input = "<h1>Title</h1><h2>Subtitle</h2>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("<h1>"));
            assertTrue(result.html().contains("Title"));
            assertTrue(result.html().contains("<h2>"));
        }

        @Test @DisplayName("Code and preformatted text preserved")
        void codePrePreserved() {
            String input = "<pre><code>System.out.println(\"hello\");</code></pre>";
            SanitizationResult result = sanitizer.sanitize(input);
            assertTrue(result.html().contains("System.out.println"));
        }
    }
}
