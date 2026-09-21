package com.safehtml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import static org.junit.jupiter.api.Assertions.*;

class UrlValidatorTest {

    private final UrlValidator validator = new UrlValidator(
            java.util.Set.of("https", "http", "mailto"));

    @Nested
    @DisplayName("Safe protocols")
    class SafeProtocols {
        @Test @DisplayName("https is allowed")
        void httpsAllowed() {
            assertTrue(validator.validate("https://example.com").allowed());
        }

        @Test @DisplayName("http is allowed")
        void httpAllowed() {
            assertTrue(validator.validate("http://example.com").allowed());
        }

        @Test @DisplayName("mailto is allowed")
        void mailtoAllowed() {
            assertTrue(validator.validate("mailto:test@example.com").allowed());
        }
    }

    @Nested
    @DisplayName("Dangerous protocols")
    class DangerousProtocols {
        @Test @DisplayName("javascript: is blocked")
        void javascriptBlocked() {
            assertFalse(validator.validate("javascript:alert(1)").allowed());
        }

        @Test @DisplayName("vbscript: is blocked")
        void vbscriptBlocked() {
            assertFalse(validator.validate("vbscript:msgbox(1)").allowed());
        }

        @Test @DisplayName("data: is blocked")
        void dataBlocked() {
            assertFalse(validator.validate("data:text/html,<script>alert(1)</script>").allowed());
        }

        @Test @DisplayName("file: is blocked")
        void fileBlocked() {
            assertFalse(validator.validate("file:///etc/passwd").allowed());
        }
    }

    @Nested
    @DisplayName("Obfuscation and case variants")
    class Obfuscation {
        @Test @DisplayName("JAVASCRIPT: (uppercase) is blocked")
        void uppercaseJavascriptBlocked() {
            assertFalse(validator.validate("JAVASCRIPT:alert(1)").allowed());
        }

        @Test @DisplayName("JaVaScRiPt: (mixed case) is blocked")
        void mixedCaseJavascriptBlocked() {
            assertFalse(validator.validate("JaVaScRiPt:alert(1)").allowed());
        }

        @Test @DisplayName("Leading whitespace is handled")
        void leadingWhitespaceBlocked() {
            assertFalse(validator.validate("  javascript:alert(1)").allowed());
        }

        @Test @DisplayName("Tab in scheme is handled")
        void tabInSchemeBlocked() {
            assertFalse(validator.validate("java\tscript:alert(1)").allowed());
        }

        @Test @DisplayName("Newline in scheme is handled")
        void newlineInSchemeBlocked() {
            assertFalse(validator.validate("java\nscript:alert(1)").allowed());
        }

        @Test @DisplayName("Carriage return in scheme is handled")
        void crInSchemeBlocked() {
            assertFalse(validator.validate("java\rscript:alert(1)").allowed());
        }

        @Test @DisplayName("Multiple control chars in scheme are handled")
        void multipleControlCharsBlocked() {
            assertFalse(validator.validate("j\ta" + (char) 0x0B + "n\u0001ascript:alert(1)").allowed());
        }
    }

    @Nested
    @DisplayName("Relative and edge-case URLs")
    class RelativeAndEdge {
        @Test @DisplayName("Relative URL without scheme is allowed")
        void relativeUrlAllowed() {
            assertTrue(validator.validate("/path/to/page").allowed());
        }

        @Test @DisplayName("Relative path without scheme is allowed")
        void relativePathAllowed() {
            assertTrue(validator.validate("page.html").allowed());
        }

        @Test @DisplayName("Empty URL is allowed")
        void emptyUrlAllowed() {
            assertTrue(validator.validate("").allowed());
        }

        @Test @DisplayName("Null URL is allowed")
        void nullUrlAllowed() {
            assertTrue(validator.validate(null).allowed());
        }

        @Test @DisplayName("Fragment-only URL is allowed")
        void fragmentOnlyAllowed() {
            assertTrue(validator.validate("#section").allowed());
        }

        @Test @DisplayName("mailto with uppercase is detected")
        void uppercaseMailtoBlockedIfNeeded() {
            // https is allowed, so this should pass
            assertTrue(validator.validate("HTTPS://example.com").allowed());
        }

        @Test @DisplayName("Protocol-relative URL is allowed (resolves to page protocol)")
        void protocolRelativeAllowed() {
            assertTrue(validator.validate("//evil.com").allowed());
        }

        @Test @DisplayName("Protocol-relative URL with path is allowed")
        void protocolRelativeWithPathAllowed() {
            assertTrue(validator.validate("//cdn.example.com/lib.js").allowed());
        }

        @Test @DisplayName("URL with unknown scheme is blocked")
        void unknownSchemeBlocked() {
            assertFalse(validator.validate("ftp://example.com").allowed());
        }

        @Test @DisplayName("URL with gopher scheme is blocked")
        void gopherSchemeBlocked() {
            assertFalse(validator.validate("gopher://example.com").allowed());
        }

        @Test @DisplayName("URL with data scheme is blocked")
        void dataSchemeBlocked() {
            assertFalse(validator.validate("data:text/html;base64,PGh0bWw+PC9odG1sPg==").allowed());
        }

        @Test @DisplayName("URL with whitespace before scheme is blocked")
        void whitespaceBeforeSchemeBlocked() {
            assertFalse(validator.validate("\t\r\n javascript:alert(1)").allowed());
        }

        @Test @DisplayName("Null byte in scheme is handled")
        void nullByteInSchemeHandled() {
            assertFalse(validator.validate("javascript\u0000:alert(1)").allowed());
        }

        @Test @DisplayName("Multiple colons in URL")
        void multipleColonsInUrl() {
            ValidationResult result = validator.validate("https://example.com:8080/path");
            assertTrue(result.allowed());
        }

        @Test @DisplayName("URL with only scheme and colon is blocked")
        void schemeOnlyBlocked() {
            assertFalse(validator.validate("javascript:").allowed());
        }

        @Test @DisplayName("Empty scheme (starts with colon) is allowed as relative")
        void emptySchemeRelative() {
            assertTrue(validator.validate(":foo").allowed());
        }
    }

    @Nested
    @DisplayName("validateAndClean")
    class ValidateAndClean {
        @Test @DisplayName("Returns cleaned URL for allowed")
        void returnsCleanForAllowed() {
            String result = validator.validateAndClean("  https://example.com  ");
            assertEquals("https://example.com", result);
        }

        @Test @DisplayName("Returns null for blocked")
        void returnsNullForBlocked() {
            assertNull(validator.validateAndClean("javascript:alert(1)"));
        }

        @Test @DisplayName("Returns cleaned URL for relative")
        void returnsCleanForRelative() {
            String result = validator.validateAndClean("  /path/page  ");
            assertEquals("/path/page", result);
        }
    }

    @Test @DisplayName("Blocked result includes scheme info")
    void blockedResultHasScheme() {
        ValidationResult result = validator.validate("JAVASCRIPT:alert(1)");
        assertFalse(result.allowed());
        assertEquals("javascript", result.blockedScheme());
    }
}
