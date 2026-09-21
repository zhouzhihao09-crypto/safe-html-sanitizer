package com.safehtml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Security-invariant tests that verify mandatory protections hold
 * across hundreds of XSS attack vectors.
 *
 * <p>Every test in this class asserts that a specific dangerous pattern
 * does NOT survive sanitization with the default (conservative) policy.</p>
 */
@DisplayName("Security invariants")
class SecurityInvariantTest {

    @BeforeEach
    void checkDefaultPolicyNotAllowDangerous() {
        SanitizationPolicy p = SanitizationPolicy.getDefault();
        assertFalse(p.allowedElements().contains("script"));
        assertFalse(p.allowedElements().contains("style"));
        assertFalse(p.allowedElements().contains("iframe"));
        assertFalse(p.allowedElements().contains("svg"));
        assertFalse(p.allowedElements().contains("object"));
        assertFalse(p.allowedElements().contains("embed"));
    }

    private SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(SanitizationPolicy.getDefault());

    // ------------------------------------------------------------------
    //  A. Script injection
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "script vector: {0}")
    @ValueSource(strings = {
            "<script>alert(1)</script>",
            "<script >alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script\n>alert(1)</script>",
            "<script\t>alert(1)</script>",
            "<script\r>alert(1)</script>",
            "<script\f>alert(1)</script>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<script/src=data:,alert(1)>",
            "<script>alert(1)//</script>",
            "<!--><script>alert(1)</script>",
            "<script>alert(String.fromCharCode(88,115,115))</script>",
            "<scr ipt>alert(1)</scr ipt>",
            "<script x>alert(1)</script>",
            "<script>alert(1); <!--",
    })
    @DisplayName("No <script> survives sanitization")
    void noScriptSurvives(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.toLowerCase().contains("<script"),
                "Script tag survived in output: " + safe);
        assertFalse(safe.contains("alert(1)"),
                "JavaScript body survived in output: " + safe);
    }

    @ParameterizedTest(name = "nested script vector: {0}")
    @ValueSource(strings = {
            "<div><script>alert(1)</script></div>",
            "<p><div><script>alert(1)</script></div></p>",
            "<p>Hello<script>alert(1)</script></p>",
            "<noscript><p><script>alert(1)</script></p></noscript>",
            "<div><span><script>alert(1)</script></span></div>",
            "<p>before<script>alert(1)</script>after</p>",
    })
    @DisplayName("Nested <script> is always removed")
    void nestedScriptRemoved(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        assertFalse(result.html().toLowerCase().contains("<script"));
        assertFalse(result.html().contains("alert(1)"));
    }

    // ------------------------------------------------------------------
    //  B. Event handlers
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "event handler vector: {0}")
    @CsvSource({
            "'<p onclick=\"alert(1)\">x</p>'",
            "'<p onclick=\"alert(1)\" foo=\"bar\">x</p>'",
            "'<p ONCLICK=\"alert(1)\">x</p>'",
            "'<p OnClick=\"alert(1)\">x</p>'",
            "'<p oNcLiCk=\"alert(1)\">x</p>'",
            "'<p onerror=\"alert(1)\">x</p>'",
            "'<p ONERROR=\"alert(1)\">x</p>'",
            "'<p onload=\"alert(1)\">x</p>'",
            "'<p onload=\"alert(1)\">x</p>'",
            "'<p onmouseover=\"alert(1)\">x</p>'",
            "'<p onfocus=\"alert(1)\">x</p>'",
            "'<p onblur=\"alert(1)\">x</p>'",
            "'<p onmouseenter=\"alert(1)\">x</p>'",
            "'<p onanimationstart=\"alert(1)\">x</p>'",
            "'<p ontransitionend=\"alert(1)\">x</p>'",
            "'<p onscroll=\"alert(1)\">x</p>'",
            "'<a href=\"#\" onclick=\"alert(1)\">link</a>'",
            "'<a href=\"#\" onerror=\"alert(1)\">link</a>'",
            "'<a href=\"#\" ONLOAD=\"alert(1)\">link</a>'",
    })
    @DisplayName("No event-handler attribute survives")
    void noEventHandlerSurvives(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html().toLowerCase();
        assertFalse(safe.contains("onclick"),
                "onclick survived: " + safe);
        assertFalse(safe.contains("onerror"),
                "onerror survived: " + safe);
        assertFalse(safe.contains("onload"),
                "onload survived: " + safe);
        assertFalse(safe.contains("onmouseover"),
                "onmouseover survived: " + safe);
        assertFalse(safe.contains("onfocus"),
                "onfocus survived: " + safe);
        assertFalse(safe.contains("onmouseenter"),
                "onmouseenter survived: " + safe);
        assertFalse(safe.contains("onanimationstart"),
                "onanimationstart survived: " + safe);
        assertFalse(safe.contains("ontransitionend"),
                "ontransitionend survived: " + safe);
        assertFalse(safe.contains("onscroll"),
                "onscroll survived: " + safe);
        assertFalse(safe.contains("onblur"),
                "onblur survived: " + safe);
    }

    // ------------------------------------------------------------------
    //  C. Dangerous URL protocols
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "dangerous URL vector: {0}")
    @CsvSource({
            "'javascript:alert(1)'",
            "'JAVASCRIPT:alert(1)'",
            "'JavaScript:alert(1)'",
            "'java\tscript:alert(1)'",
            "'java\nscript:alert(1)'",
            "'java\nscript:alert(1)'",
            "'java\r\nscript:alert(1)'",
            "'  javascript:alert(1)'",
            "'javascript:alert(1)  '",
            "'java\t\r\nscript:alert(1)'",
            "'vbscript:alert(1)'",
            "'VBSCRIPT:alert(1)'",
            "'data:text/html,<script>alert(1)</script>'",
            "'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='",
            "'file:///etc/passwd'",
            "'FILE:///etc/passwd'",
            "'javascript&colon;alert(1)'",
            "'javascript&#58;alert(1)'",
            "'javascript&#x3a;alert(1)'",
            "'&#106;avascript:alert(1)'",
            "'&#x6a;avascript:alert(1)'",
            "'java script:alert(1)'"
    })
    @DisplayName("Blocked URL protocols never survive in href")
    void blockedProtocolsNeverSurvive(String url) {
        String payload = "<a href=\"" + url + "\">link</a>";
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.contains("javascript"),
                "javascript survived in: " + safe);
        assertFalse(safe.contains("JAVASCRIPT"),
                "JAVASCRIPT survived in: " + safe);
        assertFalse(safe.contains("vbscript"),
                "vbscript survived in: " + safe);
        assertFalse(safe.contains("data:"),
                "data: survived in: " + safe);
        assertFalse(safe.contains("file:"),
                "file: survived in: " + safe);
        assertFalse(safe.contains("alert"),
                "alert survived in: " + safe);
    }

    @ParameterizedTest(name = "safe URL: {0}")
    @ValueSource(strings = {
            "https://example.com",
            "http://example.com/path",
            "mailto:test@example.com",
            "/relative/path",
            "relative/path",
            "#fragment",
            "?query=1",
            ""
    })
    @DisplayName("Safe URLs are allowed in href")
    void safeUrlsAllowed(String url) {
        String payload = "<a href=\"" + url + "\">link</a>";
        SanitizationResult result = sanitizer.sanitize(payload);
        assertTrue(result.html().contains("<a"),
                "Anchor element was removed for URL: " + url);
    }

    // ------------------------------------------------------------------
    //  D. Dangerous embedded content
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "embedded content: {0}")
    @ValueSource(strings = {
            "<iframe src=\"about:blank\"></iframe>",
            "<iframe></iframe>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<object data=\"javascript:alert(1)\"></object>",
            "<embed src=\"javascript:alert(1)\">",
            "<embed src=\"data:text/html,<script>alert(1)</script>\">",
            "<frame src=\"javascript:alert(1)\"></frame>",
            "<frameset></frameset>",
            "<applet code=\"evil\"></applet>",
            "<svg></svg>",
            "<svg onload=\"alert(1)\">",
            "<math></math>",
            "<object data=\"vbscript:alert(1)\"></object>",
    })
    @DisplayName("Dangerous embedded elements are removed entirely")
    void dangerousEmbeddedRemoved(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html().toLowerCase();
        assertAll(
                () -> assertFalse(safe.contains("<iframe"), "iframe survived"),
                () -> assertFalse(safe.contains("<object"), "object survived"),
                () -> assertFalse(safe.contains("<embed"), "embed survived"),
                () -> assertFalse(safe.contains("<frame"), "frame survived"),
                () -> assertFalse(safe.contains("<frameset"), "frameset survived"),
                () -> assertFalse(safe.contains("<applet"), "applet survived"),
                () -> assertFalse(safe.contains("<svg"), "svg survived"),
                () -> assertFalse(safe.contains("<math"), "math survived"),
                () -> assertFalse(safe.contains("javascript"), "javascript URL survived"),
                () -> assertFalse(safe.contains("vbscript"), "vbscript URL survived"),
                () -> assertFalse(safe.contains("alert(1)"), "alert(1) survived")
        );
    }

    // ------------------------------------------------------------------
    //  E. SVG / MathML attack surfaces
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "svg/mathml vector: {0}")
    @ValueSource(strings = {
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
            "<svg/onload=alert(1)>",
            "<svg><a xlink:href=\"javascript:alert(1)\">x</a></svg>",
            "<math><maction actiontype=\"statusline#http://example.com\" xlink:href=\"javascript:alert(1)\">x</maction></math>",
            "<math href=\"javascript:alert(1)\">x</math>",
            "<svg><desc><![CDATA[<script>alert(1)</script>]]></desc></svg>",
            "<image xlink:href=\"javascript:alert(1)\">",
            "<use xlink:href=\"javascript:alert(1)\">",
    })
    @DisplayName("SVG/MathML attacks are neutralized")
    void svgMathMlAttacksNeutralized(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.toLowerCase().contains("<svg"), "svg survived");
        assertFalse(safe.toLowerCase().contains("<math"), "math survived");
        assertFalse(safe.toLowerCase().contains("<image"), "image survived");
        assertFalse(safe.toLowerCase().contains("<use"), "use survived");
        assertFalse(safe.contains("javascript"), "javascript URL survived");
        assertFalse(safe.contains("alert(1)"), "alert(1) survived");
    }

    // ------------------------------------------------------------------
    //  F. Attribute attacks
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "attribute attack: {0}")
    @CsvSource({
            "'<p style=\"background:url(javascript:alert(1))\">x</p>'",
            "'<p style=\"width:expression(alert(1))\">x</p>'",
            "'<p style=\"x:\\65xpression(alert(1))\">x</p>'",
            "'<a href=\"https://example.com\" style=\"x:expression(alert(1))\">link</a>'",
    })
    @DisplayName("Style attribute is not in default allowlist and is removed")
    void styleAttributeRemoved(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.contains("style"),
                "style attribute survived: " + safe);
        assertFalse(safe.contains("expression"),
                "expression survived: " + safe);
        assertFalse(safe.contains("alert"),
                "alert survived: " + safe);
    }

    @ParameterizedTest(name = "url-attribute attack: {0}")
    @CsvSource({
            "'<img src=\"javascript:alert(1)\">'",
            "'<img src=\"JAVASCRIPT:alert(1)\">'",
            "'<iframe src=\"javascript:alert(1)\"></iframe>'",
            "'<form action=\"javascript:alert(1)\"><input type=submit></form>'",
            "'<object data=\"javascript:alert(1)\"></object>'",
            "'<object data=\"vbscript:alert(1)\"></object>'",
            "'<object data=\"data:text/html,<script>alert(1)</script>\"></object>'",
            "'<embed src=\"javascript:alert(1)\">'",
            "'<frame src=\"javascript:alert(1)\">'",
            "'<input src=\"javascript:alert(1)\">'",
            "'<a href=\"javascript:alert(1)\">x</a>'",
            "'<a href=\"vbscript:alert(1)\">x</a>'",
            "'<a href=\"data:text/html,<script>alert(1)</script>\"\">x</a>'"
    })
    @DisplayName("URL-bearing attributes with dangerous protocols are removed")
    void urlAttributesWithDangerousProtocols(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.contains("javascript:"),
                "javascript: survived: " + safe);
        assertFalse(safe.contains("vbscript:"),
                "vbscript: survived: " + safe);
        assertFalse(safe.contains("data:"),
                "data: survived: " + safe);
        assertFalse(safe.contains("alert"),
                "alert survived: " + safe);
    }

    // ------------------------------------------------------------------
    //  G. Nested attacks
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "nested attack: {0}")
    @ValueSource(strings = {
            "<p onclick=\"alert(1)\"><strong>text</strong></p>",
            "<div><p onclick=\"alert(1)\">text</p></div>",
            "<blockquote><p onclick=\"alert(1)\">text</p></blockquote>",
            "<ul><li onclick=\"alert(1)\">item</li></ul>",
            "<p><a href=\"javascript:alert(1)\">link</a></p>",
            "<blockquote><p><a href=\"javascript:alert(1)\">link</a></p></blockquote>",
            "<div><span><a href=\"javascript:alert(1)\">link</a></span></div>",
            "<pre><code><a href=\"javascript:alert(1)\">link</a></code></pre>",
            "<h1 onclick=\"alert(1)\">Title</h1>",
            "<ul><li><a href=\"javascript:alert(1)\"><strong>item</strong></a></li></ul>",
    })
    @DisplayName("Nested malicious content inside allowed elements is neutralized")
    void nestedAttacksNeutralized(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.contains("javascript:"),
                "javascript: survived: " + safe);
        assertFalse(safe.toLowerCase().contains("onclick"),
                "onclick survived: " + safe);
        assertFalse(safe.contains("alert(1)"),
                "alert(1) survived: " + safe);
    }

    // ------------------------------------------------------------------
    //  H. Parser edge cases
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "malformed: {0}")
    @ValueSource(strings = {
            "<p>Unclosed paragraph",
            "<p><strong>Unclosed tags",
            "<<script>alert(1)<</script>",
            "<p onclick=\"alert(1)\">text",
            "<scr script >alert(1)</scr script >",
            "<img src=x onerror=alert(1)>",
            "<IMG SRC=JAVASCRIPT:alert('XSS')>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<p/onclick=\"alert(1)\">x</p>",
            "<p onclick=alert(1) x>text</p>",
            "<p onclick='alert(1)'>text</p>",
            "<a href=\"javascript:alert(1)\" onclick=\"alert(2)\">x</a>",
            "<p href=\"javascript:alert(1)\">x</p>",
            "<a href =\"javascript:alert(1)\">x</a>",
            "<a href=\"javascript:alert(1)\"   >x</a>",
            "<a\t href=\"javascript:alert(1)\">x</a>",
    })
    @DisplayName("Malformed and edge-case inputs never cause XSS")
    void malformedInputsNeverXss(String payload) {
        assertDoesNotThrow(() -> sanitizer.sanitize(payload));
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.contains("javascript:"),
                "javascript: survived in: " + safe);
        assertFalse(safe.contains("JAVASCRIPT:"),
                "JAVASCRIPT: survived in: " + safe);
        assertFalse(safe.toLowerCase().contains("onclick"),
                "onclick survived in: " + safe);
        assertFalse(safe.contains("alert(1)"),
                "alert(1) survived in: " + safe);
    }

    @ParameterizedTest(name = "comment vector: {0}")
    @ValueSource(strings = {
            "<!-- secret -->",
            "<!-- <script>alert(1)</script> -->",
            "<!-- --><p>visible</p>",
            "<p>text</p><!-- comment -->",
            "<!--<!--[if IE]><script>alert(1)</script><![endif]-->",
            "<![if IE]><script>alert(1)</script><![endif]",
            "<!-- <img src=x onerror=alert(1)> -->",
    })
    @DisplayName("HTML comments are always removed and never contain executable content")
    void commentsAlwaysRemoved(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.contains("<!--"),
                "Comment survived in: " + safe);
        assertFalse(safe.contains("-->"),
                ">- survived in: " + safe);
        assertFalse(safe.contains("<!--[if"),
                "Conditional comment survived in: " + safe);
        assertFalse(safe.toLowerCase().contains("<script"),
                "Script tag inside comment survived in: " + safe);
    }

    @ParameterizedTest(name = "tag case variation: {0}")
    @ValueSource(strings = {
            "<P>text</P>",
            "<STRONG>text</STRONG>",
            "<P OnClick=\"alert(1)\">text</P>",
            "<A HREF=\"javascript:alert(1)\">link</A>",
            "<ScRiPt>alert(1)</ScRiPt>",
    })
    @DisplayName("Mixed-case tags and attributes are handled")
    void mixedCaseTagsAndAttributes(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.toLowerCase().contains("onclick"),
                "onclick survived: " + safe);
        assertFalse(safe.contains("javascript:"),
                "javascript: survived: " + safe);
        assertFalse(safe.toLowerCase().contains("<script"),
                "script survived: " + safe);
    }

    @ParameterizedTest(name = "duplicate attributes: {0}")
    @ValueSource(strings = {
            "<p onclick=\"alert(1)\" onclick=\"alert(2)\">text</p>",
            "<a href=\"https://safe.com\" href=\"javascript:alert(1)\">link</a>",
            "<p onclick=\"alert(1)\" onclick='steal()'>text</p>",
        })
    @DisplayName("Duplicate attributes are handled safely")
    void duplicateAttributesHandled(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertFalse(safe.contains("javascript:"),
                "javascript: survived: " + safe);
        assertFalse(safe.toLowerCase().contains("onclick"),
                "onclick survived: " + safe);
    }

    // ------------------------------------------------------------------
    //  I. Serialization sanity
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "invariant for: {0}")
    @ValueSource(strings = {
            "<script>alert(1)</script>",
            "<p onclick=alert(1)>x</p>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<style>body{background:url(javascript:alert(1))}</style>",
            "<object data=\"javascript:alert(1)\"></object>",
            "<form action=\"javascript:alert(1)\"><button>x</button></form>",
            "<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
            "<base href=\"javascript:alert(1)//example.com\">",
            "<!-- comment -->",
            "<p>Hello <strong>world</strong></p>",
    })
    @DisplayName("Output never contains eval-inducing patterns")
    void noEvalPatterns(String payload) {
        SanitizationResult result = sanitizer.sanitize(payload);
        String safe = result.html();
        assertAll(
                () -> assertFalse(safe.contains("javascript:"),
                        "javascript: in output"),
                () -> assertFalse(safe.contains("JAVASCRIPT:"),
                        "JAVASCRIPT: in output"),
                () -> assertFalse(safe.contains("vbscript:"),
                        "vbscript: in output"),
                () -> assertFalse(safe.contains("VBSRIPT:"),
                        "VBSRIPT: in output"),
                () -> assertFalse(safe.contains("data:"),
                        "data: in output"),
                () -> assertFalse(safe.contains("file:"),
                        "file: in output"),
                () -> assertFalse(safe.toLowerCase().contains("onclick"),
                        "onclick in output"),
                () -> assertFalse(safe.toLowerCase().contains("onerror"),
                        "onerror in output"),
                () -> assertFalse(safe.toLowerCase().contains("onload"),
                        "onload in output"),
                () -> assertFalse(safe.contains("expression("),
                        "expression() in output"),
                () -> assertFalse(safe.contains("<!--"),
                        "comment in output")
        );
    }
}
