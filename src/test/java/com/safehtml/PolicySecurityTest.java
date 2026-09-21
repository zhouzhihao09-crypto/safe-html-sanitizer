package com.safehtml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that verify mandatory security protections cannot be bypassed
 * by custom policy configuration.
 *
 * <p>These tests prove that calls to {@link SanitizationPolicy.Builder#allowElement},
 * {@link SanitizationPolicy.Builder#allowAttribute}, etc. cannot weaken
 * mandatory protections such as event-handler stripping, dangerous-element
 * removal, or URL protocol validation.</p>
 */
@DisplayName("Policy security bypass prevention")
class PolicySecurityTest {

    @Test
    @DisplayName("allowElement('script') does not permit script tags")
    void allowScriptDoesNotPermit() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("script")
                .allowElement("p")
                .allowUrl("href", "a")
                .allowUrlProtocols("https")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<script>alert(1)</script><p>safe</p>");
        assertFalse(result.html().toLowerCase().contains("<script"));
        assertFalse(result.html().contains("alert(1)"));
        assertTrue(result.html().contains("<p>safe</p>"));
        assertTrue(result.report().removedElements().stream()
                .anyMatch(e -> e.tagName().equals("script")));
    }

    @Test
    @DisplayName("allowElement('style') does not permit style tags")
    void allowStyleDoesNotPermit() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("style")
                .allowElement("p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<style>body{background:url(javascript:alert(1))}</style>"
                        + "<p>safe</p>");
        assertFalse(result.html().toLowerCase().contains("<style"));
        assertFalse(result.html().contains("javascript"));
        assertTrue(result.html().contains("<p>safe</p>"));
    }

    @Test
    @DisplayName("allowElement('iframe') does not permit iframe tags")
    void allowIframeDoesNotPermit() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("iframe")
                .allowElement("p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<iframe src=\"javascript:alert(1)\"></iframe><p>safe</p>");
        assertFalse(result.html().toLowerCase().contains("<iframe"));
        assertFalse(result.html().contains("javascript"));
        assertTrue(result.html().contains("<p>safe</p>"));
    }

    @Test
    @DisplayName("allowElement('svg') does not permit svg tags")
    void allowSvgDoesNotPermit() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("svg")
                .allowElement("p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<svg onload=\"alert(1)\"></svg><p>safe</p>");
        assertFalse(result.html().toLowerCase().contains("<svg"));
        assertFalse(result.html().contains("alert"));
        assertFalse(result.html().toLowerCase().contains("onload"));
    }

    @Test
    @DisplayName("allowAttribute('onclick') does not permit event handler")
    void allowOnclickDoesNotPermit() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("p")
                .allowAttribute("onclick", "p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<p onclick=\"alert(1)\">text</p>");
        assertFalse(result.html().toLowerCase().contains("onclick"));
        assertFalse(result.html().contains("alert(1)"));
        assertTrue(result.html().contains("text"));
    }

    @Test
    @DisplayName("allowAttribute('onerror') does not permit event handler")
    void allowOnerrorDoesNotPermit() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("p")
                .allowAttribute("onerror", "p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<p onerror=\"alert(1)\">text</p>");
        assertFalse(result.html().toLowerCase().contains("onerror"));
        assertFalse(result.html().contains("alert(1)"));
    }

    @Test
    @DisplayName("allowAttribute('onload') does not permit event handler")
    void allowOnloadDoesNotPermit() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("p")
                .allowAttribute("onload", "p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<p onload=\"alert(1)\">text</p>");
        assertFalse(result.html().toLowerCase().contains("onload"));
        assertFalse(result.html().contains("alert(1)"));
    }

    @Test
    @DisplayName("Event handlers with mixed case cannot bypass via policy")
    void mixedCaseEventHandlersBlocked() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("p")
                .allowAttribute("OnClick", "p")
                .allowAttribute("ONERROR", "p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<p OnClick=\"alert(1)\" ONERROR=\"alert(2)\">text</p>");
        assertFalse(result.html().toLowerCase().contains("onclick"));
        assertFalse(result.html().toLowerCase().contains("onerror"));
        assertFalse(result.html().contains("alert"));
    }

    @Test
    @DisplayName("URL validation still applies in custom policies")
    void urlValidationAppliesInCustomPolicy() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("a")
                .allowUrl("href", "a")
                .allowUrlProtocol("https")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<a href=\"javascript:alert(1)\">x</a><a href=\"https://safe.com\">y</a>");
        assertFalse(result.html().contains("javascript:"));
        assertTrue(result.html().contains("https://safe.com"));
        assertEquals(1, result.report().blockedUrls().size());
    }

    @Test
    @DisplayName("Custom policy allowing img does not bypass URL validation for src")
    void imgSrcUrlValidatedInCustomPolicy() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("img")
                .allowUrl("src", "img")
                .allowUrlProtocol("https")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<img src=\"javascript:alert(1)\"><img src=\"https://safe.com/img.jpg\">");
        assertFalse(result.html().contains("javascript:"));
        assertTrue(result.html().contains("https://safe.com/img.jpg"));
        assertEquals(1, result.report().blockedUrls().size());
    }

    @Test
    @DisplayName("Meta refresh cannot bypass via custom policy")
    void metaRefreshBlocked() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("meta")
                .allowAttribute("http-equiv", "meta")
                .allowAttribute("content", "meta")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">");
        assertFalse(result.html().toLowerCase().contains("<meta"));
        assertFalse(result.html().contains("javascript"));
    }

    @Test
    @DisplayName("Base tag cannot bypass via custom policy")
    void baseTagBlocked() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("base")
                .allowAttribute("href", "base")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<base href=\"javascript:alert(1)//example.com\">");
        assertFalse(result.html().toLowerCase().contains("<base"));
        assertFalse(result.html().contains("javascript"));
    }

    @Test
    @DisplayName("Form action cannot bypass via custom policy")
    void formActionBlocked() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("form")
                .allowUrl("action", "form")
                .allowUrlProtocol("https")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<form action=\"javascript:alert(1)\"><button>x</button></form>");
        assertFalse(result.html().toLowerCase().contains("<form"));
        assertFalse(result.html().contains("javascript"));
    }

    @Test
    @DisplayName("Object element cannot bypass via custom policy")
    void objectBlocked() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("object")
                .allowUrl("data", "object")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<object data=\"javascript:alert(1)\"></object>");
        assertFalse(result.html().toLowerCase().contains("<object"));
        assertFalse(result.html().contains("javascript"));
    }

    @Test
    @DisplayName("Iframe cannot bypass via custom policy")
    void iframeBlocked() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("iframe")
                .allowUrl("src", "iframe")
                .allowUrlProtocol("https")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<iframe src=\"javascript:alert(1)\"></iframe>");
        assertFalse(result.html().toLowerCase().contains("<iframe"));
        assertFalse(result.html().contains("javascript"));
    }

    @ParameterizedTest(name = "Dangerous element: {0}")
    @ValueSource(strings = {
            "script", "style", "iframe", "object", "embed", "applet",
            "frame", "frameset", "head", "meta", "link", "base",
            "noscript", "template", "title", "textarea", "select",
            "option", "form", "input", "button", "svg", "math",
            "xmp", "noembed", "noframes", "xml", "declare", "param"
    })
    @DisplayName("All dangerous elements are blocked even if explicitly allowed")
    void allDangerousElementsBlockedEvenIfAllowed(String tagName) {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement(tagName)
                .allowElement("p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<" + tagName + ">content</" + tagName + "><p>safe</p>");
        assertFalse(result.html().toLowerCase().contains("<" + tagName),
                tagName + " survived in output");
        assertTrue(result.html().contains("<p>safe</p>"));
    }

    @ParameterizedTest(name = "Event handler: on{0}")
    @ValueSource(strings = {
            "click", "error", "load", "mouseover", "focus", "blur",
            "mouseenter", "mouseleave", "mousemove", "mousedown", "mouseup",
            "keydown", "keyup", "keypress", "submit", "reset",
            "change", "input", "select", "abort", "canplay", "canplaythrough",
            "durationchange", "emptied", "ended", "loadeddata", "loadedmetadata",
            "pause", "play", "playing", "progress", "ratechange", "seeked",
            "seeking", "stalled", "suspend", "timeupdate", "volumechange",
            "waiting", "loadstart", "animationstart", "animationend",
            "transitionend", "scroll", "resize", "hashchange", "message"
    })
    @DisplayName("All event handler variants are stripped even if explicitly allowed")
    void allEventHandlerVariantsBlocked(String handler) {
        String attrName = "on" + handler;
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("p")
                .allowAttribute(attrName, "p")
                .build();
        SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
        SanitizationResult result = sanitizer.sanitize(
                "<p " + attrName + "=\"alert(1)\">text</p>");
        assertFalse(result.html().toLowerCase().contains(attrName),
                attrName + " survived in output");
        assertFalse(result.html().contains("alert(1)"),
                "alert(1) survived in output");
    }
}
