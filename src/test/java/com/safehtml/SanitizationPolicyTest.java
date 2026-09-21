package com.safehtml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

class SanitizationPolicyTest {

    @Test @DisplayName("Default policy allows basic text elements")
    void defaultPolicyHasBasicElements() {
        SanitizationPolicy policy = SanitizationPolicy.getDefault();
        assertTrue(policy.isElementAllowed("p"));
        assertTrue(policy.isElementAllowed("br"));
        assertTrue(policy.isElementAllowed("strong"));
        assertTrue(policy.isElementAllowed("em"));
        assertTrue(policy.isElementAllowed("b"));
        assertTrue(policy.isElementAllowed("i"));
        assertTrue(policy.isElementAllowed("u"));
        assertTrue(policy.isElementAllowed("ul"));
        assertTrue(policy.isElementAllowed("ol"));
        assertTrue(policy.isElementAllowed("li"));
        assertTrue(policy.isElementAllowed("blockquote"));
        assertTrue(policy.isElementAllowed("code"));
        assertTrue(policy.isElementAllowed("pre"));
        assertTrue(policy.isElementAllowed("h1"));
        assertTrue(policy.isElementAllowed("h6"));
        assertTrue(policy.isElementAllowed("a"));
    }

    @Test @DisplayName("Default policy does not allow dangerous elements")
    void defaultPolicyRejectsDangerousElements() {
        SanitizationPolicy policy = SanitizationPolicy.getDefault();
        assertFalse(policy.isElementAllowed("script"));
        assertFalse(policy.isElementAllowed("style"));
        assertFalse(policy.isElementAllowed("iframe"));
        assertFalse(policy.isElementAllowed("img"));
        assertFalse(policy.isElementAllowed("svg"));
        assertFalse(policy.isElementAllowed("div"));
    }

    @Test @DisplayName("Default policy allows href on anchor")
    void defaultPolicyAllowsHref() {
        SanitizationPolicy policy = SanitizationPolicy.getDefault();
        assertTrue(policy.isAttributeAllowed("href", "a"));
    }

    @Test @DisplayName("Default policy allows title globally")
    void defaultPolicyAllowsTitle() {
        SanitizationPolicy policy = SanitizationPolicy.getDefault();
        assertTrue(policy.isAttributeAllowed("title", "p"));
        assertTrue(policy.isAttributeAllowed("title", "a"));
        assertTrue(policy.isAttributeAllowed("title", "div"));
    }

    @Test @DisplayName("Default policy allows class globally")
    void defaultPolicyAllowsClass() {
        SanitizationPolicy policy = SanitizationPolicy.getDefault();
        assertTrue(policy.isAttributeAllowed("class", "p"));
        assertTrue(policy.isAttributeAllowed("class", "a"));
    }

    @Test @DisplayName("Default policy does not allow onclick")
    void defaultPolicyRejectsEventHandlers() {
        SanitizationPolicy policy = SanitizationPolicy.getDefault();
        assertFalse(policy.isAttributeAllowed("onclick", "a"));
        assertFalse(policy.isAttributeAllowed("onerror", "a"));
    }

    @Test @DisplayName("Default policy does not allow src on img")
    void defaultPolicyRejectsSrc() {
        SanitizationPolicy policy = SanitizationPolicy.getDefault();
        assertFalse(policy.isAttributeAllowed("src", "img"));
    }

    @Test @DisplayName("Builder allows custom elements")
    void builderCustomElements() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("div")
                .allowElement("span")
                .build();
        assertTrue(policy.isElementAllowed("div"));
        assertTrue(policy.isElementAllowed("span"));
        assertFalse(policy.isElementAllowed("p"));
    }

    @Test @DisplayName("Builder allows attributes on specific elements")
    void builderSpecificAttributes() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("a")
                .allowAttribute("href", "a")
                .allowAttribute("target", "a")
                .build();
        assertTrue(policy.isAttributeAllowed("href", "a"));
        assertTrue(policy.isAttributeAllowed("target", "a"));
        assertFalse(policy.isAttributeAllowed("href", "p"));
        assertFalse(policy.isAttributeAllowed("src", "a"));
    }

    @Test @DisplayName("Builder allows global attributes")
    void builderGlobalAttributes() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("p")
                .allowAttribute("title", "*")
                .build();
        assertTrue(policy.isAttributeAllowed("title", "p"));
        assertTrue(policy.isAttributeAllowed("title", "div"));
        assertFalse(policy.isAttributeAllowed("class", "p"));
    }

    @Test @DisplayName("Builder allowUrl registers URL attribute")
    void builderAllowUrl() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("a")
                .allowUrl("href", "a")
                .build();
        assertTrue(policy.isUrlAttribute("href"));
        assertFalse(policy.isUrlAttribute("title"));
    }

    @Test @DisplayName("Builder allows URL protocols")
    void builderUrlProtocols() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowUrlProtocols("https", "mailto")
                .build();
        assertTrue(policy.allowedUrlProtocols().contains("https"));
        assertTrue(policy.allowedUrlProtocols().contains("mailto"));
        assertFalse(policy.allowedUrlProtocols().contains("javascript"));
    }

    @Test @DisplayName("Element names are case-insensitive")
    void caseInsensitiveElements() {
        SanitizationPolicy policy = SanitizationPolicy.builder()
                .allowElement("DIV")
                .build();
        assertTrue(policy.isElementAllowed("div"));
        assertTrue(policy.isElementAllowed("DIV"));
        assertTrue(policy.isElementAllowed("Div"));
    }

    @Test @DisplayName("Empty policy allows nothing")
    void emptyPolicy() {
        SanitizationPolicy policy = SanitizationPolicy.builder().build();
        assertFalse(policy.isElementAllowed("p"));
        assertFalse(policy.isAttributeAllowed("class", "p"));
    }
}
