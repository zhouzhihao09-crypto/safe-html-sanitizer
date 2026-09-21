package com.safehtml;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An immutable, allowlist-based security policy for HTML sanitization.
 *
 * <p>A {@code SanitizationPolicy} defines which HTML elements, attributes, and
 * URL protocols are permitted. Elements, attributes, or URLs that do not
 * appear in the policy's allowlists are removed during sanitization.</p>
 *
 * <p>Use {@link #builder()} to create a new policy:</p>
 *
 * <pre>{@code
 * SanitizationPolicy policy = SanitizationPolicy.builder()
 *     .allowElement("p")
 *     .allowElement("strong")
 *     .allowElement("a")
 *     .allowUrl("href", "a")
 *     .allowUrlProtocol("https")
 *     .allowUrlProtocol("http")
 *     .build();
 * }</pre>
 *
 * <p>The default policy ({@link #getDefault()}) is intentionally conservative,
 * allowing only basic text formatting elements and a minimal set of attributes.</p>
 */
public final class SanitizationPolicy {

    private static final String WILDCARD = "*";

    private final Set<String> allowedElements;
    private final Map<String, Set<String>> allowedAttributesByElement;
    private final Set<String> globallyAllowedAttributes;
    private final Set<String> urlAttributeNames;
    private final Set<String> allowedUrlProtocols;

    private SanitizationPolicy(Builder builder) {
        this.allowedElements = Collections.unmodifiableSet(new HashSet<>(builder.allowedElements));
        Map<String, Set<String>> attrs = new HashMap<>();
        for (Map.Entry<String, Set<String>> e : builder.allowedAttributesByElement.entrySet()) {
            attrs.put(e.getKey(), Collections.unmodifiableSet(new HashSet<>(e.getValue())));
        }
        this.allowedAttributesByElement = Collections.unmodifiableMap(attrs);
        this.globallyAllowedAttributes = Collections.unmodifiableSet(new HashSet<>(builder.globallyAllowedAttributes));
        this.urlAttributeNames = Collections.unmodifiableSet(new HashSet<>(builder.urlAttributeNames));
        this.allowedUrlProtocols = Collections.unmodifiableSet(new HashSet<>(builder.allowedUrlProtocols));
    }

    /**
     * @return the set of allowed element tag names (lowercase)
     */
    public Set<String> allowedElements() {
        return allowedElements;
    }

    /**
     * @return an unmodifiable map from element tag name to its allowed attribute names
     */
    public Map<String, Set<String>> allowedAttributes() {
        return allowedAttributesByElement;
    }

    /**
     * @return the set of attribute names allowed on every element
     */
    public Set<String> globallyAllowedAttributes() {
        return globallyAllowedAttributes;
    }

    /**
     * @return the set of attribute names whose values are treated as URLs
     */
    public Set<String> urlAttributeNames() {
        return urlAttributeNames;
    }

    /**
     * @return the set of allowed URL protocol schemes (lowercase)
     */
    public Set<String> allowedUrlProtocols() {
        return allowedUrlProtocols;
    }

    /**
     * Checks whether an element tag is in the allowlist.
     *
     * @param tagName the tag name (case will be lowercased internally by jsoup)
     * @return {@code true} if the element is allowed
     */
    public boolean isElementAllowed(String tagName) {
        return allowedElements.contains(tagName.toLowerCase());
    }

    /**
     * Checks whether an attribute is allowed on a given element.
     *
     * <p>An attribute is allowed if it appears in the element-specific allowlist
     * or in the global allowlist.</p>
     *
     * @param attrName the attribute name (lowercase)
     * @param tagName  the element tag name (lowercase)
     * @return {@code true} if the attribute is allowed on this element
     */
    public boolean isAttributeAllowed(String attrName, String tagName) {
        if (globallyAllowedAttributes.contains(attrName)) {
            return true;
        }
        Set<String> elementAttrs = allowedAttributesByElement.get(tagName);
        return elementAttrs != null && elementAttrs.contains(attrName);
    }

    /**
     * Checks whether an attribute name should be treated as a URL.
     *
     * @param attrName the attribute name (lowercase)
     * @return {@code true} if the attribute value should be URL-validated
     */
    public boolean isUrlAttribute(String attrName) {
        return urlAttributeNames.contains(attrName);
    }

    /**
     * @return an unmodifiable copy of the allowed URL protocols set
     */
    public Set<String> getAllowedUrlProtocols() {
        return allowedUrlProtocols;
    }

    /**
     * Creates a conservative default policy that allows only basic text-formatting
     * elements and minimal attributes.
     *
     * @return a default policy instance
     */
    public static SanitizationPolicy getDefault() {
        return new Builder()
                .allowElements(
                        "p", "br", "strong", "em", "b", "i", "u",
                        "ul", "ol", "li", "blockquote", "code", "pre",
                        "h1", "h2", "h3", "h4", "h5", "h6", "a")
                .allowAttribute("title", WILDCARD)
                .allowAttribute("class", WILDCARD)
                .allowUrl("href", "a")
                .allowUrlProtocols("https", "http", "mailto")
                .build();
    }

    /**
     * Creates a new builder for constructing a {@code SanitizationPolicy}.
     *
     * @return a fresh builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link SanitizationPolicy}.
     */
    public static final class Builder {
        private final Set<String> allowedElements = new HashSet<>();
        private final Map<String, Set<String>> allowedAttributesByElement = new HashMap<>();
        private final Set<String> globallyAllowedAttributes = new HashSet<>();
        private final Set<String> urlAttributeNames = new HashSet<>();
        private final Set<String> allowedUrlProtocols = new HashSet<>();

        private Builder() {}

        /**
         * Allows one or more HTML elements.
         *
         * @param tagNames element tag names to allow (case-insensitive; will be lowercased)
         * @return this builder
         */
        public Builder allowElements(String... tagNames) {
            for (String name : tagNames) {
                allowedElements.add(name.toLowerCase());
            }
            return this;
        }

        /**
         * Allows a single HTML element.
         *
         * @param tagName the tag name to allow
         * @return this builder
         */
        public Builder allowElement(String tagName) {
            allowedElements.add(tagName.toLowerCase());
            return this;
        }

        /**
         * Allows an attribute on one or more specific elements.
         *
         * <p>Use the wildcard {@code "*"} to allow the attribute on every element.</p>
         *
         * @param attrName the attribute name
         * @param element  the element tag name, or {@code "*"} for all elements
         * @return this builder
         */
        public Builder allowAttribute(String attrName, String element) {
            String lowerName = attrName.toLowerCase();
            String lowerElem = element.toLowerCase();
            if (WILDCARD.equals(lowerElem)) {
                globallyAllowedAttributes.add(lowerName);
            } else {
                allowedAttributesByElement
                        .computeIfAbsent(lowerElem, k -> new HashSet<>())
                        .add(lowerName);
            }
            return this;
        }

        /**
         * Allows an attribute on all elements. Equivalent to
         * {@code allowAttribute(attrName, "*")}.
         *
         * @param attrName the attribute name
         * @return this builder
         */
        public Builder allowAttributeGlobally(String attrName) {
            return allowAttribute(attrName, WILDCARD);
        }

        /**
         * Allows a URL-valued attribute and marks it for protocol validation.
         *
         * <p>This is equivalent to calling both {@link #allowAttribute(String, String)}
         * and registering the attribute name as a URL attribute whose value
         * must pass {@link UrlValidator} checks.</p>
         *
         * @param attrName the attribute name (e.g. "href", "src")
         * @param element  the element tag name, or {@code "*"} for all elements
         * @return this builder
         */
        public Builder allowUrl(String attrName, String element) {
            allowAttribute(attrName, element);
            urlAttributeNames.add(attrName.toLowerCase());
            return this;
        }

        /**
         * Allows a URL protocol scheme.
         *
         * @param protocol the protocol scheme (e.g. "https", "mailto")
         * @return this builder
         */
        public Builder allowUrlProtocol(String protocol) {
            allowedUrlProtocols.add(protocol.toLowerCase());
            return this;
        }

        /**
         * Allows one or more URL protocol schemes.
         *
         * @param protocols protocol schemes to allow
         * @return this builder
         */
        public Builder allowUrlProtocols(String... protocols) {
            for (String p : protocols) {
                allowedUrlProtocols.add(p.toLowerCase());
            }
            return this;
        }

        /**
         * Builds the immutable policy.
         *
         * @return a new {@code SanitizationPolicy}
         */
        public SanitizationPolicy build() {
            return new SanitizationPolicy(this);
        }
    }
}
