package com.safehtml;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Validates URLs against an allowlist of protocols.
 *
 * <p>This validator is URL-protocol-centric: it checks the scheme (protocol)
 * of a URL and allows or blocks it based on whether the scheme is in the
 * configured allowlist. Relative URLs (no scheme) are always allowed.</p>
 *
 * <p>The validator handles common evasion techniques such as:</p>
 * <ul>
 *   <li>Case variations (e.g. {@code JAVASCRIPT:}, {@code JaVaScRiPt:})</li>
 *   <li>Leading/trailing whitespace and embedded control characters</li>
 *   <li>Mixed obfuscation (tabs, newlines before or inside the scheme)</li>
 * </ul>
 *
 * <p>Note: HTML entity decoding (e.g. {@code &#106;avascript:}) is performed
 * by jsoup's HTML parser before the attribute value reaches this validator,
 * so entity-based obfuscation is already mitigated.</p>
 */
public final class UrlValidator {

    private final Set<String> allowedProtocols;

    /**
     * Creates a new {@code UrlValidator} with the given set of allowed protocols.
     *
     * @param allowedProtocols the set of allowed URL schemes (e.g. "https", "http", "mailto")
     */
    public UrlValidator(Set<String> allowedProtocols) {
        this.allowedProtocols = Objects.requireNonNullElse(allowedProtocols, Set.of());
    }

    /**
     * Validates a URL and returns a {@link ValidationResult}.
     *
     * <p>The URL is cleaned of leading/trailing whitespace and embedded control
     * characters before the scheme is extracted and compared against the
     * allowlist.</p>
     *
     * @param url the raw URL to validate
     * @return a {@code ValidationResult} indicating whether the URL is allowed
     */
    public ValidationResult validate(String url) {
        if (url == null || url.isEmpty()) {
            return ValidationResult.allowed(url);
        }

        String cleaned = cleanUrl(url);

        String scheme = extractScheme(cleaned);
        if (scheme == null) {
            return ValidationResult.allowed(url);
        }

        String lowerScheme = scheme.toLowerCase(Locale.ROOT);
        if (allowedProtocols.contains(lowerScheme)) {
            return ValidationResult.allowed(url);
        }
        return ValidationResult.blocked(url, lowerScheme);
    }

    /**
     * Returns the cleaned, safe URL if allowed, or {@code null} if blocked.
     *
     * @param url the raw URL to validate
     * @return the cleaned URL if safe, {@code null} if blocked
     */
    public String validateAndClean(String url) {
        ValidationResult result = validate(url);
        if (result.allowed()) {
            return cleanUrl(url);
        }
        return null;
    }

    /**
     * Cleans the URL by trimming whitespace and removing control characters
     * (chars with code points below 0x20) that could be used for obfuscation.
     *
     * @param url the raw URL
     * @return the cleaned URL
     */
    private static String cleanUrl(String url) {
        String trimmed = url.trim();
         StringBuilder sb = new StringBuilder(trimmed.length());
         for (int i = 0; i < trimmed.length(); i++) {
             char c = trimmed.charAt(i);
             if (c >= 0x20 && !Character.isWhitespace(c)) {
                 sb.append(c);
             }
         }
        return sb.toString();
    }

    /**
     * Extracts the scheme (protocol) from a URL string.
     *
     * <p>Uses {@link URI} for parsing. If URI parsing fails, falls back to
     * manual extraction by finding the first colon and validating the
     * preceding characters as a valid scheme.</p>
     *
     * @param url the cleaned URL
     * @return the scheme, or {@code null} if no valid scheme was found
     */
    private static String extractScheme(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            if (scheme != null) {
                return scheme;
            }
        } catch (Exception e) {
            // URI parsing failed; fall back to manual extraction
        }
        return extractSchemeManually(url);
    }

    /**
     * Manually extracts a scheme from a URL when URI parsing fails.
     *
     * <p>A scheme is defined as per RFC 2396: it starts with a letter and is
     * followed by any combination of letters, digits, '+', '-', or '.'.</p>
     *
     * @param url the cleaned URL
     * @return the scheme, or {@code null} if none is found
     */
    private static String extractSchemeManually(String url) {
        int colonIndex = url.indexOf(':');
        if (colonIndex <= 0) {
            return null;
        }

        String potential = url.substring(0, colonIndex);
        if (potential.isEmpty()) {
            return null;
        }

        char first = potential.charAt(0);
        if (!Character.isLetter(first)) {
            return null;
        }

        for (int i = 0; i < potential.length(); i++) {
            char c = potential.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '+' && c != '-' && c != '.') {
                return null;
            }
        }
        return potential;
    }
}
