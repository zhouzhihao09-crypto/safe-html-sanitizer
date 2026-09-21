package com.safehtml;

import java.util.Objects;

/**
 * Represents the result of validating a URL.
 */
public final class ValidationResult {
    private final String url;
    private final boolean allowed;
    private final String blockedScheme;

    private ValidationResult(String url, boolean allowed, String blockedScheme) {
        this.url = url;
        this.allowed = allowed;
        this.blockedScheme = blockedScheme;
    }

    /**
     * Creates a result indicating the URL is allowed.
     *
     * @param url the original URL
     * @return an allowed result
     */
    public static ValidationResult allowed(String url) {
        return new ValidationResult(url, true, null);
    }

    /**
     * Creates a result indicating the URL is blocked.
     *
     * @param url the original URL
     * @param blockedScheme the scheme that was blocked
     * @return a blocked result
     */
    public static ValidationResult blocked(String url, String blockedScheme) {
        return new ValidationResult(url, false, blockedScheme);
    }

    /**
     * @return {@code true} if the URL is allowed, {@code false} if blocked
     */
    public boolean allowed() {
        return allowed;
    }

    /**
     * @return the original URL
     */
    public String url() {
        return url;
    }

    /**
     * @return the blocked scheme, or {@code null} if the URL was allowed
     */
    public String blockedScheme() {
        return blockedScheme;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ValidationResult that)) return false;
        return allowed == that.allowed
                && Objects.equals(url, that.url)
                && Objects.equals(blockedScheme, that.blockedScheme);
    }

    @Override
    public int hashCode() {
        return Objects.hash(url, allowed, blockedScheme);
    }

    @Override
    public String toString() {
        return allowed
                ? "ValidationResult[allowed, url=" + url + "]"
                : "ValidationResult[blocked, url=" + url + ", scheme=" + blockedScheme + "]";
    }
}
