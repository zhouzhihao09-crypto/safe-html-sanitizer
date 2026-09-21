package com.safehtml;

/**
 * The outcome of a sanitization operation.
 *
 * <p>Holds the sanitized HTML string together with a {@link SecurityReport}
 * that describes everything the sanitizer removed or blocked.</p>
 */
public record SanitizationResult(String html, SecurityReport report) {

    /**
     * @return the sanitized HTML, guaranteed non-{@code null}
     */
    @Override
    public String html() {
        return html == null ? "" : html;
    }

    /**
     * @return the security report describing all modifications made
     */
    @Override
    public SecurityReport report() {
        return report;
    }

    /**
     * @return {@code true} if the input was already safe (no modifications were made)
     */
    public boolean wasModified() {
        return !report.isClean();
    }
}
