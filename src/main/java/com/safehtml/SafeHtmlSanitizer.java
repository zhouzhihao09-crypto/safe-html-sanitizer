package com.safehtml;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.Comment;
import org.jsoup.nodes.Attribute;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

/**
 * A security-focused HTML sanitizer that processes untrusted HTML using
 * jsoup's parser and DOM model.
 *
 * <p>The sanitizer follows an <strong>explicit allowlist</strong> model:
 * only elements and attributes that appear in the {@link SanitizationPolicy}
 * are permitted. Everything else&mdash;including all event-handler attributes
 * (anything beginning with {@code "on"})&mdash;is removed.</p>
 *
 * <p><strong>Key security properties:</strong></p>
 * <ul>
 *   <li>Parses HTML with jsoup before any inspection or modification.</li>
 *   <li>No regular expressions are used for HTML sanitization.</li>
 *   <li>Event-handler attributes are always stripped, regardless of policy.</li>
 *   <li>URL-valued attributes are validated against an allowlist of protocols.</li>
 *   <li>Known dangerous elements (e.g. {@code <script>}, {@code <style>})
 *       are always removed even if a custom policy attempts to allow them.</li>
 *   <li>HTML comments are always removed.</li>
 *   <li>Thread-safe: each {@link #sanitize(String)} call uses its own report
 *       context; a single sanitizer instance may be shared across threads.</li>
 * </ul>
 *
 * <p>This is an experimental/educational library. See the project README
 * and SECURITY.md for limitations and threat-model details.</p>
 */
public class SafeHtmlSanitizer {

    private static final Set<String> DANGEROUS_ELEMENTS = Set.of(
            "script", "style", "iframe", "object", "embed", "applet",
            "frame", "frameset", "head", "meta", "link", "base",
            "noscript", "template", "title", "textarea", "select",
            "option", "form", "input", "button", "svg", "math",
            "xmp", "noembed", "noframes", "xml", "declare", "param"
    );

    private static final Set<String> SKIP_ELEMENTS = Set.of("html", "body");

    private final SanitizationPolicy policy;
    private final UrlValidator urlValidator;

    /**
     * Creates a sanitizer with the given policy.
     *
     * @param policy the allowlist policy to apply; must not be {@code null}
     */
    public SafeHtmlSanitizer(SanitizationPolicy policy) {
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.urlValidator = new UrlValidator(policy.getAllowedUrlProtocols());
    }

    /**
     * Sanitizes untrusted HTML according to the configured policy.
     *
     * <p>This method is thread-safe: a fresh {@code SecurityReport.Builder} is
     * created for each call and used only within the call's call stack.</p>
     *
     * @param html the raw HTML input; {@code null} or empty strings produce
     *             an empty result with an empty report
     * @return a {@link SanitizationResult} containing the safe HTML and a report
     */
    public SanitizationResult sanitize(String html) {
        SecurityReport.Builder report = new SecurityReport.Builder();

        if (html == null || html.isEmpty()) {
            return new SanitizationResult("", report.build());
        }

        Document doc = Jsoup.parseBodyFragment(html);

        removeComments(doc, report);

        Elements heads = doc.select("head");
        for (Element head : heads) {
            for (Element child : new ArrayList<>(head.children())) {
                sanitizeElement(child, report);
            }
            head.remove();
        }

        sanitizeElement(doc.body(), report);

        String safeHtml = doc.body().html();
        return new SanitizationResult(safeHtml, report.build());
    }

    /**
     * Convenience method that returns only the sanitized HTML string.
     *
     * @param html the raw HTML input
     * @return the sanitized HTML
     */
    public String sanitizeToHtml(String html) {
        return sanitize(html).html();
    }

    /**
     * Recursively removes all HTML comments from a node tree.
     * Iterates children in reverse order so removal is safe.
     *
     * @param node   the root node to start from
     * @param report the report to record removed comments in
     */
    private void removeComments(Node node, SecurityReport.Builder report) {
        for (int i = node.childNodeSize() - 1; i >= 0; i--) {
            Node child = node.childNode(i);
            if (child instanceof Comment) {
                report.addRemovedComment(((Comment) child).getData());
                child.remove();
            } else {
                removeComments(child, report);
            }
        }
    }

    /**
     * Recursively sanitizes an element and its descendants using post-order
     * traversal (children are processed before the element itself).
     *
     * @param el     the element to sanitize
     * @param report the report to record modifications in
     */
    private void sanitizeElement(Element el, SecurityReport.Builder report) {
        String tagName = el.tagName().toLowerCase();

        if (SKIP_ELEMENTS.contains(tagName)) {
            for (Element child : new ArrayList<>(el.children())) {
                sanitizeElement(child, report);
            }
            return;
        }

        for (Element child : new ArrayList<>(el.children())) {
            sanitizeElement(child, report);
        }

        if (DANGEROUS_ELEMENTS.contains(tagName)) {
            String parentName = el.parent() != null ? el.parent().tagName() : "(root)";
            report.addRemovedElement(tagName, parentName);
            el.remove();
            return;
        }

        if (!policy.isElementAllowed(tagName)) {
            String parentName = el.parent() != null ? el.parent().tagName() : "(root)";
            report.addRemovedElement(tagName, parentName);
            if (el.parent() != null) {
                if (Tag.isKnownTag(tagName)) {
                    el.unwrap();
                } else {
                    el.remove();
                }
            }
            return;
        }

        sanitizeAttributes(el, tagName, report);
    }

    /**
     * Removes disallowed attributes, event handlers, and unsafe URLs.
     *
     * @param el     the element whose attributes to sanitize
     * @param tagName the lowercased tag name of the element
     * @param report the report to record modifications in
     */
    private void sanitizeAttributes(Element el, String tagName, SecurityReport.Builder report) {
        Iterator<Attribute> iter = el.attributes().iterator();
        while (iter.hasNext()) {
            Attribute attr = iter.next();
            String attrName = attr.getKey().toLowerCase();

            if (attrName.startsWith("on")) {
                report.addRemovedAttribute(attrName, tagName);
                iter.remove();
                continue;
            }

            if (!policy.isAttributeAllowed(attrName, tagName)) {
                report.addRemovedAttribute(attrName, tagName);
                iter.remove();
                continue;
            }

            if (policy.isUrlAttribute(attrName)) {
                String url = el.attr(attrName);
                if (!url.isEmpty()) {
                    ValidationResult vr = urlValidator.validate(url);
                    if (!vr.allowed()) {
                        report.addBlockedUrl(url, attrName, tagName, vr.blockedScheme());
                        iter.remove();
                    }
                }
            }
        }
    }
}
