package com.safehtml;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * An immutable record of all modifications made during sanitization.
 *
 * <p>A {@code SecurityReport} is produced by every call to
 * {@link SafeHtmlSanitizer#sanitize(String)} and describes which elements,
 * attributes, comments, and URLs were removed or blocked. It gives callers
 * visibility into the sanitizer's decisions without exposing internal parser
 * details.</p>
 *
 * @see SanitizationResult
 */
public final class SecurityReport {

    private final List<RemovedElement> removedElements;
    private final List<RemovedAttribute> removedAttributes;
    private final List<BlockedUrl> blockedUrls;
    private final List<RemovedComment> removedComments;
    private final int totalModifications;

    private SecurityReport(
            List<RemovedElement> removedElements,
            List<RemovedAttribute> removedAttributes,
            List<BlockedUrl> blockedUrls,
            List<RemovedComment> removedComments) {
        this.removedElements = Collections.unmodifiableList(new ArrayList<>(removedElements));
        this.removedAttributes = Collections.unmodifiableList(new ArrayList<>(removedAttributes));
        this.blockedUrls = Collections.unmodifiableList(new ArrayList<>(blockedUrls));
        this.removedComments = Collections.unmodifiableList(new ArrayList<>(removedComments));
        this.totalModifications = removedElements.size()
                + removedAttributes.size()
                + blockedUrls.size()
                + removedComments.size();
    }

    /**
     * @return an unmodifiable list of elements that were removed or unwrapped
     */
    public List<RemovedElement> removedElements() {
        return removedElements;
    }

    /**
     * @return an unmodifiable list of attributes that were removed
     */
    public List<RemovedAttribute> removedAttributes() {
        return removedAttributes;
    }

    /**
     * @return an unmodifiable list of URLs that were blocked
     */
    public List<BlockedUrl> blockedUrls() {
        return blockedUrls;
    }

    /**
     * @return an unmodifiable list of HTML comments that were removed
     */
    public List<RemovedComment> removedComments() {
        return removedComments;
    }

    /**
     * @return the total number of individual modifications made
     */
    public int totalModifications() {
        return totalModifications;
    }

    /**
     * @return {@code true} if no modifications were made (the HTML was already safe)
     */
    public boolean isClean() {
        return totalModifications == 0;
    }

    /**
     * Returns a human-readable summary of this report.
     */
    @Override
    public String toString() {
        return "SecurityReport[" +
                "elementsRemoved=" + removedElements.size() +
                ", attributesRemoved=" + removedAttributes.size() +
                ", urlsBlocked=" + blockedUrls.size() +
                ", commentsRemoved=" + removedComments.size() +
                ", totalModifications=" + totalModifications +
                ']';
    }

    /**
     * A record of a removed or unwrapped element.
     */
    public static final class RemovedElement {
        private final String tagName;
        private final String parentName;

        public RemovedElement(String tagName, String parentName) {
            this.tagName = Objects.requireNonNull(tagName);
            this.parentName = parentName;
        }

        /** @return the tag name of the removed element */
        public String tagName() { return tagName; }

        /** @return the tag name of the parent element, or {@code "(root)"} if none */
        public String parentName() { return parentName; }

        @Override
        public String toString() {
            return "RemovedElement[tag=" + tagName + ", parent=" + parentName + "]";
        }
    }

    /**
     * A record of a removed attribute.
     */
    public static final class RemovedAttribute {
        private final String attrName;
        private final String elementName;

        public RemovedAttribute(String attrName, String elementName) {
            this.attrName = Objects.requireNonNull(attrName);
            this.elementName = Objects.requireNonNull(elementName);
        }

        /** @return the attribute name that was removed */
        public String attrName() { return attrName; }

        /** @return the tag name of the element that had the attribute */
        public String elementName() { return elementName; }

        @Override
        public String toString() {
            return "RemovedAttribute[attr=" + attrName + ", element=" + elementName + "]";
        }
    }

    /**
     * A record of a blocked URL.
     */
    public static final class BlockedUrl {
        private final String url;
        private final String attrName;
        private final String elementName;
        private final String blockedScheme;

        public BlockedUrl(String url, String attrName, String elementName, String blockedScheme) {
            this.url = url;
            this.attrName = Objects.requireNonNull(attrName);
            this.elementName = Objects.requireNonNull(elementName);
            this.blockedScheme = blockedScheme;
        }

        /** @return the original URL that was blocked */
        public String url() { return url; }

        /** @return the attribute name (e.g. "href", "src") */
        public String attrName() { return attrName; }

        /** @return the tag name of the element */
        public String elementName() { return elementName; }

        /** @return the URL scheme that was blocked */
        public String blockedScheme() { return blockedScheme; }

        @Override
        public String toString() {
            return "BlockedUrl[url=" + url + ", attr=" + attrName +
                    ", element=" + elementName + ", scheme=" + blockedScheme + "]";
        }
    }

    /**
     * A record of a removed HTML comment.
     */
    public static final class RemovedComment {
        private final String content;

        public RemovedComment(String content) {
            this.content = content == null ? "" : content;
        }

        /** @return the text content of the removed comment */
        public String content() { return content; }

        @Override
        public String toString() {
            return "RemovedComment[content=" + (content.isEmpty() ? "(empty)" : content) + "]";
        }
    }

    /**
     * Mutable builder for {@link SecurityReport}.
     */
    public static final class Builder {
        private final List<RemovedElement> removedElements = new ArrayList<>();
        private final List<RemovedAttribute> removedAttributes = new ArrayList<>();
        private final List<BlockedUrl> blockedUrls = new ArrayList<>();
        private final List<RemovedComment> removedComments = new ArrayList<>();

        /**
         * Records a removed or unwrapped element.
         */
        public Builder addRemovedElement(String tagName, String parentName) {
            removedElements.add(new RemovedElement(tagName, parentName));
            return this;
        }

        /**
         * Records a removed attribute.
         */
        public Builder addRemovedAttribute(String attrName, String elementName) {
            removedAttributes.add(new RemovedAttribute(attrName, elementName));
            return this;
        }

        /**
         * Records a blocked URL.
         */
        public Builder addBlockedUrl(String url, String attrName, String elementName, String blockedScheme) {
            blockedUrls.add(new BlockedUrl(url, attrName, elementName, blockedScheme));
            return this;
        }

        /**
         * Records a removed comment.
         */
        public Builder addRemovedComment(String content) {
            removedComments.add(new RemovedComment(content));
            return this;
        }

        /**
         * Builds the immutable report.
         *
         * @return a new {@code SecurityReport}
         */
        public SecurityReport build() {
            return new SecurityReport(removedElements, removedAttributes,
                    blockedUrls, removedComments);
        }
    }
}
