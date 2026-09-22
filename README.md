# SafeHTML

A small, security-focused HTML sanitization library for Java 21.

> ** WARNING: EXPERIMENTAL / EDUCATIONAL **
>
> This library is a learning project and is **not production-ready**. Do not use
> it as your sole defense against XSS or other injection attacks in production
> systems. See [Limitations](#current-limitations) for details.

---

## Problem Being Solved

Web applications routinely render user-supplied HTML (comments, forum posts, CMS
content). If rendered without sanitization, this HTML can carry cross-site
scripting (XSS) payloads that execute malicious JavaScript in victims'
browsers.

The goal of SafeHTML is to provide a minimal, readable, easily auditable library
that strips dangerous constructs from untrusted HTML before it is stored or
rendered.

## How Sanitization Works

1. **Parse** — The input string is parsed into a DOM tree using
   [jsoup](https://jsoup.org/)'s HTML parser. No regular expressions are used
   to manipulate HTML.
2. **Walk the DOM** — A recursive, post-order traversal visits every element.
   Children are processed before parents, so when a parent is removed or
   unwrapped, its already-sanitized children are handled correctly.
3. **Allowlist filters** —
   * Elements not in the policy's allowlist are either **removed** (dangerous
     tags like `<script>`, content discarded) or **unwrapped** (non-dangerous
     tags like `<div>`, children kept).
   * Attributes not in the policy's allowlist are stripped.
   * All event-handler attributes (`on*`, e.g. `onclick`, `onerror`) are
     removed unconditionally — they are never allowlisted.
4. **URL validation** — Attributes registered as URL-bearing (e.g. `href`) are
   validated by `UrlValidator`. The URL is cleaned of leading/trailing
   whitespace and embedded control characters, then its scheme is extracted
   and checked against the policy's allowed-protocol allowlist. Relative URLs
   (no scheme) are always allowed.
5. **Comments** — All HTML comments are removed.
6. **Serialize** — The cleaned DOM is serialized back to an HTML string.

## Architecture

```
+-------------------------------------------------------------+
|                       Client Code                           |
|                                                             |
|  SanitizationPolicy policy = SanitizationPolicy.builder()    |
|      .allowElement("p") ... .build();                      |
|                                                             |
|  SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);|
|  SanitizationResult result = sanitizer.sanitize(input);     |
|  String safe = result.html();                               |
+-------------------------------------------------------------+
        |                           |
        |  SanitizationPolicy        |  SanitizationResult
        v                           v
+-------------------+        +------------------+
| SanitizationPolicy |        | SanitizationResult|
| - allowedElements   |      | - html            |
| - allowedAttributes |      | - report          |
| - urlAttributeNames |      | - wasModified()   |
| - allowedProtocols  |      +------------------+
| + getDefault()      |               |
| + builder()         |               |  SecurityReport
+-------------------+               |  - removedElements
        |                           v  - removedAttributes
        |  +------------------+  - blockedUrls
        |  |  UrlValidator    |  - removedComments
        |  | - allowedProtocols|  - totalModifications()
        |  | + validate(url)  |  +------------------+
        |  +------------------+
        v
+-------------------+
| SafeHtmlSanitizer |
| - policy          |
| - urlValidator    |
| + sanitize(html)  |
| - removeComments()|
| - sanitizeElement()|
| - sanitizeAttrs() |
+-------------------+
        |
        v
+---------------------------------------------------+------------------+
|                  jsoup (HTML parser)             |     java.net.URI  |
|  Jsoup.parseBodyFragment(html) -> DOM tree       |  scheme extraction|
|  Node, Element, Comment, Attribute                |                  |
+---------------------------------------------------+------------------+
```

### Class responsibilities

| Class                  | Responsibility                                        |
|------------------------|------------------------------------------------------|
| `SafeHtmlSanitizer`    | Orchestrates DOM traversal, element/attribute/URL filtering |
| `SanitizationPolicy`   | Immutable allowlist; builder API for configuration   |
| `UrlValidator`         | Scheme extraction and protocol allowlist check        |
| `ValidationResult`     | Outcome of a single URL validation                    |
| `SanitizationResult`   | Holds sanitized HTML string + security report         |
| `SecurityReport`       | Immutable log of all removals / blocks during sanitization |

## Example Usage

```java
import com.safehtml.*;

SanitizationPolicy policy = SanitizationPolicy.builder()
        .allowElement("p")
        .allowElement("strong")
        .allowElement("a")
        .allowUrl("href", "a")
        .allowUrlProtocol("https")
        .allowUrlProtocol("http")
        .allowUrlProtocol("mailto")
        .build();

SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(policy);
SanitizationResult result = sanitizer.sanitize(
    "<p onclick=\"alert(1)\">Hello <a href='javascript:evil()'>world</a></p>"
);

System.out.println(result.html());       // <p>Hello <a>world</a></p>
System.out.println(result.report());     // SecurityReport[elementsRemoved=0, ...]
System.out.println(result.wasModified()); // true
```

### Using the default policy

```java
SafeHtmlSanitizer sanitizer = new SafeHtmlSanitizer(SanitizationPolicy.getDefault());
SanitizationResult result = sanitizer.sanitize(untrustedHtml);
String safeHtml = result.html();
```

## Before / After

**Input (malicious):**

```html
<p onclick="stealCookies()">Hello <strong>world</strong></p>
<a href="javascript:alert(1)">click me</a>
<script>document.location='http://evil.com'</script>
<iframe src="vbscript:alert(1)"></iframe>
```

**Output (sanitized with default policy):**

```html
<p>Hello <strong>world</strong></p>
<a>click me</a>
```

**Security report:**

```
SecurityReport[elementsRemoved=2, attributesRemoved=1, urlsBlocked=2, commentsRemoved=0, totalModifications=5]
  Removed elements:
    - script (parent: body)
    - iframe (parent: body)
  Removed attributes:
    - onclick on p
  Blocked URLs:
    - javascript:alert(1) in href on a
    - vbscript:alert(1) in src on iframe
```

## Security Model

| Property                     | Status | Notes |
|-----------------------------|--------|-------|
| Allowlist (not blocklist)   | Yes    | Only explicitly allowed elements/attributes survive |
| Event-handler attrs (`on*`) | Stripped unconditionally | Cannot be bypassed by any policy |
| Always-blocked elements    | Yes   | `script`, `style`, `iframe`, `svg`, `math`, etc. removed even if policy allows them |
| URL protocol allowlist      | Yes    | `javascript:`, `vbscript:`, `data:`, `file:` blocked |
| Case-insensitive scheme     | Yes    | `JAVASCRIPT:` and `javascript:` both blocked |
| Whitespace in URL scheme  | Handled | Spaces, tabs, newlines stripped from URL before scheme extraction |
| HTML entity obfuscation     | Handled | jsoup decodes entities before attribute values reach the validator |
| Regex HTML sanitization     | No     | Uses jsoup DOM model exclusively |
| Comments                    | Always removed | No conditional-comment bypass |
| Thread safety               | Yes    | Each `sanitize()` call uses its own report context |

See [SECURITY.md](SECURITY.md) for the full threat model and disclosure policy.

## Test Strategy

Tests are written with JUnit 5 and organized into nested classes:

| Test class                    | Focus |
|-------------------------------|-------|
| `UrlValidatorTest`            | Protocol allowlist, case variants, obfuscation |
| `SanitizationPolicyTest`      | Builder API, default policy, case-insensitivity |
| `SafeHtmlSanitizerTest`       | End-to-end sanitization + XSS payloads |
| `SecurityInvariantTest`       | Security invariants across hundreds of vectors |
| `PolicySecurityTest`          | Policy bypass prevention |

XSS payloads covered include `<script>`, `<img onerror>`, `<svg onload>`,
`<iframe>`, `<a href="javascript:...">`, HTML-entity obfuscation, tab/newline
obfuscation, case-variant schemes, and nested combinations.

The full suite runs **363 tests** with zero failures, covering security
invariants (250+ parameterized XSS vectors), policy bypass prevention
(29 dangerous elements + 42 event handlers), end-to-end sanitization
behavior, and demo server HTTP endpoints.

## Current Limitations

- **Not audited by security professionals.** This is an educational project.
- **No CSS sanitization.** The `style` attribute is not in the default
  allowlist, but if a developer explicitly allows it, CSS-based attacks (e.g.
  `expression()`, `url(javascript:...)`) are **not** mitigated.
- **No `<img>` or other media elements by default.** The default policy is
  intentionally restrictive. Adding `src`-bearing elements requires
  `allowUrl("src", element)` for proper URL validation.
- **Protocol-relative URLs** (`//evil.com`) are allowed because they inherit
  the page's protocol. This is intentional but could be surprising.
- **No encoding/escaping of unwrapped element content.** Content from
  unwrapped elements is left as-is (jsoup already parses it into a safe DOM).

## How to Build

```bash
# prerequisites: JDK 21, Maven 3.9+
mvn clean package
```

The compiled JAR is produced at `target/safe-html-sanitizer-1.0.0-SNAPSHOT.jar`.

## How to Run Tests

```bash
mvn test
```

## Demo

A small, zero-dependency HTTP server is included for live demonstration.
It uses Java's built-in `com.sun.net.httpserver` (no Spring, no database).

### Starting the demo

```bash
# Compile and start the demo server (default port: 8080)
mvn compile exec:java -Dexec.mainClass=com.safehtml.demo.DemoServer

# Or with a custom port
mvn compile exec:java -Dexec.mainClass=com.safehtml.demo.DemoServer -Dexec.args="9090"
```

Then open <http://localhost:8080/> in a browser.

### What the demo shows

```
UNTRUSTED HTML ──► SafeHTML Sanitizer ──► SANITIZED HTML (safe, escaped display)
                          │
                          └──► SECURITY REPORT (removed elements, attributes,
                                    blocked URLs, removed comments)
```

The browser UI includes:
- A **textarea** pre-filled with a malicious HTML example (editable)
- **Example attack buttons** (script injection, event handler, javascript: URL, SVG payload, harmless HTML)
- A **"Sanitize HTML"** button that sends the input to the backend
- A **Before/After** comparison showing the original input and the sanitized output side by side
- A **Security Report** with summary statistics and a detailed list of all modifications

### Example malicious input

```html
<p>Hello</p>
<script>alert('XSS')</script>
<a href="javascript:alert(1)">Click me</a>
<img src="x" onerror="alert(1)">
```

### Security considerations for the demo

- The sanitized HTML is displayed using `textContent` (never `innerHTML`), so
  it cannot be rendered as active HTML — preventing XSS in the demo itself.
- User input is never injected into server-side templates.
- `exec:java` is for local demonstration only.

> **This demo is for educational/portfolio purposes. It is not production-ready.**

## Roadmap

- [ ] Pluggable `AttributePolicy` interface for value-level checks (e.g.
      CSS class allowlist patterns)
- [ ] Optional CSS sanitization for the `style` attribute
- [ ] Support for `srcset` and other multi-URL attributes
- [ ] Fuzz testing with jazzer
- [ ] Performance benchmarking

## License

This project is released under the MIT License. See `LICENSE` for details.
