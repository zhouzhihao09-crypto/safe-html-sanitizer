# Security Policy

## Scope

The SafeHTML project provides an HTML sanitization library that reduces the risk
of cross-site scripting (XSS) and other content-injection attacks when rendering
untrusted HTML in Java applications.

**This library is experimental and educational.** It should not be the sole
defense against XSS in production systems.

## Supported Versions

| Version | Status       |
|---------|-------------|
| 1.x     | Experimental |

## Threat Model

SafeHTML defends against the following classes of attacks in the **serialized
HTML output**:

* **Script injection** — `<script>` elements and their content are always
  removed. Elements like `<style>`, `<iframe>`, `<object>`, `<embed>`, `<svg>`,
  `<math>`, etc. are also removed with their content.
* **Event-handler attributes** — all attributes whose name begins with `on`
  (case-insensitive) are stripped unconditionally. This cannot be bypassed by
  any policy configuration.
* **Dangerous URL protocols** — `href`, `src`, and other URL-bearing attributes
  are validated against a protocol allowlist. `javascript:`, `vbscript:`,
  `data:`, and `file:` URLs are blocked. Known dangerous elements are always
  removed regardless of whether the policy allows them.
* **HTML comments** — all comments are removed, preventing conditional-comment
  and other comment-based bypass techniques.
* **HTML entity obfuscation** — jsoup's parser decodes HTML entities before
  attribute values reach the URL validator, so entity-based obfuscation
  (e.g. `&#106;avascript:`) is mitigated.

## What SafeHTML Does NOT Protect Against

* **CSS-based attacks** — the `style` attribute is not in the default allowlist.
  If a developer explicitly allows it, CSS-based attacks (e.g.
  `expression()`, `url(javascript:...)`) are possible.
* **Encoding-based bypasses** — SafeHTML relies on jsoup's parser for entity
  decoding. Unusual encodings that jsoup does not decode are not handled.
* **Browser-specific quirks** — SafeHTML produces clean HTML; it does not
  replicate every browser's XSS-filter behavior.
* **Denial of service** — deeply nested or extremely large inputs are not
  specially handled. A very large input could consume significant memory.
* **Protocol-relative URLs** (`//evil.com`) — these are allowed because they
  inherit the page's protocol (http/https). This is intentional but could be
  surprising.

## URL Validation Decisions

| URL form                         | Status   | Reason                                  |
|---------------------------------|----------|-----------------------------------------|
| `https://example.com`            | Allowed  | In allowlist                            |
| `http://example.com`             | Allowed  | In allowlist                            |
| `mailto:user@example.com`        | Allowed  | In allowlist                            |
| `/relative/path`                 | Allowed  | No scheme (relative URL)                |
| `page.html`                      | Allowed  | No scheme (relative URL)                |
| `#fragment`                      | Allowed  | No scheme (fragment)                    |
| `//cdn.example.com/lib.js`      | Allowed  | No scheme (protocol-relative; inherits https) |
| `javascript:alert(1)`            | Blocked  | Not in allowlist                        |
| `JAVASCRIPT:alert(1)`            | Blocked  | Case-insensitive; not in allowlist      |
| `java\tscript:alert(1)`          | Blocked  | Control chars stripped; scheme extracted |
| `data:text/html,...`             | Blocked  | Not in allowlist                        |
| `vbscript:alert(1)`              | Blocked  | Not in allowlist                        |
| `file:///etc/passwd`             | Blocked  | Not in allowlist                        |

## Mandatory Protections (Cannot Be Bypassed)

These protections are enforced at the sanitizer level and cannot be disabled
or weakened by any `SanitizationPolicy` configuration:

1. **Always-blocked elements** — `script`, `style`, `iframe`, `object`,
   `embed`, `applet`, `frame`, `frameset`, `svg`, `math`, `head`, `meta`,
   `link`, `base`, `noscript`, `template`, `title`, `form`, `input`, `button`,
   `textarea`, `select`, `option`, `xmp`, `noembed`, `noframes`, and others.
   Even calling `allowElement("script")` in a custom policy will not permit
   these elements.
2. **Event-handler attributes** — any attribute beginning with `on` is always
   removed. Even calling `allowAttribute("onclick", "p")` will not preserve it.
3. **URL protocol validation** — any attribute registered via `allowUrl(...)`
   has its value validated against the protocol allowlist. This cannot be
   disabled.

## Reporting a Vulnerability

If you find a security vulnerability in SafeHTML:

1. **Do not** open a public issue.
2. Open a private GitHub Security Advisory on the repository:
   Navigate to the **Security** tab of the GitHub repository and click
   **Report a vulnerability**.
3. Include a description of the issue, steps to reproduce, and a suggested fix
   if possible.

We will acknowledge receipt within 72 hours and investigate promptly. Fixes will
be released as patch versions.

## Responsible Disclosure

We follow responsible disclosure. Please allow us time to investigate and
address the issue before public disclosure. We ask that you not disclose the
vulnerability to anyone outside the project maintainers until a fix is
available.
