# Security headers

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Recommended sink_kinds

- `csp_missing` — no Content-Security-Policy header on an HTML-rendering response
- `csp_unsafe_inline` — CSP present but weakened by `unsafe-inline` / `unsafe-eval` / wildcards / static nonce / report-only-without-enforce
- `clickjacking_unprotected` — neither `frame-ancestors` (CSP) nor `X-Frame-Options: DENY/SAMEORIGIN` set on a sensitive page
- `hsts_missing` — no `Strict-Transport-Security` on an HTTPS endpoint (or too short `max-age` / missing `includeSubDomains` on multi-domain setup)
- `mime_sniff_unprotected` — no `X-Content-Type-Options: nosniff`
- Cross-reference: `core/disclosure.md` covers `Server:` / `X-Powered-By:` / cookie flags (over-disclosing headers). This file covers *missing* defensive headers. When CSP gaps amplify XSS, the underlying sink remains `unsafe_html_render` (see `core/frontend-js.md`); CSP-missing is the defense-in-depth amplifier, dedupe handles via `[CROSS_SINK_MERGE]`.

## Confidence floor rules

- HTML-rendering route without any CSP header (`Content-Security-Policy` absent from the response) + inline `<script>` blocks in the rendered page → **confidence ≥ 8** for `csp_missing` (concrete XSS amplifier — any reflected/stored XSS becomes unmitigated).
- CSP header present but `script-src` contains `unsafe-eval` or `unsafe-inline` in production (no nonce/hash mechanism) → **confidence ≥ 8** for `csp_unsafe_inline` (policy provides false sense of security; bypass is trivial).
- Login / admin / fund-transfer page with no `X-Frame-Options` and no `frame-ancestors` directive in CSP → confidence ≥ 8 (`clickjacking_unprotected`).
- `Strict-Transport-Security: max-age=0` in production response → confidence ≥ 9 (`hsts_missing`) — explicit downgrade, not configuration mistake.
- User-upload / user-download endpoint returning user-controlled `Content-Type` without `X-Content-Type-Options: nosniff` → confidence ≥ 8 (`mime_sniff_unprotected`).

## Content-Security-Policy

- HTML responses returned without any `Content-Security-Policy` header — every reflected/stored XSS goes unmitigated (no defense-in-depth)
- `script-src 'unsafe-inline'` or `script-src 'unsafe-eval'` in production CSP — inline `<script>` and `eval()`/`new Function()` permitted, defeats the policy
- `default-src *` / `script-src *` / `style-src *` / any wildcard in sensitive directives — equivalent to no policy
- Static nonce — the same `nonce-<value>` reused across requests (cached in a config file, env var, or hardcoded string). Attacker scrapes one nonce and embeds it in their payload → CSP bypassed
- `Content-Security-Policy-Report-Only` deployed without an enforce-mode `Content-Security-Policy` header alongside (in production, not staging). Reports flow but nothing is blocked — false sense of security
- `data:` in `script-src` / `default-src` — allows `<script src="data:text/javascript,...">` (XSS via SVG, data URI smuggling)
- Inline `<script>...</script>` in templates while CSP permits `unsafe-inline` — typical "temporary exception" that becomes permanent. Cross-ref: when CSP is later hardened, the inline blocks become broken behaviour, motivating regression to `unsafe-inline`
- `script-src 'self' https:` — `https:` schema-source is effectively a wildcard for all HTTPS origins
- `script-src 'self' 'unsafe-hashes'` with hashes covering inline event handlers (`onclick`, `onload`) — typically misused to allow inline event handlers globally
- `object-src` not set to `'none'` — Flash/embed/object vectors remain (less relevant in 2025, but still seen in policies copied from older guides)
- `base-uri` not constrained → injected `<base href="//evil.com/">` reroutes every relative URL on the page
- `connect-src *` (or `default-src *` with no override) — open XHR/fetch/WebSocket exfiltration channel for any in-page script.
- `frame-src *` — arbitrary iframes can be embedded; phishing surface and amplifier for any reflected-content vulnerability.

## Clickjacking

- Neither `Content-Security-Policy: frame-ancestors 'none'` / `'self'` **nor** `X-Frame-Options: DENY` / `SAMEORIGIN` set on sensitive surfaces (login form, admin panel, transfer-funds page) — clickjacking attack possible via hidden iframe overlay
- `X-Frame-Options: ALLOW-FROM <uri>` — deprecated, not honored by Chrome/Edge/Firefox in 2025. Treat as "no protection" → must be `frame-ancestors` in CSP
- `X-Frame-Options: ALLOWALL` — explicit opt-out (sometimes from old config snippets)
- `frame-ancestors` directive in `<meta http-equiv="Content-Security-Policy">` tag — browsers ignore `frame-ancestors` when delivered via meta tag (per CSP spec). Must be a real HTTP header

## MIME sniffing

- Missing `X-Content-Type-Options: nosniff` on file-download / user-upload endpoints — browser may sniff content and render an attacker-controlled `.txt` as HTML/JS
- `Content-Type: text/html` returned for a user-uploaded `.svg` without `nosniff` — SVG can carry inline `<script>` → stored XSS

## HSTS (Strict-Transport-Security)

- No `Strict-Transport-Security` header on HTTPS endpoints — first-visit MITM downgrade possible (no protection until first successful HTTPS response with HSTS)
- `Strict-Transport-Security: max-age=<N>` with `N < 31536000` (1 year, the HSTS preload-list minimum) — short window allows downgrade after expiry; common values 86400 (1 day) / 604800 (1 week) are too short for production. OWASP recommends 63072000 (2 years) for preload submissions.
- Missing `includeSubDomains` while the application serves on `*.example.com` (auth subdomain, admin subdomain) — attacker pivots through unprotected subdomain
- Missing `preload` directive + not on the HSTS preload list — first-ever visit still vulnerable to SSL strip
- HSTS set on HTTP responses (instead of HTTPS-only) — header is ignored over HTTP by spec; sign of misconfigured middleware
- HSTS `max-age=0` left from a debugging session — disables HSTS for the cached duration

## Referrer-Policy

- Header absent → browser default is `strict-origin-when-cross-origin` (modern) or `no-referrer-when-downgrade` (legacy) — full path + query leaks in `Referer` to cross-origin links
- `Referrer-Policy: unsafe-url` — forces full URL leakage, never appropriate on authenticated pages
- Path/query carries tokens, password-reset hashes, session identifiers — even with the modern default, internal redirects (HTTPS→HTTPS, different origin) still leak path+query to third-party analytics

## Permissions-Policy (formerly Feature-Policy)

- Header absent on authenticated pages → camera/microphone/geolocation/payment APIs available to any iframe embedding the surface and any third-party script. Severity scales with whether the page is iframeable (combine with missing `frame-ancestors`).
- `Permissions-Policy: <feature>=*` — explicit wildcard equivalent to no policy
- `Feature-Policy:` header alone (legacy) — modern browsers honor `Permissions-Policy`; legacy header ignored. Sign of stale config
- Authenticated page embedded as an iframe by a third party + missing `Permissions-Policy` → the embedding origin gains access to the user's camera/mic through the embedded UI

## COOP / COEP / CORP

- Missing `Cross-Origin-Opener-Policy: same-origin` on pages that open popups (OAuth flow, admin actions) — `window.opener` leak from popup chains (XS-Leaks); attacker page opened via `window.open` retains a reference back to the parent
- Missing `Cross-Origin-Embedder-Policy: require-corp` on pages that use `SharedArrayBuffer` / high-resolution timers → Spectre-class side channels exploitable
- Missing `Cross-Origin-Resource-Policy: same-origin` on sensitive JSON endpoints — endpoint embeddable as `<script>` from a third-party origin (XS-Search / XS-Leaks)
- `Cross-Origin-Resource-Policy: cross-origin` on private endpoints (`/api/me`, `/api/profile`) — should be `same-origin` / `same-site`
