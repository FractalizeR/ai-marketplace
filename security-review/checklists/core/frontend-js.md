# Frontend JavaScript (Ember / Vue / Stimulus / plain JS)

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `unsafe_html_render` — `innerHTML` / `v-html` / `{{{...}}}` with user input
- `cors_misconfig` — `Access-Control-Allow-Origin: *` with credentials
- `hardcoded_secret` — tokens in localStorage / sessionStorage

## General JavaScript

- `innerHTML`, `outerHTML`, `insertAdjacentHTML` with user input — XSS
- `eval(str)`, `new Function(str)`, `setTimeout(str, ...)`, `setInterval(str, ...)` with user input — RCE in the browser
- `document.write()`, `document.writeln()` with user input
- Prototype pollution: `Object.assign(target, userInput)` where userInput contains `__proto__`
- CORS misconfiguration: `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`
- `postMessage`: handler without `event.origin` check
- WebSocket: connection to a user-controlled URL without a whitelist
- JWT in `localStorage` instead of an httpOnly cookie
- Credentials in query params (logs, referer leak)
- Client-side routing: sensitive data (token, email) in URL/query without redacting

## Ember.js

- Handlebars: `{{{unescaped}}}` (triple-stash) with user input — XSS
- `htmlSafe()`, `Ember.String.htmlSafe()` with untrusted data
- DOM manipulation via `this.$()` with concatenation
- Computed properties: race conditions on async with critical data
- Ember Data: leak of sensitive attributes into JSON API responses
- Unsafe relationship serialization
- Services: storing tokens in localStorage
- Actions: handling user input without validation before sending to the backend

## Vue.js

- `v-html="userInput"` — direct XSS
- `:is="userInput"` (dynamic components) with untrusted input
- `v-bind:innerHTML`, `domProps.innerHTML`
- Unsafe binding in `href`, `src`: a check for `javascript:` and `data:` URIs is mandatory
- Vuex: storing tokens/passwords in state (leak via Vue DevTools in prod)
- `mounted()`, `created()` with user-controlled operations without validation

## Stimulus / asset pipelines

- Stimulus controllers accepting data attributes without validation → DOM XSS if they reach `innerHTML`
- `importmap.php`: import URL with user-controlled fragments
- Webpack entries with user-controlled parameters in build config (rare, but possible in dev-server)
- `HtmlWebpackPlugin` templates with unsafe inject logic

## API / AJAX calls

- Missing CSRF tokens on mutating operations via cookie auth
- Credentials (tokens, API keys) in query parameters
- User-controlled URL in `fetch()` / `XMLHttpRequest` without validation (SSRF, open redirect to external URLs)
- Missing check of response `Content-Type` before parsing as JSON (MIME sniffing attacks)

## LocalStorage / SessionStorage

- Storing passwords, JWT, secrets in plaintext
- Storing user email/PII with XSS risk (any XSS → exfiltration)
- `localStorage.setItem('token', ...)` — token is accessible to any JS on the page
