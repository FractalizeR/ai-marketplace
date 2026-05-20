# Information disclosure / PII leaks / stacktrace exposure / debug info

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `pii_in_logs` — logging PII / tokens / passwords in plaintext
- `stacktrace_exposed` — stacktrace / debug disclosure in response
- `hardcoded_secret` — cross-reference to `crypto.md` / `auth.md`

## Confidence floor rules

- **Plaintext PII in logs** (`$logger->info(..., ['password' => $plain])`, `['email' => ..., 'passport' => ...]`) → **confidence ≥ 9** for pii_in_logs.
- **`$exception->getTraceAsString()` in API response in production** (not in a debug branch) → **confidence ≥ 9** for stacktrace_exposed.
- **`$logger->debug($request->getContent())`** when the body contains credentials/tokens/PII → **confidence ≥ 8**.
- **Sequential ID in API** (`/user/1`, `/user/2`, ...) without rate-limit + without authz → **confidence ≥ 8** for idor_lookup (cross-ref `auth.md`).

## Logging sensitive data

- `$logger->info('user login', ['password' => $plaintext])`
- Password / token in request log middleware
- `$logger->debug('payload', [$request->getContent()])` — body contains credit card / password
- Exception logging with `$exception->getTrace(true)` — trace may contain parameters with secrets
- PII (passport, INN, email, phone) at info/debug levels
- Session ID in access logs
- Database query logs with parameter values (any ORM SQL logger in production)

## PII handling (152-FZ / GDPR)

- Storing passport data, INN, SNILS in plaintext columns instead of encrypted ones
- Biometric data without explicit consent
- Missing audit log of PII access (who and when read it)
- PII in URLs (`/user/vladimir.ivanov@example.com/profile`) — ends up in logs, referer, browser history
- PII in GET parameters (must be POST-only)
- Missing data retention policy: old data stored without a term

## API response leaks

- Serialization without selective field whitelist → the entire object with internal fields goes to the client
- `email`, `phone`, `hashedPassword`, `lastLoginIp` returned to clients that do not need them
- Relationships are serialized in full (`user -> orders -> transactions`) — excessive disclosure
- Error response with `$exception->getMessage()` in production — leaks internal details (DB name, file path)
- `__debugInfo()` implementations rendered into API response

## Stacktrace / debug info

- Custom error handler returning `$exception->getTraceAsString()` in the body
- PHP `display_errors=On` in production
- Uncaught exception in a JSON API → leak via default framework handler if no exception listener is registered

## Source code exposure

- `.git/` directory deployed to a web-accessible location
- `.env`, `.env.local` readable via the web (incorrect Nginx/Apache configuration)
- `composer.json` / `package.json` accessible — leak of dependencies (version info + CVE lookup)
- Backup files: `config.php.bak`, `config.old` in web root
- Source maps (`*.js.map`) in production — leak full original JS source

## API enumeration

- Different response timing for "user exists" vs "user doesn't exist" on login/reset — enumerate users
- Different HTTP status code (401 vs 404) for existing/non-existing resources
- Error message: `"User already exists"` vs `"Invalid credentials"` — reveals account presence
- Pagination with precise counts → enumerate total records
- Sequential IDs in API (`/user/1`, `/user/2`, ...) — enumerate via increment (cross-ref IDOR in `auth.md`)

## Response headers

- `Server: Apache/2.4.41 (Ubuntu)` — leak server version (CVE targeting)
- `X-Powered-By: PHP/7.4.3` — leak PHP version
- `Via:` headers revealing internal proxies
- `X-AspNet-Version`, etc

## Session cookies

- Session cookie without `HttpOnly` → accessible to JS (XSS → session theft)
- Without `Secure` → transmitted over HTTP (if MITM)
- Without `SameSite=Lax/Strict` → CSRF vector
- Long-lived session without idle timeout
