# Information disclosure / PII leaks / stacktrace exposure / debug info

> Some items in this file are adapted from `cloudflare/security-audit-skill` (MIT License) — see [`THIRD_PARTY_NOTICES.md`](../../../THIRD_PARTY_NOTICES.md) for the license text and the full list of affected files.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `pii_in_logs` — logging PII / tokens / passwords in plaintext
- `stacktrace_exposed` — stacktrace / debug disclosure in response
- `hardcoded_secret` — cross-reference to `crypto.md` / `auth.md`
- `missing_authz` — a legitimate feature (export, backup, preview link) reachable without the same authorization check as its normal read path (cross-ref `auth.md`)
- `idor_lookup` — a legitimate feature (search, filter, sort, export) used as an oracle for records the caller cannot directly access (cross-ref `auth.md`)

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

## Export and backup as exfiltration

A legitimate export/backup/report feature is a data-access path like any other — it needs the same per-item authorization as the interactive read path, not just a permission check on triggering the export itself.

- An export/report-generation endpoint checks that the caller may "use exports" but not that the caller may read each row being exported — a low-privilege user's CSV/PDF export silently includes other users' or other tenants' records.
- Snapshot/backup download endpoint returns the full backup archive to any authenticated user, not only to an operator role.
- Export includes soft-deleted or draft records that the normal listing endpoint filters out.
- Export includes fields the normal serializer strips (internal notes, prior revision history, another user's contact details) because the export code path builds its output independently of the API serializer (cross-ref "API response leaks" above).

## Search, filter, and sort as oracle

A search/filter/sort endpoint enforces the same access-scoping as the resource it queries — otherwise it becomes a side-channel for content the caller cannot read directly.

- Search returns a hit count, snippet, or "did you mean" suggestion for records outside the caller's access scope, even when opening the record itself is correctly denied.
- A filter parameter accepts a value for a field the UI never exposes (e.g. `status=internal_review`, `role=admin`) and the backend applies it without checking whether the caller may filter on that field.
- Sorting by a field the caller cannot read (e.g. `?sort=internal_score`) leaks that field's relative ordering through result position even though the field itself is stripped from the response body.
- Autocomplete/typeahead endpoints query the full unscoped table and only filter the final response, so timing or partial-match behavior still discloses existence.

## Preview, draft, and staging leakage

- A preview/share token is scoped to "any draft" instead of the one document it was issued for — swapping the ID in the URL exposes another user's draft.
- Draft or unpublished content is included in a search index, sitemap, or RSS/Atom feed that a normal reader endpoint would exclude.
- A CDN or reverse-proxy cache rule caches a response by URL only, ignoring the `Authorization`/session context — a private/draft page served once to an authenticated user gets cached and then served to anonymous visitors.
- Staging/preview subdomain uses the same database as production without its own access controls, or is reachable without the authentication the production host enforces.

## Repository and git-history hygiene

- `TODO`/`FIXME`/`HACK`/`XXX` comments that reference a missing or bypassed security control (e.g. `// TODO: add auth check here`, `// FIXME: validate this input`).
- Seed/fixture/test credentials (`seed_admin@example.test` / `password123`) that are also valid against the production database because the seeding script runs unconditionally on every environment.
- `.env`, `.env.local`, `credentials.json`, `*.pem`, `*.key` committed to the repository (cross-ref `hardcoded_secret` in `crypto.md`).
- Lockfile absent or dependencies unpinned (`composer.json` without `composer.lock`, floating `^`/`~` ranges with no lockfile committed) — the deployed version is not reproducible from source, and known-CVE versions can be pulled silently.
- Secrets present only in git history: a value was committed and later removed in a subsequent commit, but the blob is still reachable via `git log -p` / `git show <old-commit>` — removal from the working tree is not revocation.
- A security fix visible as reverted, commented-out, or superseded by a later commit that reintroduces the original unsafe behavior (e.g. an `#[IsGranted]` / permission check added then removed in a follow-up commit without a documented reason).

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
