# Authentication, Authorization, IDOR, Disclosure-adjacent auth issues

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `missing_authz` — missing server-side permission check
- `idor_lookup` — access to a resource by ID without owner check
- `csrf_missing` — missing CSRF protection on a mutating endpoint
- `cors_misconfig` — `Access-Control-Allow-Origin: *` with credentials
- `webhook_unverified` — webhook without signature / replay protection
- `hardcoded_secret` — keys/tokens in the repository
- `oauth_state_missing` — OAuth/OIDC callback without state parameter / PKCE
- `oidc_misconfig` — OAuth/OIDC configuration flaw: loose `redirect_uri` matching, missing `aud`/`iss` validation, attacker-controlled issuer URL

## Confidence floor rules

- **Webhook endpoint without signature verification** (no `hash_equals`, no HMAC validation) → **confidence ≥ 9** for webhook_unverified.
- **`Access-Control-Allow-Origin: *`** together with `Access-Control-Allow-Credentials: true` → **confidence ≥ 9** for cors_misconfig.
- **OAuth callback without `state` check** (any flow, any vendor) → **confidence ≥ 9** for `oauth_state_missing`. Cross-ref `integrations/oauth-oidc/auth.md` for vendor-specific patterns. This is a defense-in-depth floor: when the integration is detected, the integration file gives a sharper signal; when it isn't (custom OAuth without a detected package), this core floor still catches it.

## Trusted patterns (do NOT flag)

- `random_bytes()`, `random_int()`, `\Random\Randomizer` (PHP 8.2+), `Str::random()` (Laravel — uses `random_bytes` under the hood on PHP 7+), `Symfony\Component\String\ByteString::fromRandom()` (uses CSPRNG internally), `secrets.token_bytes()` / `secrets.token_urlsafe()` / `secrets.token_hex()` (Python) — CSPRNG, secure by construction. **Not** `weak_random`. This is the canonical CSPRNG list referenced from `_meta.md`.
- `hash_equals()` (PHP), `hmac.compare_digest()` (Python) — constant-time comparison. This is the secure alternative to `==`/`===` for secrets; do not flag as timing-attack risk.
- `password_hash($pwd, PASSWORD_BCRYPT)` / `password_hash($pwd, PASSWORD_ARGON2ID)` / `password_hash($pwd, PASSWORD_DEFAULT)` — these ARE the recommended primitives for password storage; do not flag as `weak_hash`. Pair with `password_verify()` (constant-time).
- `Symfony\Component\Security\Csrf\CsrfTokenManager`, Laravel `@csrf` / `csrf_token()` directives — framework-managed CSRF protection; flag only when the token check is explicitly bypassed or the endpoint is excluded from the CSRF middleware.

## IDOR

- Fetching a resource by ID from request without an owner check: ORM-lookup like `repository.find($request->...)` / equivalent without comparison to the current user
- Auto-binding of a path parameter into an entity without an authz check in the handler (any framework value resolver / param converter)
- Predictable sequential IDs (`/orders/123`, `/orders/124`) without UUID or authz
- Access to other users' files via `/download?file=...` without ownership verification

## JWT and tokens

JWT-specific patterns: see `integrations/jwt-generic/auth.md` (auto-loaded when JWT use is detected). Includes `alg: none`, algorithm confusion, `kid`/`jku`/`jwk` header injection, claim validation, token storage and rotation.

## OAuth/OIDC

OAuth 2.0 / OpenID Connect patterns: see `integrations/oauth-oidc/auth.md` (auto-loaded when OAuth client/server use is detected). Includes `state`/PKCE, `redirect_uri` exact-match, token swap via login CSRF, OIDC `id_token` validation, server-side authorization endpoint hygiene.

## MFA / lifecycle

- TOTP replay in a window of ±N seconds without drift-counter / proof-of-burned-code.
- Recovery codes without single-use enforcement and without re-hash on consumption.
- MFA enrollment via self-service without verification proof-of-current-session.
- `remember-device` cookie without TTL / UA-binding / IP-binding (loses MFA gate forever).
- Email change via self-service without confirming the new address (account takeover via email).
- Password change without invoking `logoutOtherDevices()` / `invalidateSessions()` — old sessions remain active.
- Account merge / soft-delete restore across a tenant boundary (restoring into another tenant).

## Password reset / impersonation

- Password reset token: predictable, not invalidated after use, stored plaintext
- Missing TTL for the reset token
- Account enumeration via different responses for "user exists" vs "user not found" on the reset endpoint
- Impersonation without logging / without checking admin role on the source user

## Signed URLs

- URL with a signature where the signature is computed from a partial payload (easy to forge)
- Signed URL without expiration (valid forever)
- Signed URL with user-controlled `path` without verification that the path is within whitelisted scope

## Webhook signature verification (incoming webhooks)

- Webhook endpoint accepts requests without verifying `X-Signature` / HMAC
- Verification via `==` instead of `hash_equals()` (timing attack)
- Missing replay protection: webhook can be replayed, no `nonce` / `timestamp` with a short window
- Missing idempotency key: reprocessing the same webhook triggers duplicate side-effects

## CSRF

- API endpoint with cookie-based authentication accepting mutating requests without a CSRF / anti-forgery token
- `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` (cross-ref CORS misconfig)

## Tenancy trust anti-patterns (internal/service firewalls with a shared secret)

Typical pattern of internal firewalls / service-to-service auth: handler accepts a shared-secret header (e.g. `X-Internal-Auth`, `X-Service-Key` or similar) and authenticates the **service**, not the **tenant**. Controllers then use a tenant-owner field (`tenantId` / `workspaceId` / `ownerId`) from the **request body or URL** without cryptographic binding to the authenticating secret. One compromised shared service secret → cross-tenant operations against any tenants.

- **Service-level auth accepts tenant-ID from body**: handler reads body / DTO with tenant-owner field and writes to DB without verifying that the call source actually represents this tenant. **confidence ≥ 8**, sink_kind `missing_authz`, root_cause `authz`.
- **Missing HMAC binding of body to tenant-ID**: internal API expects `Authorization: Bearer <service_secret>` but does not require `X-Tenant-Signature: hmac(body, tenant_secret)`. A shared secret does not prove the right to act on behalf of the specified tenant.
- **Identity headers without signature**: identity headers like `X-User-Id` / `X-Tenant-Id` / `X-Role` from an upstream proxy without HMAC/JWT — downstream trusts the headers, but anyone who bypassed the proxy (direct access to pod/node, SSRF through a neighboring service) can forge them.
- **Shared secret identical across all consumer services**: rotation requires simultaneous edits everywhere; compromise of one consumer = compromise of the whole contour. Should be per-service subject with separate keys.
- **Service auth via `in_array($secret, $validSecrets, true)` instead of `hash_equals`**: timing attack when comparing shared secrets. See `crypto.md`.
- **Missing IP CIDR / mTLS for internal endpoints**: internal API exposed on a public interface relying solely on a header check. Any SSRF in a neighboring service → cross-tenant write.

## Throttling / rate limiting (absence of defense is also a finding)

"There is no defensive code" — report it, not only "defensive code is vulnerable".

- **No throttling on login endpoint** (form_login / json_login / any password-based login) → brute-force / password spray. **confidence ≥ 8**.
- **No rate-limit on a public mutating endpoint** (password reset request, signup, contact-form) → enumeration / spam / resource exhaustion across auth surfaces.
- **No rate-limit on a webhook receiver** → replay storm against a downstream service.
- **No account lockout / delay after N failed reset/login attempts** → enumeration via timings and different HTTP codes.

## Hardcoded secrets

- API keys, passwords, tokens directly in code (`$apiKey = "sk_live_..."`)
