# Authentication / Authorization (Auth0)

> This checklist extends `core/auth.md` for projects that use Auth0 for authentication. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

> **Layering note**: Auth0 issues OIDC-compliant JWTs. The worker also loads `integrations/jwt-generic/auth.md` and `integrations/oauth-oidc/auth.md` for the underlying mechanics (algorithm confusion, `state`, PKCE, …). This file documents the **Auth0-specific** patterns on top of those.

## Confidence floor rules

- **Auth0 Management API client secret committed to git** (literal in code, `.env` committed, `config/auth0.php` with a real value rather than `env(...)`) → `hardcoded_secret` **confidence ≥ 9**. The Management API secret grants tenant administration: user creation, role assignment, rule injection — total IdP compromise.
- **Embedded (custom-domain or `/co/authenticate`) login used on a production tenant** instead of Universal Login → `oidc_misconfig` **confidence ≥ 8**. Embedded login is documented as vulnerable to credential stuffing; Auth0's own recommendation is Universal Login on every production tenant.
- **JWKS endpoint (`https://{tenant}.auth0.com/.well-known/jwks.json`) fetched without TLS verification** (`verify_peer=false`, `CURLOPT_SSL_VERIFYPEER => false`, allow-self-signed Guzzle context) → `tls_validation_bypass` confidence ≥ 9.

## JWT validation specifics

- **`iss` mismatch** with the tenant URL. Auth0 issuers always end in a TRAILING SLASH: `https://{tenant}.auth0.com/`. A verifier that compares against `https://{tenant}.auth0.com` (no slash) silently rejects ALL real tokens during dev, then often "fixes" the issue by disabling the check entirely. Look for code that constructs the expected issuer without the trailing slash AND for code that disabled the issuer check after such a mismatch. Sink: `oidc_misconfig`.
- **`aud` mismatch** — Auth0 audiences for API tokens must equal the API identifier configured in the Auth0 dashboard (an arbitrary URI string, not necessarily a real URL). A verifier that accepts any `aud` or uses `client_id` (only valid for ID tokens) accepts cross-API tokens. Sink: `oidc_misconfig`.
- **JWKS endpoint without TLS validation** — `https://{tenant}.auth0.com/.well-known/jwks.json` fetched via a Guzzle / curl client with TLS verification disabled. Attacker MitMs the JWKS response and supplies their own keys. Sink: `tls_validation_bypass` (cross-listed in `core/crypto.md`).
- **Auth0 Authentication API token confused with Management API token**: the Auth0 SDK can mint two distinct tokens. The Management API token has audience `https://{tenant}.auth0.com/api/v2/` and grants tenant-level administration. App code that accepts ANY token with a matching issuer (without checking `aud`) treats a Management API token as a user token — privilege escalation. Sink: `oidc_misconfig`.

## Custom claims namespace

Auth0 forces APPLICATION-defined custom claims to be inside a URI namespace (e.g. `https://yourapp.com/role`, `https://yourapp.com/tenant_id`). The platform silently drops top-level claim names that collide with reserved JWT claim names — application-defined `role` / `groups` / `department` etc. must go inside the namespace.

- **Backend reads a flat APPLICATION claim** like `role` from the token without the namespace prefix — the value is `null` for tokens minted by Auth0 (because the platform dropped that property at issuance) and silently fails open (`if ($role === 'admin') { ... }` returns false, fall-through to default deny? or fall-through to default allow?). Worse: tokens forged via Rules / Actions manipulation that DO include a flat `role` claim are then accepted. Sink: `oidc_misconfig`.
- **Worker search pattern** — grep for `->getClaim('role')`, `$claims['role']`, `$claims['groups']` (etc.) without a `https://` namespace; cross-check that the corresponding Action/Rule writes claims to the same namespace.

### `permissions` claim — Auth0 RBAC standard claim (NOT custom)

When Auth0 RBAC is enabled in the API settings ("Enable RBAC" + "Add Permissions in the Access Token"), Auth0 ALWAYS emits `permissions` as a STANDARD top-level claim in the access token (it is NOT namespaced). Do not group `permissions` with the application-defined custom claims above.

The Auth0-RBAC failure modes are different:

- **RBAC toggle ON in the dashboard, but backend ignores `permissions` and re-derives authz from custom `role` / `groups`** — the RBAC pipeline is bypassed; permissions assigned to a user via the Auth0 dashboard have no effect. Cross-ref: missing-defense. Sink: `oidc_misconfig`.
- **"Add Permissions in the Access Token" OFF in the API settings** — the access token has no `permissions` claim; backend that reads it gets `null` and silently fails open. Surfaces during config drift. Sink: `oidc_misconfig`.
- **Backend reads `permissions` from the ID token** — `permissions` lives on the access token only. Cross-listed with the token-type confusion section above.
- **Backend trusts user `app_metadata.permissions`** from a `/userinfo` lookup instead of the RBAC-enforced access-token claim — `app_metadata` is dashboard-administered but mutable via the Management API; if a Rule/Action copies user-controlled input there, attacker can self-grant permissions. Use the access token's `permissions` claim, which is enforced by Auth0 RBAC.

## Auth0 Rules / Actions

Auth0 Rules (legacy) and Actions (current) are JavaScript snippets that run during the login pipeline. They are NOT in the project's git tree by default — they live in the tenant configuration. Worker observations are limited to call sites that read claims those rules produce.

- **Rule / Action logs the full `user` object**: code with `console.log(user)` or `api.access.deny(\`bad user ${user.email}\`)` exfiltrates email + PII into Auth0 log streams (and often into log forwarders like Datadog / Splunk). Architecture-level finding; cross-ref `core/disclosure.md` (`pii_in_logs`). Surface this whenever the project's Rules/Actions code is in the repo (some teams version-control them as `auth0-actions/`).
- **Rule / Action exposes secrets via the `configuration` object**: Auth0's `configuration` is meant for shared keys, but values are stored in plaintext and accessible to every Rule/Action. A secret leaked here is leaked to every other rule.

## Connection / identity provider mismatches

Auth0 tokens carry a `sub` claim of shape `{connection}|{provider_user_id}` — e.g. `google-oauth2|108…`, `email|abc123`, `auth0|abc123`.

- **Connection field not validated**: the backend trusts `sub` (or the user record fetched from Auth0) without checking `connection`. Attacker who can social-link an attacker-controlled Google account to a victim's email (or registers a username/password account with the victim's email if email verification is off) takes over the victim's account. Sink: `missing_authz`.
- **Email verification not enforced** before granting access via a social connection: `email_verified` defaults to true for some providers, false for others. Code that doesn't gate on `email_verified === true` accepts unverified emails — attacker registers `victim@target.tld` via a provider that doesn't verify ownership and gets in. Cross-ref `core/auth.md` (account-takeover via email-trust).

## Token lifecycle

- **Refresh token rotation not enabled**: Auth0 supports rotation but it's opt-in (`Application Settings → Refresh Token Rotation`). Without rotation, a stolen refresh token grants indefinite access. Cross-ref `integrations/jwt-generic/auth.md`. Report as missing-defense.
- **Refresh token reuse detection not enabled**: even with rotation, the reuse-detection toggle must be on — that's what causes Auth0 to revoke the family on reuse.
- **Universal Login not enforced for sensitive operations**: re-authentication for high-risk flows (password change, MFA enrollment) should require Universal Login; embedded prompts that reuse the existing session can be triggered silently.

## Worker search patterns

- `\\Auth0\\SDK\\Auth0` / `\\Auth0\\SDK\\Configuration\\SdkConfiguration` — SDK construction sites; check `tokenAlgorithm` (must not be `HS256` for OIDC mode with JWKS), `audience`, `issuer`.
- `Auth0::client_credentials_grant(` / `->management()` — Management API entry points; the secret used here must come from env / KMS, never literal.
- `assertWithSubject(` / `JWT::decode(` against Auth0 issuer — usually means a hand-rolled verifier; the JWT-generic checklist applies in full.
- Config keys `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, `AUTH0_CLIENT_*` in `.env*` — verify the secret is not committed; the `.env.example` should hold placeholders only.
