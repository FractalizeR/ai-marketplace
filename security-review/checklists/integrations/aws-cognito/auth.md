# Authentication / Authorization (AWS Cognito)

> This checklist extends `core/auth.md` for projects that use AWS Cognito User Pools for authentication. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

> **Layering note**: Cognito User Pools issue OIDC-style JWTs. The worker also loads `integrations/jwt-generic/auth.md` and `integrations/oauth-oidc/auth.md` for the underlying mechanics. This file documents the **Cognito-specific** patterns on top of those.

## Confidence floor rules

- **Wrong token-type used for application-level authorization** (e.g., reading user identity / `email` from an access token — access tokens don't include `email`; or reading `scope` / `client_id` from an ID token — ID tokens don't include `scope`) → `oidc_misconfig` **confidence ≥ 8**. The two tokens have different purposes; the receiving code MUST validate the `token_use` claim (`id` vs `access`) matches the expected usage. NOTE: `cognito:groups` is present on BOTH the ID token and the access token by default, so it is NOT a useful discriminator for token-type confusion bugs — the discriminating claims are `email` (ID only) and `scope` / `client_id` (access only).
- **App client secret committed to git** for a confidential client → `hardcoded_secret` confidence ≥ 9 (same floor as `core/auth.md` for any committed credential).

## JWT validation specifics

- **`iss` exact match required**: Cognito ID and access tokens carry `iss = https://cognito-idp.{region}.amazonaws.com/{user_pool_id}` — note: no trailing slash, region MUST match, user-pool-id MUST match. Verifier that compares prefix-wise or accepts any `cognito-idp.*.amazonaws.com` accepts tokens from foreign user pools (cross-tenant). Sink: `oidc_misconfig`.
- **JWKS endpoint location**: `<iss>/.well-known/jwks.json`. A verifier that hardcodes a JWKS URL (e.g. baked into a PEM file) does not pick up key rotation — when AWS rotates signing keys (which happens), all live tokens reject. Symptom: project disables signature check "to fix login" — that's the failure mode to look for. Sink: `oidc_misconfig`.
- **`token_use` claim** must be either `id` or `access`; the receiving code must check `token_use` matches the token's intended role. A backend that calls `getUserAttributes()` on an access token (which doesn't carry user attributes) or that reads `email` from an access token (which doesn't have it) is wired wrong AND opens forgery via swapped tokens. Sink: `oidc_misconfig`.

## ID token vs Access token confusion

Cognito issues TWO tokens per session:

- **ID token** — contains user identity (`email`, `phone_number`, custom attributes). Used to identify WHO the user is. Does NOT contain `scope` or `client_id`.
- **Access token** — contains `scope`, `client_id`, `token_use=access`. Used to identify WHAT the user is allowed to do. Does NOT contain `email` or other PII.
- **`cognito:groups`** — present on BOTH tokens by default. Not a discriminator for token-type confusion bugs.

The split is non-obvious; failure modes:

- **Backend reads identity (e.g. `email`) from the access token** — claim is empty → user "logged in" as no-name (or anonymous identifier). Sink: `oidc_misconfig`. Secondary impact depending on downstream code.
- **Backend reads `scope` / `client_id` from the ID token** — claim is empty → scope check silently fails open. Sink: `oidc_misconfig`.
- **Backend accepts EITHER token interchangeably** (no `token_use` check) — attacker submits an ID token where an access token is expected, bypassing scope checks. Sink: `oidc_misconfig`.
- **Backend uses `cognito:groups` from one token-type when it expected the other** — this is NOT inherently a bug (both tokens carry the claim by default), but flag it as a code smell: the choice should be deliberate and documented, otherwise a future Cognito config change (e.g. removing the claim from one token via pre-token-generation lambda) will silently break authz.

## Custom attributes

Cognito custom attributes are prefixed `custom:` — e.g. `custom:tenant_id`, `custom:role`. The backend must read them with the prefix.

- **Backend reads `tenant_id` without the `custom:` prefix** — the value is `None` and the code silently fails open (multi-tenant isolation broken if the comparison is `if (record.tenant_id === request.tenant_id)` and both sides are `None`). Sink: `missing_authz`.
- **`custom:` attributes used for security-sensitive data without an enforced verifier**: Cognito custom attributes are writable from the user pool admin or via lambda triggers — they are not signed independently of the JWT. If the issuance pipeline allows the user to influence their own custom attributes (e.g., a self-service profile page that copies a request field to a custom attribute), the attacker can elevate themselves.

## App client / flow configuration

- **Public client (no secret) with `ALLOW_ADMIN_USER_PASSWORD_AUTH` flow enabled**: backend's admin password flow accepts username + password without app-secret authentication → credential stuffing via the API. Mitigation: confidential client OR `ALLOW_USER_SRP_AUTH` only. Sink: `oidc_misconfig` (with `core/auth.md` `weak_random` cross-ref if the username is enumerable).
- **`USER_PASSWORD_AUTH` enabled on a confidential client**: sends the user's password in cleartext to Cognito (over TLS). Functional but trades SRP's defense in depth for one PII channel — flag if MFA isn't required.
- **`ALLOW_CUSTOM_AUTH` enabled without a custom lambda**: malformed config; ignored at runtime — flag as missing-defense.

## Identity Pool vs User Pool

Cognito has two distinct products:

- **User Pool** — the IdP (what this checklist covers).
- **Identity Pool** — federation → temporary IAM creds for AWS resources.

Mixing them in IAM policy or in app-level authz is a privilege-escalation footgun:

- **Identity Pool credentials trusted for app-level authz**: STS-issued temporary creds attached to an Identity Pool are AWS IAM credentials, not user authz tokens. App code that pulls IAM "user" from `STS.GetCallerIdentity` and uses it as the user identifier bypasses the User Pool's authorization model entirely. Sink: `missing_authz`.

## Hosted UI / Custom domain

- **Hosted UI on a custom domain without CloudFront WAF**: Cognito's hosted UI is per-region; if it's exposed on a custom domain (via a `Domain` resource) without WAF or other rate limiting, login becomes susceptible to credential stuffing at API rates. Architecture-level finding; report as missing defense.
- **Hosted UI `redirect_uri` allowlist by domain only**: any path under the registered host accepts the callback → open-redirect via path takeover (legit `app.example.com/dashboard` vs attacker `app.example.com/static/uploaded.html` if upload paths are allowed). Sink: `oidc_misconfig`.

## Worker search patterns

- `CognitoIdentityProviderClient` constructor — check `region`, `version`, and the credential source (must be SDK default chain, never literal keys).
- `->getCookie()` / `->getCredentials()` post-`InitiateAuth` — verify the result is treated according to `token_use`.
- `JWT::decode($idToken, ...)` against a Cognito JWKS URL — confirms the issuer is constructed correctly; cross-ref `integrations/jwt-generic/auth.md`.
- `.env` keys `COGNITO_*`, `AWS_COGNITO_*` — verify secrets are not committed.
