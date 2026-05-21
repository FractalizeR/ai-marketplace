# Authentication / Authorization (Keycloak)

> This checklist extends `core/auth.md` for projects that use Keycloak for authentication. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

> **Layering note**: Keycloak is OIDC-compliant. The worker also loads `integrations/jwt-generic/auth.md` and `integrations/oauth-oidc/auth.md` for the underlying mechanics. This file documents the **Keycloak-specific** patterns on top of those.

## Confidence floor rules

- **`KEYCLOAK_CLIENT_SECRET` committed to git** (in code, in `.env` committed to the repo, in `config/*.yaml` with a real value rather than `env(...)`) → `hardcoded_secret` **confidence ≥ 9**. The client secret allows server-side impersonation of the confidential client.
- **JWKS endpoint fetched without TLS verification** → `tls_validation_bypass` confidence ≥ 9 (cross-listed in `core/crypto.md`). Keycloak deployments are often self-signed in lower environments — verify the production code path enforces TLS.

## Realm URL structure

Keycloak organizes everything by realm. Realm-level URLs:

- Token endpoint: `https://{server}/realms/{realm}/protocol/openid-connect/token`
- Userinfo: `https://{server}/realms/{realm}/protocol/openid-connect/userinfo`
- JWKS: `https://{server}/realms/{realm}/protocol/openid-connect/certs`
- Issuer: `https://{server}/realms/{realm}`

The `master` realm is Keycloak's admin realm — tokens issued by `master` carry Keycloak-administrator-level claims:

- **App code accepts tokens from `master` realm** as user tokens — privilege escalation: any Keycloak admin becomes an app admin. Look for code that compares `iss` against the server host alone or that doesn't include the realm name. Sink: `oidc_misconfig`.

## Audience validation

Keycloak access tokens default to `aud` containing `account` (Keycloak's built-in self-account API) — they do NOT automatically contain the app's `client_id` unless configured via a "audience mapper" on the client.

- **Missing `aud` check** — any Keycloak-issued token for the same realm passes. Sink: `oidc_misconfig`.
- **`aud` check looks for `client_id` but Keycloak doesn't add it**: works in dev (because dev verifier skips `aud`), fails in prod. The "fix" usually disables `aud` checking. Verify the audience mapper is configured on the Keycloak client AND the verifier expects `client_id` in `aud`.

## Confidential vs public clients

Keycloak distinguishes confidential (has a client secret) vs public (no secret) clients:

- **Public client used for backend authz**: a public client issues tokens without a `client_secret` check — any party that can reach the token endpoint and supply a username/password gets a token. App code that doesn't enforce introspection (or doesn't verify the `azp` / `aud` claims to ensure the token came from a confidential client) accepts forged-context tokens. Sink: `oidc_misconfig`.
- **`azp` (authorized party) claim ignored**: `azp` identifies the client to which the token was issued. Backend that wants to scope-check "this token was issued to my app, not some other client in the same realm" must validate `azp` matches the expected `client_id`. Sink: `oidc_misconfig`.

## Realm roles vs client roles

Keycloak tokens carry TWO disjoint role sets:

- **Realm roles**: `realm_access.roles` — claim is a flat array on the token.
- **Client roles**: `resource_access.{client_id}.roles` — claim is keyed by client, only the relevant client's roles are visible.

Failure modes:

- **Code reads ONLY `realm_access.roles`**: client-level roles ignored. If permissions are modeled at the client level (more common), users granted via client roles are silently denied OR (worse) the code falls back to allow because the realm roles array is missing. Sink: `missing_authz`.
- **Code reads ONLY `resource_access.X.roles`** for the wrong client X — same shape of bug. Look for hardcoded client IDs in the lookup that don't match the current app's `client_id`.
- **Privilege escalation via the unread role set**: user has `realm_admin` realm role; the app checks only client roles — `realm_admin` is not visible there → the user has admin capability they can't trigger via the app, but the path may still be reachable via other channels.

## Token Exchange

Keycloak's token-exchange endpoint allows trading one token for another (e.g., a user token for a service-account token, or a token for one client for a token for another client). Token exchange is OFF by default; when enabled:

- **Token exchange permissions misconfigured**: the "exchange" permission on a client is meant to be granted only to specific service accounts. If it's granted broadly (e.g. to a `master` realm role), any service that holds such a token can mint tokens impersonating any user. Architecture-level finding; report as missing-defense.
- **Subject token isn't required to belong to the same realm**: cross-realm token exchange can be enabled — usually unintended; verify the realm pairs.

## Required Actions & `prompt=none`

Keycloak's "required actions" (verify email, update password, configure OTP) fire during interactive login. They can be bypassed via `prompt=none`:

- **`prompt=none` honored without checking `auth_time`**: client requests silent re-auth; Keycloak issues a token from an existing session without firing required actions. Backend that doesn't compare `auth_time` to a session-freshness threshold accepts a session that hadn't completed the required action (e.g., email verification). Sink: `oidc_misconfig`.

## Local validation vs introspection

For high-value endpoints (admin actions, financial transfers) local JWT validation is insufficient — revoked tokens stay "valid" until they expire because the resource server doesn't know about the revocation.

- **No introspection on sensitive endpoints**: token introspection (`/protocol/openid-connect/token/introspect`) hits Keycloak's session store and reports `active=false` for revoked tokens. Endpoints that mutate state without introspection accept revoked tokens until their natural TTL.

## Worker search patterns

- `Stevenmaguire\\OAuth2\\Client\\Provider\\Keycloak` — provider construction; check `realm`, `authServerUrl`, `version` (versions matter — older Keycloaks use `/auth/realms/`, newer use `/realms/`).
- `Keycloak\\Admin\\Client` — admin REST client; verify the admin credentials' source.
- `.env` keys `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_SECRET` — verify secrets are not committed; check that `_REALM` is NOT `master` in app code.
- URL substring `/realms/master/protocol/openid-connect/` in source — usually a bug; that's the admin realm.
