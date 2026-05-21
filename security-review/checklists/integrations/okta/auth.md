# Authentication / Authorization (Okta)

> This checklist extends `core/auth.md` for projects that use Okta for authentication. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

> **Layering note**: Okta is OIDC-compliant. The worker also loads `integrations/jwt-generic/auth.md` and `integrations/oauth-oidc/auth.md` for the underlying mechanics. This file documents the **Okta-specific** patterns on top of those.

## Confidence floor rules

- **`client_credentials` flow secret committed to git** (literal in code, in `.env` committed to the repo, or in `config/*.yaml` with a real value rather than `env(...)`) → `hardcoded_secret` **confidence ≥ 9**. The client credentials grant secret allows minting arbitrary service-account tokens.
- **JWKS / OIDC discovery endpoint fetched without TLS verification** → `tls_validation_bypass` confidence ≥ 9 (cross-listed in `core/crypto.md`).

## Issuer-URL ambiguity (org URL vs auth server)

Okta has TWO valid issuer-URL shapes:

- **Org URL**: `https://{org}.okta.com` (no path) — used by Okta's classic "organization authorization server".
- **Custom auth server**: `https://{org}.okta.com/oauth2/{auth_server_id}` — used by Okta's per-API auth servers (recommended for API access). The `default` auth server lives at `https://{org}.okta.com/oauth2/default`.

A verifier configured for one shape SILENTLY REJECTS tokens issued from the other (no error, just "invalid token"). Failure modes:

- **Issuer URL mismatch leads to "fixed by disabling the check"**: code base history shows the issuer was wrong, dev disabled the check entirely. Sink: `oidc_misconfig`.
- **Issuer URL allows BOTH shapes via a substring / prefix match**: code accepts any token whose `iss` starts with `https://{org}.okta.com` — attacker who can spin up a non-default auth server (legitimate Okta admin features) mints tokens that pass this verifier. Sink: `oidc_misconfig`.

## Custom domain consistency

When Okta is configured behind a custom domain (e.g. `login.example.com`), BOTH the issuer URL AND the JWKS endpoint must use the custom domain consistently. A mismatch (issuer says `login.example.com`, JWKS fetched from `{org}.okta.com`) means the JWKS / token validation can desynchronize on cert rotation — and the workaround tends to be "disable signature check".

- **Mixed org URL and custom domain** in config — flag as `oidc_misconfig`. Verifier code that hardcodes the JWKS URL separately from the issuer is the signal.

## Default auth server vs custom auth server

The `default` auth server (`{org}.okta.com/oauth2/default`) has a different claims set from custom auth servers:

- **`groups` claim is empty on the default auth server's access tokens** unless an explicit claim mapping is configured. Code that does `if (in_array('admin', $access_token['groups']))` against the default server gets `null` / empty → silent fail-open. Sink: `missing_authz`.
- **`scope` claim on the default auth server** carries only basic OIDC scopes (`openid email profile`). Custom scopes require a custom auth server. Code that gates on `wallet.write` on a default-auth-server token always fails — symptom: dev disables the scope check.

## Audience validation

Okta access tokens carry `aud` = the API identifier configured in the Okta auth server (different from `client_id`):

- **Missing `aud` validation** — token from any of the org's Okta clients accepted. Sink: `oidc_misconfig`.
- **`aud` validated against `client_id`** (instead of the API identifier) — works only for ID tokens; access-token validation is wrong. Sink: `oidc_misconfig`.

## Group-claim handling

Okta group filtering happens server-side at issuance: groups that don't match the auth server's group-filter aren't sent. Result: the claim may be absent or an empty array.

- **Code with `if ('admin' in $token['groups'])` against absent claim**: depending on the language idiom, this either throws (PHP key not set, undefined index notice) or silently returns false. If false, the next branch determines impact; if a `try/catch` wraps it and the catch falls through to allow, that's a confident `missing_authz`.

## Worker search patterns

- `Okta\\JwtVerifier\\` classes — check `setAudience` and `setClientId` calls; missing audience setter = no `aud` check.
- `Okta\\OktaSDK\\` — admin SDK; verify the auth-server scope of any token-mint call.
- `OKTA_ISSUER`, `OKTA_DOMAIN`, `OKTA_AUTH_SERVER_ID` in `.env*` — verify consistency with the JWKS URL constructed in code.
- URL substring `.okta.com` / `.oktapreview.com` in source — usually an issuer hardcode; double-check that the auth-server segment is included.
