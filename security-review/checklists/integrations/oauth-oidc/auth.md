# Authentication / Authorization (OAuth 2.0 / OpenID Connect — generic)

> This checklist extends `core/auth.md` for projects that run an OAuth 2.0 / OpenID Connect client or server flow. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **Callback handler with no `state` check on a public OAuth client** (the route that receives `?code=&state=` does not compare `state` against a server-side stored value, OR the comparison is absent / commented out / `==` with empty fallback) → `oauth_state_missing` **confidence ≥ 9**, severity ≥ High. Well-known attack class — account linking / session hijack.
- **`redirect_uri` matched by prefix or regex in production** (the OAuth server's allowed redirect list compares the incoming `redirect_uri` with `startsWith` / `substr` / a regex containing wildcards instead of exact string equality) → `oidc_misconfig` **confidence ≥ 8**, severity ≥ High. Attacker registers `legit.app.evil.com` against allowlist `legit.app*`.
- **OIDC discovery URL (`/.well-known/openid-configuration`) or JWKS endpoint fetched without TLS verification in production** → `tls_validation_bypass` confidence ≥ 9 (cross-listed with `core/crypto.md`).

## Client-side flow: authorization request

- **Missing `state` parameter on the authorization request**: the client builds the `/authorize` URL without a `state=<unguessable>` value or stores it in a place the callback can't read (URL fragment, JS-only memory in a multi-tab session) → CSRF on the callback. Attacker initiates the flow on their own account, lures the victim into completing the callback, victim's session is now linked to attacker's identity. Sink_kind `oauth_state_missing`.
- **`state` not unguessable**: `state` derived from `md5(time())`, sequential integer, user ID, session ID — predictable. Sink_kind `oauth_state_missing` (also flag `weak_random` if a non-CSPRNG is the source).
- **`state` not bound to the user's session**: server accepts any non-empty `state`, doesn't compare it to a per-session stored value → the parameter is decorative. Sink_kind `oauth_state_missing`.
- **Missing PKCE on a public client (mobile, SPA, native)**: no `code_challenge` / `code_verifier` pair on the authorization request → an attacker who intercepts the authorization code (clipboard, OS deep-link race, mobile inter-app interception) can exchange it for tokens. Confidential clients (server-side with a client secret) historically didn't require PKCE; OAuth 2.1 mandates it for everyone. Public clients without PKCE are a confident finding.
- **Implicit flow used**: response_type=token (deprecated; OAuth 2.1 removes it). Token returned in the URL fragment, leaks via `Referer` header to third-party assets on the landing page. Sink_kind `oidc_misconfig`.
- **`response_mode=fragment` on a server-side client**: same leakage pattern as implicit flow when the server expects to read the token from the fragment.

## Client-side flow: callback handler

- **Token swap via login CSRF**: attacker initiates the OAuth flow with their own account, parks the callback link, lures the victim to click it. Without state-binding to the victim's session, the victim is logged into the attacker's account → all subsequent actions (uploads, purchases, content saved) flow into the attacker's identity. Sink_kind `oauth_state_missing` (root cause: missing state binding). Severity ≥ High when the linked account has any user-visible data.
- **Code accepted multiple times**: the authorization-code grant returns a single-use code. If the client doesn't track used codes (or the OAuth server doesn't), a captured code can be replayed. Architecture-level finding; report as a missing-defense observation.
- **`redirect_uri` constructed from request parameters**: callback handler reads the final landing URL from the request body / query / referrer and redirects there without an allowlist — open redirect with auth context, can land tokens on attacker pages. Sink_kind `redirect_open`.

## OIDC `id_token` validation (client side)

- **Nonce missing on the authorization request OR nonce not validated on the `id_token`**: OIDC nonce binds the ID token to the original authorization request. Without it, an attacker who captures any ID token (logs, mis-routed response) can replay it. Sink_kind `oauth_state_missing` (analogous mechanism: missing per-request binding).
- **`at_hash` validation missing on hybrid / implicit flow**: when the ID token is returned alongside an access token (`response_type=id_token token` or `code id_token`), the spec requires `at_hash` to bind them. Without verification, an attacker can pair their own access token with a victim's ID token.
- **`c_hash` validation missing on hybrid flow**: same as `at_hash` but for the authorization code in flows returning code + id_token together.
- **`aud` validation absent**: ID token from one client (e.g. a dev app) is accepted by another client because nobody compares `aud` to the local `client_id`. Sink_kind `oidc_misconfig`. Cross-listed with `jwt-generic/auth.md`.
- **`iss` (issuer) validation absent or trusts user-supplied URL**: the verifier accepts any issuer, OR pulls the expected issuer from the token itself (circular trust), OR pulls it from a request parameter (`?provider=https://evil`). Sink_kind `oidc_misconfig`.

## Server-side: `/authorize` endpoint hygiene

- **`redirect_uri` exact-match enforcement absent**: the OAuth server compares the incoming `redirect_uri` against the registered URI by prefix, by `startsWith`, by regex, or by domain match. Sink_kind `oidc_misconfig`. Examples:
  - Allowed `https://app.example.com/*`, incoming `https://app.example.com.evil/callback` → matches if compared by `startsWith`.
  - Regex `^https://.*\.example\.com/callback$` → matches `evil.example.com.attacker/callback` if the regex is unanchored on a `.`-bug.
  - Allowed `https://app.example.com/callback`, incoming `https://app.example.com:443@evil.com/callback` → matches if compared by `host` extraction that doesn't normalize the URL.
- **`redirect_uri` registration accepts wildcards in production**: client registration permits `https://*.example.com/callback` — any subdomain (including takeover-vulnerable subdomains) becomes a valid callback. Sink_kind `oidc_misconfig`.
- **Scope binding missing**: the issued access token carries scopes the user did not explicitly grant (consent screen omitted, or the client requested less than the server granted). Sink_kind `oidc_misconfig`.
- **No consent screen for high-risk scopes**: skipping the consent UI for `openid email profile` is acceptable; skipping it for `wallet.write` is not. Architecture-level; report as missing defense.
- **`prompt=none` silent re-auth abuse**: attacker uses silent re-auth without user interaction to refresh the victim's tokens at any time. Mitigation: require interactive auth for high-risk scopes regardless of `prompt`.

## Server-side: token endpoint

- **No client authentication on confidential clients**: token endpoint accepts requests without verifying `client_secret` (or `client_assertion` for JWT-bearer client auth). Mass token issuance.
- **Refresh token rotation absent**: a stolen refresh token grants indefinite access; each rotation must invalidate the previous refresh token and emit a new one. Reuse of an old refresh token signals theft → revoke the entire family. Cross-ref `jwt-generic/auth.md`.
- **Token introspection endpoint exposed without auth**: any caller can query `/introspect` with a token and learn its claims; aids token theft / scope enumeration.

## Generic OAuth/OIDC hygiene

- **`prompt=none` silent re-auth abuse**: see `/authorize` section above.
- **Account linking without verification of new email ownership**: the link request sends a code to the new email but doesn't validate that the owner actually clicked. Cross-listed with `core/auth.md` § "MFA / lifecycle".
- **Single-Logout (SLO) unverified**: front-channel SLO request not verified against the IdP's signature → attacker forces logout of any user. Architecture-level; report as missing defense.
- **Token cached by intermediate proxy** because `Cache-Control: no-store` is missing on token endpoint responses → token replay across cache hits. Sink_kind `secret_in_response` adjacent (the secret leaks via cache rather than response body).

## Cross-stack notes

- **Symfony KnpUOAuth2ClientBundle**: configuration in `config/packages/knpu_oauth2_client.yaml`. Check `redirect_route` (route name resolved at runtime — search the route's controller for state handling). Check `client_kwargs` for `scope` declarations.
- **Symfony omines/oauth2-client-bundle**: similar shape; configuration in `config/packages/omines_oauth2_client.yaml`.
- **Laravel Socialite**: configuration in `config/services.php` under each provider key. Search `Socialite::driver('<provider>')->stateless()` — stateless mode SKIPS state validation; only acceptable for API-style flows with a server-side counterpart, never for browser-driven sign-in.
- **Laravel Passport**: server side. Check `Passport::tokensCan(...)` (scope definitions), `Passport::personalAccessTokensExpireIn(...)`, and middleware on `/oauth/*` routes (default middleware group: `web` — required for CSRF on the consent screen).
- **league/oauth2-client direct use**: search for `->getAuthorizationUrl(`, `->getAccessToken('authorization_code', ...)`, `->getState()`. The library DOES emit `state` automatically (on `getAuthorizationUrl()` and persists to session) — but only if the consumer reads back `$provider->getState()` and compares it on the callback. Many integrations skip this step.
- **league/oauth2-server**: configuration in dedicated bootstrap. Check the `AuthorizationServer::enableGrantType()` calls — implicit grant (`new ImplicitGrant(...)`) is deprecated; if present, flag as `oidc_misconfig`. Check `setRedirectUriValidator()` for an exact-match implementation.
