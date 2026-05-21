# Authentication / Authorization (JWT — generic)

> This checklist extends `core/auth.md` for projects that use JSON Web Tokens. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

> **Scope note**: This checklist primarily targets JWS-based tokens (header-then-payload-then-signature, with `alg`/`kid`/`jku`/`jwk` headers). PASETO tokens (`paragonie/paseto`) have a different attack surface — no algorithm-confusion or kid-injection vector — but the storage, transport, and lifecycle items (storage in localStorage, missing rotation, etc.) still apply. Skip JWS-header rules when the project uses PASETO exclusively.

## Confidence floor rules

- **`alg: none` confirmed in the verifier's algorithm allowlist** (e.g., `verify(jwt, key, ['none', 'HS256'])`, `JWT::decode($token, $key, ['none'])`) → `jwks_spoof` **confidence ≥ 10**, severity ≥ HIGH. Absolute evidence — no exceptions.
- **Algorithm validation entirely absent** (verifier called without any `algorithms` allowlist parameter — no explicit list to check `none` against) → `jwks_spoof` **confidence ≥ 9**. Strong evidence pending exploit confirmation (the library may still reject `none` by default depending on version).
- **HS256 with a shared symmetric secret committed to git** (literal in code, in `.env` committed to the repo, in `config/*.yaml` with a real value rather than `%env(...)%`) → `jwks_spoof` **confidence ≥ 9** (also flag `hardcoded_secret`).
- **Verifier accepts `alg` from the token header without an allowlist** (no explicit `algorithms` parameter on decode, or the list is computed from `header.alg` itself) → `jwks_spoof` confidence ≥ 9.

## Algorithm-confusion family (`jwks_spoof`)

The signature-verification step is the entire trust boundary of a JWT. Any pattern that lets the attacker influence the algorithm or the verification key collapses authn.

- **`alg: none` accepted**: verifier call without an explicit algorithm whitelist, OR the whitelist contains the string `"none"`. firebase/php-jwt versions prior to 6.x had this as a footgun if `JWT::decode($token, $key, $algorithms)` was called without the third argument — sink_kind `jwks_spoof`.
- **Algorithm confusion RS256 → HS256**: the server stores an RSA public key (intended for `RS256` signature verification); the verifier picks the algorithm from the token header without an allowlist. Attacker submits a token with `alg: HS256` signed using the public key as the HMAC secret. Public keys are typically distributed (`/.well-known/jwks.json`, hardcoded `.pem`), so the attacker has them. Sink_kind `jwks_spoof`.
- **`kid` header trusted without an allowlist**: verifier reads the `kid` (key ID) from the token header and looks it up in a key store or file path. If the store is queried with raw `kid` value, the attacker can:
  - Pass `kid` = path-traversal string like `../../../tmp/evil.pem` (file-based key store).
  - Pass `kid` of a known public file with predictable content (`/dev/null`, a static asset) and sign with that content as HMAC secret.
  - Pass `kid` of a different tenant's key when the store is shared across tenants.
  Sink_kind `jwks_spoof`.
- **`jku` (JWKS URL) header followed without an allowlist**: verifier fetches the JWK set from a URL embedded in the token header. Attacker hosts their own JWKS, supplies a `jku` pointing to it, and signs the token with the matching private key. Sink_kind `jwks_spoof`; also flag `ssrf` family for the URL-fetch side.
- **`x5u` (X.509 URL) header followed without an allowlist**: same pattern as `jku` but with X.509 cert chains. Sink_kind `jwks_spoof`.
- **`jwk` header trusted without external pin**: verifier accepts the public key embedded in the token's `jwk` header and uses it for verification. Attacker generates a key pair, embeds the public key, signs with the private key — perfect signature, no trust anchor. Sink_kind `jwks_spoof`.
- **JWT body parsed BEFORE signature verification**: implementation bug — the code reads claims (`sub`, `tenant_id`, ...) from the encoded body without first calling verify. Subsequent authz decisions trust forged claims. Sink_kind `jwks_spoof`.

## Claim validation

- **Missing `aud` (audience) validation**: a token issued for service A is accepted by service B because nobody compares `aud` to the local service identifier. Common in microservice meshes that share an issuer.
- **Missing `iss` (issuer) validation**: any token signed by anyone with a copy of the verifier key is accepted, regardless of issuer. Cross-tenant / cross-environment token reuse.
- **Missing `exp` (expiration) validation**: tokens never expire from the verifier's perspective; revocation impossible without an external blacklist.
- **Missing `nbf` (not-before) validation**: the token is accepted before its activation window — usually benign but a leak channel for pre-issued tokens.
- **`iat` skew not enforced**: tokens minted in the far future (or past) are accepted; replay window unbounded.
- **`sub` claim accepted without verifying user existence**: backend trusts `sub` and proceeds without a DB lookup; a deleted user's token still authenticates because `exp` hasn't fired.

## Token storage and lifecycle

- **JWT in `localStorage` / `sessionStorage` instead of an httpOnly cookie**: XSS = total token theft (no `httpOnly` defence). Cross-ref `core/frontend-js.md` for the JS side; mark this as an architecture-level issue, not a per-token issue.
- **Refresh token rotation absent**: a stolen refresh token grants indefinite access because each rotation does not invalidate the previous one. Rotation must be: every refresh issues a new refresh token AND invalidates the old one; reuse of an old token signals theft and revokes the family.
- **JTI replay protection missing**: no nonce or blacklist on logout / on detected reuse. A stolen access token remains usable until its natural `exp`, even after the user logs out. Sink_kind `webhook_replay` is the analogy, but for JWTs use `jwks_spoof` only when the signature itself is forgeable; replay without forgery is a missing-defense finding (no enum value — report as architecture-level).
- **Long-lived access tokens (TTL ≫ 15 min)**: refresh-flow purpose defeated; theft window expanded. Less a defect on its own but a precondition for impact on other findings.

## Cross-stack notes

- **Symfony Lexik bundle**: configuration in `config/packages/lexik_jwt_authentication.yaml`. Check `algorithm` (default RS256), `pass_phrase` source, `token_extractors` (`header` / `query_parameter` / `cookie`). Query-parameter extractor leaks tokens into access logs.
- **Laravel tymon/jwt-auth, php-open-source-saver/jwt-auth**: configuration in `config/jwt.php`. Check `secret` source (env vs literal), `algo`, `blacklist_enabled`, `blacklist_grace_period`.
- **firebase/php-jwt direct use**: search for `JWT::decode(` and `JWT::encode(` call sites — the third argument to `decode` is the algorithms array; if it's missing, omitted, or built from header data the call is unsafe.
- **lcobucci/jwt**: search for `$config->validator()->validate(` chains — every validation constraint must be present (SignedWith, IssuedBy, PermittedFor, StrictValidAt). Missing constraints = silent acceptance.
