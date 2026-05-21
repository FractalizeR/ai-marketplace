# Cryptography (JWT — generic)

> This checklist extends `core/crypto.md` for projects that use JSON Web Tokens. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **TLS validation explicitly disabled when fetching JWKS** (`CURLOPT_SSL_VERIFYPEER = false`, Guzzle `verify => false`, Symfony `verify_peer: false` on the JWKS endpoint client) in a production code path → `tls_validation_bypass` **confidence ≥ 9**. A forged JWKS at any MITM point yields full token forgery (`jwks_spoof` follow-on).
- **JWT signed with HS256 using a secret shorter than 32 bytes (256 bits)** → `weak_hash` confidence ≥ 8 (key length under HMAC-SHA-256's security parameter; offline brute force feasible).

## Signing keys

- **Weak HS256 key length**: `JWT_SECRET` literal shorter than 32 bytes, or generated from a low-entropy source (`md5(time())`, dictionary word, project name). The HMAC-SHA-256 security parameter is 256 bits; under that the signature is brute-forceable offline once an attacker captures one signed token. Sink_kind `weak_hash` (algorithm weakness in usage).
- **Same key used for signing AND encryption**: JWS signing key reused as JWE encryption key collapses cryptographic separation; a known-plaintext attack against the encrypted payload yields the signing key. Sink_kind `weak_hash`.
- **Symmetric secret shared across multiple services**: same `JWT_SECRET` distributed to every microservice as the verifier key — any service compromise compromises the entire mesh. Architecture-level finding; severity tracks impact (lateral movement).
- **Public key embedded in token `jwk` header trusted without external pin**: verifier accepts the public key from the token's `jwk` header without comparing against a trust anchor. Cross-listed in `jwt-generic/auth.md` (`jwks_spoof`); here we emphasize the crypto failure: there is no key-pinning step.

## JWKS endpoint hygiene

- **TLS validation disabled when fetching JWKS** (`/.well-known/jwks.json` or vendor-specific JWKS URL): any HTTP client option that disables peer verification on the fetch (`CURLOPT_SSL_VERIFYPEER = false`, Guzzle `['verify' => false]`, Symfony HttpClient `'verify_peer' => false`) opens a MITM that swaps the JWKS for an attacker-controlled key set → full token forgery. Sink_kind `tls_validation_bypass`.
- **JWKS cache TTL too long**: the verifier caches the JWKS response for hours or days. When the issuer rotates a compromised key, every cached verifier still accepts tokens signed with the old key for the full TTL. Compensating control: a short TTL (≤ 10 min) with an `expires_at` honoring the JWKS-endpoint cache headers.
- **JWKS fetch unauthenticated when issuer requires it**: some private OIDC providers expect a client credential on the JWKS endpoint; the verifier omits it and silently fetches an empty / default JWKS, then accepts no tokens or, worse, falls back to an embedded `jwk` (see `auth.md`).
- **No rotation strategy at all**: signing key is a single literal in code/.env, never rotated. Architecture-level finding (no enum value); track as `hardcoded_secret` if the key value is in the repo, otherwise as a missing-defense observation.

## Encrypted JWT (JWE)

- **JWE `alg: dir` with a low-entropy CEK**: direct-encryption flow where the content encryption key is derived from a weak password or a short ASCII secret. Sink_kind `weak_hash`.
- **JWE `enc` algorithm without integrity** (e.g. older AES-CBC profiles without HMAC): padding-oracle vulnerable. The JWE spec prevents this in practice (mandatory authenticated `enc` values), but custom-rolled JWE implementations may regress. Sink_kind `weak_hash`.
- **Encryption key reused as signing key**: see "Signing keys" above.

## At-rest token storage (cross-link)

JWT refresh tokens / access tokens stored in the database without column encryption are a separate class — see `core/crypto.md` § "Encryption at rest". Compromise of the DB grants long-lived impersonation. Sink_kind `hardcoded_secret` (extended interpretation: secret-at-rest without encryption).
