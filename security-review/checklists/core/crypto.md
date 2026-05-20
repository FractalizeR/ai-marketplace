# Cryptography / weak algorithms / hardcoded secrets / type juggling

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `weak_hash` — MD5/SHA1 for passwords or security-sensitive hashes
- `hardcoded_secret` — API key/password/token in the repository
- `type_juggling` — loose comparison `==` for security-sensitive values
- `weak_random` — insecure source of randomness for security-critical values
- `secret_in_response` — token/secret leak in HTTP response body

## Confidence floor rules

For the following patterns, confidence **does not vary** between workers — these are unambiguous vulnerabilities that do not require "bold interpretation":

- **Committed `.env` in git** with a real value for `*_KEY`/`*_TOKEN`/`*_SECRET` (not a placeholder `__YOUR_SECRET_HERE__`, not `.env.example`/`.env.dist`) → **confidence ≥ 8**. Checking "maybe it's not prod" is the reviewer's responsibility, **not a bar for reporting**.
- **Hardcoded credential in code** (`$apiKey = 'sk_live_...'`, `$password = 'real_value'`) → **confidence ≥ 9**.
- **MD5/SHA1 for password hash** (any password hasher using `md5`/`sha1`) → **confidence ≥ 9**.
- **`verify_peer: false`** / `CURLOPT_SSL_VERIFYPEER = false` in production services → **confidence ≥ 8**.
- **`==` instead of `hash_equals()`** when comparing tokens/hashes → **confidence ≥ 9**.
- **JWT with `alg: none`** or missing algorithm validation → **confidence ≥ 10**.

## Hardcoded secrets

- API keys, passwords, tokens directly in code (`$api = 'sk_live_...'`)
- Secrets in env files committed to the repository (no `.local`/override mechanism)
- Configs (yaml/ini/json) without parameterization via environment variables
- Git history: secret removed in a new commit but visible in git log (requires rotation)
- Staging/dev credentials accidentally deployed to production config

## Weak hashes / algorithms

- `md5($password)`, `sha1($password)` for password storage (even with salt — weak)
- `md5($apiKey)` for HMAC — use `hash_hmac('sha256', ...)` with `hash_equals`
- JWT with `alg: none` or `HS256` without a strong secret
- 3DES, RC4, ECB mode for symmetric encryption
- SSL/TLS with deprecated protocols, SSLv3, TLS 1.0 (depends on configuration, not code)

## JWT advanced

- `kid` header injection: attacker controls `kid` → forge HMAC via path traversal to a public file as the key.
- `jwk` / `x5u` header injection: attacker embeds their public key in the header → signs their own JWT.
- Algorithm confusion (RS256→HS256): server does not validate `alg` → attacker declares HS256 + uses RSA public key as HMAC secret.
- `aud` / `iss` mismatch: no check → a token from another service is accepted.
- `nbf` / `iat` skew without leeway → false-positive rejection; or missing check → past tokens accepted.

## Weak random

Covers sink_kind `weak_random`. **Only** direct calls to insecure APIs:

- `mt_rand()`, `rand()`, `uniqid()`, `microtime()` for security-sensitive values (CSRF tokens, password reset tokens, session ID, OAuth state, salt, nonce).
- `array_rand()` / `shuffle()` for security selection (choosing admin permission, choosing a cryptographic key from a set).

**Explicit exception from weak_random:** wrappers backed by `random_bytes()` / `random_int()` under the hood — do not report. For example, Symfony `Symfony\Component\String\ByteString::fromRandom()`, Laravel `Str::random()` (PHP 7+ → `random_bytes`), `bin2hex(random_bytes(N))`.

**Floor:** confidence ≥ 9 with a confirmed weak sink (found a direct `mt_rand` at a security-critical point).

## Secret in response

Covers sink_kind `secret_in_response`. Token/secret leak in HTTP response body:

- Symfony Serializer returns a Token entity without `#[Groups]` filter (the full entity is serialized → `accessToken`, `refreshToken` in the response).
- Laravel API Resource returns a field with `api_token` / `password` / `secret` (missing `$hidden` or Resource projection).
- Webhook receiver echoes back the signature/secret in the response body (a diagnostic endpoint left in prod).
- JSON response serializes the entire config object, including sensitive keys.

**Floor:** confidence ≥ 9 if an explicit leak of an active secret in the response body is found.

## Key management

- Encryption key stored in the same place as the encrypted data
- Fixed IV for AES-CBC (must be random per encryption)
- Short key (< 128 bit for AES)
- Cipher without authentication (AES-CBC without HMAC — padding oracle vulnerable); use AES-GCM
- Key rotation not implemented

## Encryption at rest (secrets in DB without encryption)

Tokens and keys stored **in the DB** as plaintext form a separate class from "hardcoded secrets" (which live in the repository). Compromise of the DB or backup exposes long-lived third-party credentials.

- **OAuth access/refresh tokens in DB plaintext** (`accessToken` / `refreshToken` fields storing OAuth tokens of integrations — `Column(type: 'string')` or equivalent): DB compromise → attacker gains access to user accounts at the external OAuth provider on behalf of the integration. **confidence ≥ 8**, sink_kind `hardcoded_secret` (extended interpretation: secret-at-rest without encryption).
- **JWT refresh tokens in DB plaintext**: a refresh token is typically long-lived — DB compromise grants long-lived impersonation capability.
- **API keys of external services plaintext** (fields like `apiKey`, `signingSecret`, `botToken` and similar): allows the attacker to forge events on behalf of the integrated service or strip signatures.
- **Webhook shared secrets plaintext**: if an attacker takes from the DB the value the service uses for HMAC-signing incoming webhooks — they can forge a webhook.
- **Passwords / answers in DB without bcrypt/argon**: see "Weak hashes". This is not at-rest encryption but an adjacent anti-pattern.
- **Session storage with plaintext session body**: session handler with fields `user_id`, `csrf_token` without encryption — DB access = session hijack.

**Safe solutions**: ORM-level column encryption, Vault/KMS lookup on load (tokens are not stored in DB at all — only a reference), per-row encryption with a key from env.

**Not a finding**: if the field is already encrypted via a lifecycle callback / type and the key is outside the DB; or if the field is ephemeral (TTL < 5 minutes) and single-use.

## Cryptographic randomness

- `rand()`, `mt_rand()` for security tokens — not cryptographically strong
- `uniqid()` for one-time tokens
- Use `random_bytes()`, `random_int()` instead
- Session ID generated via weak PRNG
- CSRF token via `md5(time())` or similar

## Type juggling / comparison

- `==` instead of `===` for comparing tokens, hashes
- `if ($user_hash == $expected)` — `"0e..."` strings can be equated as floats
- `in_array($needle, $haystack)` without `strict: true` — type juggling
- Comparison of user input with a numeric value via `==` (`'abc' == 0` → true)
- Password verify via `==` instead of `password_verify()`
- `hash_equals($known, $user)` is mandatory for comparing secret strings (timing attack)

## Certificate validation

- `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)` — full verification disabled
- Any HTTP client (curl/Guzzle/HttpClient) with `verify_peer: false` or `verify: false`
- User-controlled CA bundle path
- Ignoring hostname mismatch

## Signed URLs / cookies / tokens

- Signature over only part of the payload → ability to tamper with the remaining fields
- `RememberMe` / signed cookie without TTL
- Expired tokens are not invalidated
- Refresh token reuse detection is missing (token can be used multiple times)

## Password policies

- No minimum length / complexity
- No check against a common password list
- Unlimited login attempts without throttling (see `auth.md`)
- Password reset flow with weak token (see `auth.md`)
