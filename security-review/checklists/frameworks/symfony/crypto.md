# Cryptography (Symfony)

> This checklist complements `core/crypto.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## APP_SECRET / Symfony secrets

- `APP_SECRET` in `.env` without `.env.local` override (committed) — compromise = forging signed cookies, signed URLs, CSRF tokens
- Credentials in `services.yaml` / `services.xml` without parameterization through `%env(...)%` — secrets in the commit

## PasswordHasher misuse

- Symfony password hasher `plaintext` or `md5`/`sha1` for User entity (`config/packages/security.yaml::password_hashers`) — applied at `UserPasswordHasherInterface::hashPassword()` → weak password hashes in DB

## Symfony JWT bundle pitfalls

- `lexik/jwt-authentication-bundle`: weak / hardcoded `JWT_PASSPHRASE` in `.env` (committed); short TTL not configured; `token_extractors` accepts token from insecure sources (query param) with cookie-auth

## JWT (lexik/jwt-authentication-bundle) — extended

Complements the section of the same name above; here — the full set of bundle-specific patterns.

- **`JWT_PASSPHRASE` / `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` in `.env` without `.env.local` override** (committed) → attacker re-signs tokens of any user → full authentication bypass. Sink_kind: `hardcoded_secret`. Cross-link: `auth.md` → JWT bundle and `core/crypto.md` → APP_SECRET.
- **`token_extractors.query_parameter.enabled: true`** in `config/packages/lexik_jwt_authentication.yaml` with cookie/header auth: token ends up in the URL → leak via browser history, server access logs, `Referer` header. If query is the only extractor, assess whether it should be cookie/header.
- **`kid` / `jwk` header passthrough**: only if the project has a **custom Authenticator** or a direct call to `JWSLoader`/`JWTEncoderInterface::decode()` that passes the `kid` header into a file-system path lookup without a whitelist → kid header injection (path traversal to an attacker-controlled keyfile). See `core/crypto.md` → JWT advanced.
- **Token TTL is not configured or is too long** (`token_ttl: 3600` ok, `token_ttl: 31536000` — a year — not ok): absence of a refresh flow + long TTL → revocation is impossible.

## JWT advanced (general patterns)

All patterns from `core/crypto.md → JWT advanced` (kid header injection, jwk/x5u header injection, algorithm confusion RS256→HS256, aud/iss mismatch, nbf/iat skew without leeway) apply to Symfony identically. Symfony specifics:

- **`Lcobucci\JWT\Configuration` directly (without the bundle)**: when creating `Configuration::forSymmetricSigner(...)` / `forAsymmetricSigner(...)`, validation constraints (`SignedWith`, `IssuedBy`, `PermittedFor`, `LooseValidAt`/`StrictValidAt`) are **optional**. If the developer forgot `setValidationConstraints([...])` or called `->validator()->validate($token)` without constraints → any signature/iss/aud is accepted. Grep `Lcobucci\JWT\Configuration` without a subsequent `setValidationConstraints`. Confidence ≥ 8 for projects using such tokens for authn.
- **`web-token/jwt-framework` (if used)**: `JWSLoader` without a `signatureAlgorithms` whitelist → algorithm confusion possible; `JWKSet::createFromKeyData()` accepting an untrusted JWK without a `kid` whitelist.

## Persistent OAuth credentials in plain `string` columns (Doctrine entity)

- `#[ORM\Column(type: 'string')] $accessToken | $refreshToken | $clientSecret | $apiKey | $botToken | $authToken | $webhookSecret` — without a custom Doctrine Type / EncryptedStringType → encryption-at-rest gap
- Also check JSON configs: `#[ORM\Column(type: Types::JSON)] $config` where `$config` serializes `botToken`/headers with `Authorization: Bearer ...` (typical pattern in notification channel / webhook mapping entities)
- Sink_kind: `hardcoded_secret` (root_cause_family `crypto`)
- Threat: DB compromise (snapshot/backup leak / SQL injection / DBA insider) gives persistent access to all integrations of all tenants; refresh tokens usually live for months and are auto-renewed
- Fix: Doctrine custom type with AES-256-GCM (key from `framework.secrets:` or KMS), `doctrine-encrypt-bundle`/`halite`
