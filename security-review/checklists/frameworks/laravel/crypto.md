# Cryptography (Laravel)

> This checklist complements `core/crypto.md` for laravel projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## APP_KEY / encrypter

- `APP_KEY` is missing or has the default `base64:...` example from `.env.example` — compromise = forging signed cookies, signed URLs, decrypt any encrypted payloads
- `APP_KEY` rotation without `APP_PREVIOUS_KEYS` — old encrypted cookies become invalid (DoS) + if the key is leaked, there is no window for rotation
- Custom Encrypter via `Crypt::extend(...)` without an AEAD cipher (CBC without HMAC) → padding oracle
- `Crypt::encrypt($data, $serialize=true)` — serializes through PHP serialize. Decrypt with a compromised key = RCE gadget chain

## Password hashing

- `config/hashing.php`: `'driver' => 'bcrypt'` is correct. `'argon2'` is correct. `'argon'` (old Argon2i) — less reliable; use `argon2id`
- Custom hashing via `Hash::extend('md5', ...)` or `Hash::extend('sha1', ...)` → weak hashes
- `Hash::make($password, ['rounds' => 4])` — too few BCrypt rounds (by default 10–12 is reasonable)
- Manual `md5($password)` / `sha1($password)` in legacy seeders/migrations — weak hashes land in DB
- `Hash::needsRehash($hash)` without performing rehash in login flow — outdated hashes silently persist

## JWT (`tymon/jwt-auth`, `laravel/passport`)

- `JWT_SECRET` weak / hardcoded in `.env` (committed); generated via `php -r "echo bin2hex(random_bytes(8));"` (short)
- `JWT_TTL` too long (infinite or > 24 hours)
- Algorithm `HS256` with a publicly known secret — token forge
- `none` algorithm let through via misconfiguration → unsigned tokens accepted
- Token extractors: `query_string` extractor for cookie-auth flow → token leaks into server logs
- Refresh-token rotation missing — one long-TTL token

## Signed URLs

- `URL::signedRoute('foo', $params)` without an `expiration` argument → indefinite signed URL
- Signed URL with user-controlled parameters: `signedRoute('reset', ['user_id' => $req->user_id])` — restrict the scope (use the authenticated user, not from the request body)
- `URL::hasValidSignature($request)` forgotten in the handler — signature is not verified

## Session encryption

- `config/session.php`: `'encrypt' => false` (default) — session ID in cookie plaintext (the content itself is server-side, but stealing the cookie = session hijack without MITM)
- `config/session.php`: `secure: false`, `same_site: 'lax'` without `'strict'` for critical operations

## Random / IDs

- `Str::random(8)` for CSRF/reset token — uses `random_bytes`, length 8 = 48 bits — too few
- `mt_rand($min, $max)` / `rand()` for security-critical id — predictable
- `time()` or `microtime()` as seed for random — predictable
- Sequential numeric IDs in URLs / API responses without protection — IDOR enumeration friend

## API key storage

- API keys / OAuth client secrets stored as plaintext in `oauth_clients`/custom table — DB compromise = full key leak
- Sanctum `personal_access_tokens.token` — Laravel hashes by default (sha256). Custom code storing plaintext breaks the invariant
- `$user->createToken(...)` plain-text is returned, OK at creation time, but repeat access is impossible — UI shows a "copy now" warning, but DB does not leak

## JWT advanced

> See `core/crypto.md → JWT advanced` for the generic description (alg confusion, kid injection, jku/x5u trust). Below are Laravel-specific notes.

- `tymon/jwt-auth`: custom `JWT::decode($token, $key, $allowed_algos = ['HS256', 'RS256'])` — array with both types → attacker takes the RS256 public key, forges an HS256 token with that same key as secret → accepted. **confidence ≥ 9** with a confirmed mixed-algo configuration.
- `tymon/jwt-auth` `kid` claim in header processed by a custom resolver that reads a file/URL by the `kid` value without an allowlist → path traversal or fetch attacker-controlled JWK. **confidence ≥ 8**.
- `php-open-source-saver/jwt-auth` (tymon fork) — inherits the same codebase, risks are identical. Look for both packages in `composer.json`.
- `lcobucci/jwt` directly (without a bundle): `Validator::validate($token, new SignedWith($algorithm, $key))` — if `$algorithm` is taken from `$token->headers()->get('alg')` without enforcement → alg confusion.
- `firebase/php-jwt` `JWT::decode($jwt, $keys)` where `$keys` is an array `[$kid => $key]`: attacker sets a known `kid` of a different algorithm → accepted. `firebase/php-jwt >= 6.0` requires `Key` with an explicit algorithm — old versions (5.x) are vulnerable.

## weak_random Laravel specifics

> sink_kind: `weak_random`. See `core/crypto.md → weak_random` for the generic description.

- **`Hash::make($password, ['rounds' => 4])`** — insufficient rounds for bcrypt. Minimum 10 (Laravel default — 12). `rounds=4` is brute-forced in milliseconds. **confidence ≥ 9** (`weak_random` for a derived KDF, or a separate finding `weak_kdf_rounds`).
- **`Hash::make($password, ['rounds' => $request->input('rounds')])`** — user-controlled cost factor → DoS (rounds=20 → 30s/hash) or intentional weak hash via rounds=4.
- **`Str::password($length, false, false, false)`** — all options (`letters`, `numbers`, `symbols`, `spaces`) disabled → the method returns an empty string or crashes. `Str::password(12, true, false, false)` — letters only → entropy 5.7 bits/char → 68 bits for 12 chars, below recommended.
- **`config/hashing.php`: `'argon' => ['memory' => 1024, 'time' => 1, 'threads' => 1]`** — insufficient parameters for Argon2; use Laravel defaults (memory=65536, time=4) or explicitly hardware-tuned values.
- **Explicit exception**: `Str::random($length)` — **NOT** a weak pattern. Under the hood `random_bytes()` (PHP 7+ secure CSPRNG). **Do not report as weak_random.** Check only length: `Str::random(8)` for CSRF/reset token = 48 bits of entropy (base62 string of length 8 ≈ 47.6 bits), too few — this is already described in the `## Random / IDs` section above as length, not algorithm.

## Secret in response Laravel specifics

> sink_kind: `secret_in_response`. The primary material is in `frameworks/laravel/disclosure.md → secret_in_response (Sanctum / Eloquent / API Resource)`. Here only a cross-link, so scanning the crypto checklist does not miss the category.
