# Cryptography (Laravel)

> Этот чек-лист дополняет `core/crypto.md` для проектов на laravel. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## APP_KEY / encrypter

- `APP_KEY` отсутствует или с дефолтным `base64:...` примером из `.env.example` — компрометация = подделка signed cookies, signed URLs, decrypt любых encrypted payloads
- `APP_KEY` rotation без `APP_PREVIOUS_KEYS` — старые encrypted cookies становятся невалидны (DoS) + если ключ leaked, нет окна для rotation
- Custom Encrypter через `Crypt::extend(...)` без AEAD-шифра (CBC без HMAC) → padding oracle
- `Crypt::encrypt($data, $serialize=true)` — сериализует через PHP serialize. Decrypt при компрометированном ключе = RCE gadget chain

## Password hashing

- `config/hashing.php`: `'driver' => 'bcrypt'` корректно. `'argon2'` корректно. `'argon'` (старый Argon2i) — менее надёжен; используй `argon2id`
- Custom hashing через `Hash::extend('md5', ...)` или `Hash::extend('sha1', ...)` → слабые хэши
- `Hash::make($password, ['rounds' => 4])` — слишком мало BCrypt rounds (по умолчанию 10–12 разумно)
- Manual `md5($password)` / `sha1($password)` в legacy seeders/migrations — слабые хэши попадают в БД
- `Hash::needsRehash($hash)` без выполнения rehash в login flow — стелс-устаревшие хэши остаются

## JWT (`tymon/jwt-auth`, `laravel/passport`)

- `JWT_SECRET` weak / hardcoded в `.env` (попадает в коммит); сгенерирован через `php -r "echo bin2hex(random_bytes(8));"` (короткий)
- `JWT_TTL` слишком long (бесконечный или > 24 часа)
- Алгоритм `HS256` с публично известным secret — token forge
- `none` algorithm пропущен через misconfiguration → unsigned tokens accepted
- Token extractors: `query_string` extractor для cookie-auth flow → token leaks в server logs
- Refresh-token rotation отсутствует — один длинный TTL-токен

## Signed URLs

- `URL::signedRoute('foo', $params)` без `expiration` argument → бессрочный signed URL
- Signed URL с user-controlled параметрами: `signedRoute('reset', ['user_id' => $req->user_id])` — ограничивай scope (use authenticated user, не из request body)
- `URL::hasValidSignature($request)` забыт в обработчике — сигнатура не проверяется

## Session encryption

- `config/session.php`: `'encrypt' => false` (default) — session ID в cookie plaintext (само содержимое серверное, но stealing cookie = session hijack без MITM)
- `config/session.php`: `secure: false`, `same_site: 'lax'` без `'strict'` для critical operations

## Random / IDs

- `Str::random(8)` для CSRF/reset token — использует `random_bytes`, длина 8 = 48 bits — слишком мало
- `mt_rand($min, $max)` / `rand()` для security-critical id — predictable
- `time()` или `microtime()` как seed для random — predictable
- Sequential numeric IDs в URLs / API responses без protection — IDOR enumeration friend

## API key storage

- API keys / OAuth client secrets хранятся как plaintext в `oauth_clients`/custom таблице — DB compromise = full key leak
- Sanctum `personal_access_tokens.token` — Laravel hashes по умолчанию (sha256). Custom code, ставящий plaintext, ломает инвариант
- `$user->createToken(...)` plain-text возвращается, ОК на момент создания, но повторный access невозможен — UI показывает "copy now" warning, но БД не leak

## JWT advanced

> См. `core/crypto.md → JWT advanced` для generic-описания (alg confusion, kid injection, jku/x5u trust). Ниже — Laravel-уточнения.

- `tymon/jwt-auth`: custom `JWT::decode($token, $key, $allowed_algos = ['HS256', 'RS256'])` — массив с обоими типами → atta берёт RS256 public key, формирует HS256-токен с этим же ключом как secret → принимается. **confidence ≥ 9** при подтверждённой mixed-algo конфигурации.
- `tymon/jwt-auth` `kid` claim в header обработан custom resolver-ом, который читает файл/URL по значению `kid` без allowlist → path traversal или fetch attacker-controlled JWK. **confidence ≥ 8**.
- `php-open-source-saver/jwt-auth` (форк tymon) — наследует ту же кодовую базу, риски идентичны. Ищи оба package в `composer.json`.
- `lcobucci/jwt` напрямую (без bundle): `Validator::validate($token, new SignedWith($algorithm, $key))` — если `$algorithm` берётся из `$token->headers()->get('alg')` без enforce → alg confusion.
- `firebase/php-jwt` `JWT::decode($jwt, $keys)` где `$keys` — массив `[$kid => $key]`: атакующий проставляет известный `kid` другого алгоритма → принимается. `firebase/php-jwt >= 6.0` требует `Key` с явным алгоритмом — старые версии (5.x) уязвимы.

## weak_random Laravel-специфика

> sink_kind: `weak_random`. См. `core/crypto.md → weak_random` для generic-описания.

- **`Hash::make($password, ['rounds' => 4])`** — недостаточно rounds для bcrypt. Минимум 10 (default Laravel — 12). `rounds=4` за миллисекунды brute-force-ится. **confidence ≥ 9** (`weak_random` для производного KDF, либо separate finding `weak_kdf_rounds`).
- **`Hash::make($password, ['rounds' => $request->input('rounds')])`** — user-controlled cost factor → DoS (rounds=20 → 30s/hash) или intentional weak hash через rounds=4.
- **`Str::password($length, false, false, false)`** — все опции (`letters`, `numbers`, `symbols`, `spaces`) выключены → метод вернёт пустую строку или crash. `Str::password(12, true, false, false)` — только буквы → entropy 5.7 бит/символ → 68 бит для 12 символов, ниже recommended.
- **`config/hashing.php`: `'argon' => ['memory' => 1024, 'time' => 1, 'threads' => 1]`** — недостаточные параметры для Argon2; используй defaults Laravel (memory=65536, time=4) или явно тюненые под hardware.
- **Явное исключение**: `Str::random($length)` — **НЕ** слабый паттерн. Под капотом `random_bytes()` (PHP 7+ secure CSPRNG). **Не репортить как weak_random.** Проверять только длину: `Str::random(8)` для CSRF/reset token = 48 бит entropy (base62 строка длиной 8 ≈ 47.6 бит), слишком мало — это уже описано в секции `## Random / IDs` выше как длина, не как алгоритм.

## Secret in response Laravel-специфика

> sink_kind: `secret_in_response`. Основной материал — `frameworks/laravel/disclosure.md → secret_in_response (Sanctum / Eloquent / API Resource)`. Здесь только cross-link, чтобы при сканировании crypto-checklist не пропустить категорию.
