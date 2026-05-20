# Cryptography / weak algorithms / hardcoded secrets / type juggling

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `weak_hash` — MD5/SHA1 для паролей или security-чувствительных хешей
- `hardcoded_secret` — API key/password/token в репозитории
- `type_juggling` — слабое сравнение `==` для security-чувствительных значений
- `weak_random` — небезопасный source of randomness для security-критичных значений
- `secret_in_response` — token/secret leak в HTTP response body

## Confidence floor rules

Для следующих паттернов confidence **не варьируется** между воркерами — это однозначные уязвимости, не требующие «смелой интерпретации»:

- **Commited `.env` в git** с реальным значением `*_KEY`/`*_TOKEN`/`*_SECRET` (не placeholder `__YOUR_SECRET_HERE__`, не `.env.example`/`.env.dist`) → **confidence ≥ 8**. Проверка «вдруг это не prod» — обязанность ревьюера, **не бар для репорта**.
- **Hardcoded credential в коде** (`$apiKey = 'sk_live_...'`, `$password = 'real_value'`) → **confidence ≥ 9**.
- **MD5/SHA1 для хеша пароля** (любой password hasher с `md5`/`sha1`) → **confidence ≥ 9**.
- **`verify_peer: false`** / `CURLOPT_SSL_VERIFYPEER = false` в production-сервисах → **confidence ≥ 8**.
- **`==` вместо `hash_equals()`** при сравнении токенов/hash'ей → **confidence ≥ 9**.
- **JWT с `alg: none`** или отсутствие проверки алгоритма → **confidence ≥ 10**.

## Hardcoded secrets

- API keys, пароли, токены прямо в коде (`$api = 'sk_live_...'`)
- Secrets в env-файлах, попадающих в коммит (отсутствует `.local`/override механизм)
- Конфиги (yaml/ini/json) без параметризации через переменные окружения
- Git history: секрет удалён в новом коммите, но виден в git log (требует rotation)
- Staging/dev credentials, случайно deployed в production config

## Weak hashes / algorithms

- `md5($password)`, `sha1($password)` для хранения паролей (даже с salt — слабо)
- `md5($apiKey)` для HMAC — используй `hash_hmac('sha256', ...)` с `hash_equals`
- JWT с `alg: none` или `HS256` без strong secret
- 3DES, RC4, ECB mode для симметричного шифрования
- SSL/TLS с устаревшими протоколами, SSLv3, TLS 1.0 (зависит от конфигурации, не кода)

## JWT advanced

- `kid` header injection: атакующий контролирует `kid` → forge HMAC через path traversal к public file как ключу.
- `jwk` / `x5u` header injection: атакующий встраивает свой публичный ключ в header → подписывает свой JWT.
- Algorithm confusion (RS256→HS256): сервер не валидирует `alg` → атакующий заявляет HS256 + использует RSA public key как HMAC secret.
- `aud` / `iss` mismatch: проверки нет → token от другого сервиса принимается.
- `nbf` / `iat` skew без leeway → false-positive отказ; или отсутствие проверки → past tokens принимаются.

## Weak random

Покрывает sink_kind `weak_random`. **Только** прямые вызовы небезопасных API:

- `mt_rand()`, `rand()`, `uniqid()`, `microtime()` для security-чувствительных значений (CSRF tokens, password reset tokens, session ID, OAuth state, salt, nonce).
- `array_rand()` / `shuffle()` для security selection (выбор admin permission, выбор cryptographic key из набора).

**Явное исключение из weak_random:** обёртки на `random_bytes()` / `random_int()` под капотом — не репортить. Например, Symfony `Symfony\Component\String\ByteString::fromRandom()`, Laravel `Str::random()` (PHP 7+ → `random_bytes`), `bin2hex(random_bytes(N))`.

**Floor:** confidence ≥ 9 при подтверждённо-слабом sink (нашли прямой `mt_rand` в security-критичной точке).

## Secret in response

Покрывает sink_kind `secret_in_response`. Token/secret leak в HTTP response body:

- Symfony Serializer возвращает Token entity без `#[Groups]` фильтра (полное entity сериализуется → `accessToken`, `refreshToken` в response).
- Laravel API Resource возвращает поле с `api_token` / `password` / `secret` (отсутствие `$hidden` или Resource projection).
- Webhook receiver echo'ит back подпись/секрет в response body (диагностический endpoint, оставшийся в prod).
- JSON response полностью сериализует config-объект, включая чувствительные ключи.

**Floor:** confidence ≥ 9 если нашли явный leak активного secret'а в response body.

## Key management

- Encryption key хранится в том же месте, что и зашифрованные данные
- Fixed IV для AES-CBC (должен быть random per encryption)
- Короткий ключ (< 128 bit для AES)
- Cipher без authentication (AES-CBC без HMAC — padding oracle vulnerable); использовать AES-GCM
- Key rotation не реализован

## Encryption at rest (секреты в БД без шифрования)

Токены и ключи, хранимые **в БД** plaintext — отдельный класс от «hardcoded secrets» (которые в репозитории). Компрометация БД или backup выдаёт долгоживущие credentials третьих сторон.

- **OAuth access/refresh tokens в БД plaintext** (поля `accessToken` / `refreshToken` для хранения OAuth tokens интеграций — `Column(type: 'string')` или эквивалент): компрометация БД → атакующий получает доступ к аккаунтам пользователей у external OAuth-провайдера от имени интеграции. **confidence ≥ 8**, sink_kind `hardcoded_secret` (расширенная трактовка: секрет-at-rest без шифрования).
- **JWT refresh tokens в БД plaintext**: refresh token обычно долгоживущий — компрометация БД выдаёт long-lived impersonation возможность.
- **API keys внешних сервисов plaintext** (поля типа `apiKey`, `signingSecret`, `botToken` и подобные): позволяет атакующему подделывать events от имени интегрированного сервиса или снимать сигнатуры.
- **Webhook shared secrets plaintext**: если злоумышленник снимает из БД значение, которое сервис использует для HMAC подписи incoming webhook'ов — он может подделать webhook.
- **Passwords / answers в БД без bcrypt/argon**: см. «Weak hashes». Это не at-rest encryption, но соседний анти-паттерн.
- **Session storage с plaintext тела сессии**: session handler с полями `user_id`, `csrf_token` без шифрования — доступ к БД = hijack session.

**Безопасные решения**: ORM-уровневое шифрование столбцов, Vault/KMS lookup при загрузке (токены не хранятся в БД вообще — только reference), per-row encryption с ключом из env.

**Не находка**: если поле уже шифруется через lifecycle callback / type, и ключ вне БД; или если field — ephemeral (TTL < 5 минут) и single-use.

## Cryptographic randomness

- `rand()`, `mt_rand()` для security tokens — не криптографически стойкие
- `uniqid()` для одноразовых токенов
- Вместо этого — `random_bytes()`, `random_int()`
- Session ID generated через weak PRNG
- CSRF token через `md5(time())` или подобное

## Type juggling / comparison

- `==` вместо `===` для сравнения токенов, hashes
- `if ($user_hash == $expected)` — `"0e..."` strings могут приравняться друг к другу как float
- `in_array($needle, $haystack)` без `strict: true` — type juggling
- Comparison user input с numeric value через `==` (`'abc' == 0` → true)
- Password verify через `==` вместо `password_verify()`
- `hash_equals($known, $user)` обязателен для сравнения строк секретов (timing attack)

## Certificate validation

- `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)` — полное отключение верификации
- Любой HTTP-клиент (curl/Guzzle/HttpClient) с `verify_peer: false` или `verify: false`
- User-controlled CA bundle path
- Игнорирование hostname mismatch

## Signed URLs / cookies / tokens

- Подпись только части payload → возможность tampering остальных полей
- `RememberMe` / signed cookie без TTL
- Expired tokens не инвалидируются
- Refresh token reuse detection отсутствует (токен можно использовать несколько раз)

## Password policies

- Нет минимальной длины / complexity
- Нет проверки против common password list
- Unlimited login attempts без throttling (см. `auth.md`)
- Password reset flow с weak token (см. `auth.md`)
