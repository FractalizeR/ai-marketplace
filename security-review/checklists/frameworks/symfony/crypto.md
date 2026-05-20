# Cryptography (Symfony)

> Этот чек-лист дополняет `core/crypto.md` для проектов на symfony. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## APP_SECRET / Symfony secrets

- `APP_SECRET` в `.env` без `.env.local` override (попадает в коммит) — компрометация = подделка signed cookies, signed URLs, CSRF tokens
- Credentials в `services.yaml` / `services.xml` без параметризации через `%env(...)%` — секреты в коммите

## PasswordHasher misuse

- Symfony password hasher `plaintext` или `md5`/`sha1` для User entity (`config/packages/security.yaml::password_hashers`) — применяется при `UserPasswordHasherInterface::hashPassword()` → слабые хэши паролей в БД

## Symfony JWT bundle pitfalls

- `lexik/jwt-authentication-bundle`: weak / hardcoded `JWT_PASSPHRASE` в `.env` (попадает в коммит); short TTL не настроен; `token_extractors` принимает токен из несекьюрных источников (query param) при cookie-auth

## JWT (lexik/jwt-authentication-bundle) — расширенно

Дополняет одноимённую секцию выше; здесь — полный набор bundle-specific паттернов.

- **`JWT_PASSPHRASE` / `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` в `.env` без `.env.local` override** (попадает в коммит) → атакующий ре-подписывает токены любого пользователя → полный bypass authentication. Sink_kind: `hardcoded_secret`. Cross-link: `auth.md` → JWT bundle и `core/crypto.md` → APP_SECRET.
- **`token_extractors.query_parameter.enabled: true`** в `config/packages/lexik_jwt_authentication.yaml` при cookie/header auth: токен попадает в URL → утечка через browser history, server access logs, `Referer` header. Если query — единственный extractor, оценить, не должен ли быть cookie/header.
- **`kid` / `jwk` header passthrough**: только если в проекте есть **custom Authenticator** или прямой вызов `JWSLoader`/`JWTEncoderInterface::decode()`, передающий header `kid` в file-system path lookup без whitelist → kid header injection (path traversal к подконтрольному keyfile). См. `core/crypto.md` → JWT advanced.
- **Token TTL не настроен или слишком велик** (`token_ttl: 3600` ок, `token_ttl: 31536000` — год — нет): отсутствие refresh-flow + долгий TTL → revocation невозможна.

## JWT advanced (общие паттерны)

Все паттерны из `core/crypto.md → JWT advanced` (kid header injection, jwk/x5u header injection, algorithm confusion RS256→HS256, aud/iss mismatch, nbf/iat skew без leeway) применимы к Symfony одинаково. Symfony specifics:

- **`Lcobucci\JWT\Configuration` напрямую (без bundle)**: при создании `Configuration::forSymmetricSigner(...)` / `forAsymmetricSigner(...)` validation constraints (`SignedWith`, `IssuedBy`, `PermittedFor`, `LooseValidAt`/`StrictValidAt`) **опциональны**. Если разработчик забыл `setValidationConstraints([...])` или вызвал `->validator()->validate($token)` без constraints → любая подпись/iss/aud принимается. Грепать `Lcobucci\JWT\Configuration` без последующего `setValidationConstraints`. Confidence ≥ 8 для проектов, использующих такие токены для authn.
- **`web-token/jwt-framework` (если используется)**: `JWSLoader` без `signatureAlgorithms` whitelist → algorithm confusion возможен; `JWKSet::createFromKeyData()` принимающий untrusted JWK без `kid` whitelist.

## Persistent OAuth credentials в plain `string` columns (Doctrine entity)

- `#[ORM\Column(type: 'string')] $accessToken | $refreshToken | $clientSecret | $apiKey | $botToken | $authToken | $webhookSecret` — без custom Doctrine Type / EncryptedStringType → encryption-at-rest gap
- Также проверить JSON-конфиги: `#[ORM\Column(type: Types::JSON)] $config` где `$config` сериализует `botToken`/headers с `Authorization: Bearer ...` (типичный паттерн в notification channel / webhook mapping entities)
- Sink_kind: `hardcoded_secret` (root_cause_family `crypto`)
- Threat: DB compromise (snapshot/backup leak / SQL injection / DBA insider) даёт persistent доступ ко всем integrations всех tenant'ов; refresh tokens обычно живут месяцами и продлеваются автоматически
- Fix: Doctrine custom type с AES-256-GCM (ключ из `framework.secrets:` или KMS), `doctrine-encrypt-bundle`/`halite`
