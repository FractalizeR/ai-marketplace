# Authentication, Authorization, IDOR, Disclosure-adjacent auth issues

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `missing_authz` — отсутствие проверки прав на server-side
- `idor_lookup` — доступ к ресурсу по ID без проверки владельца
- `csrf_missing` — отсутствие CSRF protection на mutating endpoint
- `cors_misconfig` — `Access-Control-Allow-Origin: *` с credentials
- `webhook_unverified` — webhook без подписи / защиты от replay
- `hardcoded_secret` — ключи/токены в репозитории
- `oauth_state_missing` — OAuth/OIDC callback без state параметра / PKCE

## Confidence floor rules

- **Webhook endpoint без проверки signature** (нет `hash_equals`, нет HMAC валидации) → **confidence ≥ 9** для webhook_unverified.
- **`Access-Control-Allow-Origin: *`** вместе с `Access-Control-Allow-Credentials: true` → **confidence ≥ 9** для cors_misconfig.
- **OAuth callback без `state`/PKCE на public client** → confidence ≥ 9 (`oauth_state_missing`, well-known attack class — account linking / session hijack).

## IDOR

- Получение ресурса по ID из request без проверки владельца: ORM-lookup типа `repository.find($request->...)` / equivalent без сравнения с текущим пользователем
- Auto-binding параметра пути в entity без authz-чека в обработчике (любой framework value resolver / param converter)
- Предсказуемые sequential ID (`/orders/123`, `/orders/124`) без UUID или authz
- Доступ к чужим файлам через `/download?file=...` без проверки принадлежности

## JWT и токены

- JWT с `alg: none` или отсутствием валидации алгоритма
- Слабый `secret` (короткий, в репозитории)
- Отсутствие проверки `exp` (expiration)
- JWT в localStorage вместо httpOnly cookie (frontend risk, см. также frontend-js.md)
- `sub` claim принимается без проверки существования пользователя

## OAuth/OIDC

- PKCE для public clients (mobile/SPA): отсутствие `code_challenge` / `code_verifier` пары (`oauth_state_missing` если callback без state, иначе обычный missing-defense).
- `redirect_uri` whitelist по `startsWith` или `substring` вместо точного `exactMatch` / prefix-with-trailing-slash — атакующий регистрирует `evil.com.legit.app` или `app/path?redirect=evil.com`.
- Account linking без верификации владения новым email (link request присылает code на email, но не валидирует, что именно владелец нажал).
- Token swap через login CSRF: атакующий заставляет жертву аутентифицироваться его OAuth-аккаунтом → атакующий получает доступ к данным жертвы.
- `prompt=none` silent re-auth абуз: атакующий через silent re-auth без user interaction обновляет токены жертвы.
- OAuth state параметр отсутствует (`oauth_state_missing`, **confidence floor ≥ 9** для public clients).

## MFA / lifecycle

- TOTP replay в окне ±N секунд без drift-counter / proof-of-burned-code.
- Recovery codes без single-use enforcement и без re-hash на consumption.
- MFA enrollment через self-service без verification proof-of-current-session.
- `remember-device` cookie без TTL / UA-binding / IP-binding (теряет MFA gate forever).
- Email change через self-service без confirm нового адреса (account takeover через email).
- Password change без вызова `logoutOtherDevices()` / `invalidateSessions()` — старые сессии остаются активны.
- Account merge / soft-delete restore через tenant boundary (восстановление на чужого tenant'а).

## Password reset / impersonation

- Password reset token: предсказуемый, не invalidируется после использования, хранится plaintext
- Отсутствие ограничения по времени действия reset-токена
- Account enumeration через разные ответы для «user exists» vs «user not found» на reset endpoint
- Impersonation без логирования / без проверки admin-роли на исходном пользователе

## Signed URLs

- URL с signature, где подпись считается от частичного payload (легко подделать)
- Signed URL без expiration (валиден вечно)
- Signed URL с user-controlled `path` без verification, что path в whitelisted scope

## Webhook signature verification (incoming webhooks)

- Webhook endpoint принимает запросы без проверки `X-Signature` / HMAC
- Verification через `==` вместо `hash_equals()` (timing attack)
- Отсутствие replay protection: webhook можно переиграть, отсутствует `nonce` / `timestamp` с коротким окном
- Отсутствие idempotency key: повторная обработка того же webhook вызывает повторные side-effects

## CSRF

- API endpoint с cookie-based аутентификацией, принимающий мутирующие запросы без CSRF / anti-forgery токена
- `Access-Control-Allow-Origin: *` одновременно с `Access-Control-Allow-Credentials: true` (cross-ref CORS misconfig)

## Tenancy trust anti-patterns (internal/service firewalls с shared secret)

Типичный паттерн внутренних firewall'ов / service-to-service auth: обработчик принимает shared-secret header (например `X-Internal-Auth`, `X-Service-Key` или подобные) и аутентифицирует **сервис**, а не **tenant**. Далее контроллеры используют tenant-owner поле (`tenantId` / `workspaceId` / `ownerId`) из **тела запроса или URL** без cryptographic binding к аутентифицирующему секрету. Один скомпрометированный shared service secret → cross-tenant операции над любыми арендаторами.

- **Service-level auth принимает tenant-ID из body**: handler читает body / DTO с tenant-owner полем и пишет в БД без проверки, что источник вызова действительно представляет этого tenant'а. **confidence ≥ 8**, sink_kind `missing_authz`, root_cause `authz`.
- **Отсутствие HMAC-binding body к tenant-ID**: внутренний API ожидает `Authorization: Bearer <service_secret>`, но не требует `X-Tenant-Signature: hmac(body, tenant_secret)`. Shared secret не доказывает право на указанный tenant.
- **Identity headers без подписи**: identity-заголовки вида `X-User-Id` / `X-Tenant-Id` / `X-Role` из upstream прокси без HMAC/JWT — downstream доверяет заголовкам, но любой, кто обошёл прокси (direct access к pod/node, SSRF через соседний сервис), может их подделать.
- **Shared secret одинаков для всех сервисов-потребителей**: ротация требует одновременных правок везде; компрометация одного потребителя = компрометация всего contour'а. Должна быть per-service subject с отдельными ключами.
- **Service auth через `in_array($secret, $validSecrets, true)` вместо `hash_equals`**: timing attack при сравнении shared secrets. См. `crypto.md`.
- **Отсутствие IP CIDR / mTLS для internal endpoints**: внутренний API открыт на public interface с одной лишь проверкой header'а. Любая SSRF в соседнем сервисе → cross-tenant write.

## Throttling / rate limiting (отсутствие защиты — тоже находка)

«Защитного кода нет» — репортить, не только «защитный код уязвим».

- **Нет throttling на login endpoint** (form_login / json_login / любой password-based вход) → brute-force / password spray. **confidence ≥ 8**.
- **Нет rate-limit на public mutating endpoint** (password reset request, signup, contact-form) → enumeration / spam / resource exhaustion на auth poverty.
- **Нет rate-limit на webhook receiver** → replay storm против нижнего сервиса.
- **Нет account lockout / задержки после N неудачных попыток reset/login** → enumeration через тайминги и разные HTTP коды.

## Hardcoded secrets

- API ключи, пароли, токены прямо в коде (`$apiKey = "sk_live_..."`)
