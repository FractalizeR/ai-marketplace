# Information disclosure / PII leaks / stacktrace exposure / debug info

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `pii_in_logs` — логирование PII / токенов / паролей в plaintext
- `stacktrace_exposed` — раскрытие stacktrace / debug в response
- `hardcoded_secret` — кросс-ссылка на `crypto.md` / `auth.md`

## Confidence floor rules

- **Плейнтекст PII в логах** (`$logger->info(..., ['password' => $plain])`, `['email' => ..., 'passport' => ...]`) → **confidence ≥ 9** для pii_in_logs.
- **`$exception->getTraceAsString()` в API response в production** (не в debug-ветке) → **confidence ≥ 9** для stacktrace_exposed.
- **`$logger->debug($request->getContent())`** когда body содержит credentials/tokens/PII → **confidence ≥ 8**.
- **Sequential ID в API** (`/user/1`, `/user/2`, ...) без rate-limit + без authz → **confidence ≥ 8** для idor_lookup (cross-ref `auth.md`).

## Логирование чувствительных данных

- `$logger->info('user login', ['password' => $plaintext])`
- Password / token в request log middleware
- `$logger->debug('payload', [$request->getContent()])` — body содержит credit card / password
- Exception logging с `$exception->getTrace(true)` — trace может содержать параметры с секретами
- PII (паспорт, ИНН, email, phone) в info/debug уровнях
- Session ID в access logs
- Database query logs со значениями параметров (любой ORM SQL logger в production)

## PII handling (152-ФЗ / GDPR)

- Сохранение паспортных данных, ИНН, СНИЛС в plaintext колонках вместо шифрованных
- Биометрические данные без явного согласия
- Отсутствие audit log доступа к ПДН (кто и когда читал)
- PII в URLs (`/user/vladimir.ivanov@example.com/profile`) — попадают в логи, referer, browser history
- PII в GET параметрах (должны быть POST-only)
- Отсутствие data retention policy: старые данные хранятся без срока

## API response leaks

- Сериализация без selective field whitelist → весь объект с internal полями отдаётся клиенту
- `email`, `phone`, `hashedPassword`, `lastLoginIp` возвращаются клиентам, которым не нужны
- Relationships сериализуются полностью (`user -> orders -> transactions`) — избыточное раскрытие
- Error response с `$exception->getMessage()` в production — leak внутренних деталей (имя БД, путь файла)
- `__debugInfo()` implementations, рендерящие в API response

## Stacktrace / debug info

- Custom error handler, возвращающий `$exception->getTraceAsString()` в body
- PHP `display_errors=On` в production
- Uncaught exception в JSON API → leak через default framework handler, если не зарегистрирован свой exception listener

## Source code exposure

- `.git/` директория deployed в web-accessible location
- `.env`, `.env.local` readable через web (неверная конфигурация Nginx/Apache)
- `composer.json` / `package.json` доступны — leak dependencies (version info + CVE lookup)
- Backup files: `config.php.bak`, `config.old` в web root
- Source maps (`*.js.map`) в production — leak full original JS source

## API enumeration

- Разный timing ответа «user exists» vs «user doesn't exist» на login/reset — enumerate users
- Разное HTTP status code (401 vs 404) для existing/non-existing resources
- Error message: `"User already exists"` vs `"Invalid credentials"` — раскрывает наличие аккаунта
- Pagination с precise counts → enumerate total records
- Sequential IDs в API (`/user/1`, `/user/2`, ...) — enumerate через инкремент (cross-ref IDOR в `auth.md`)

## Response headers

- `Server: Apache/2.4.41 (Ubuntu)` — leak server version (CVE targeting)
- `X-Powered-By: PHP/7.4.3` — leak PHP version
- `Via:` headers, раскрывающие internal proxies
- `X-AspNet-Version`, etc

## Session cookies

- Session cookie без `HttpOnly` → доступна JS (XSS → session theft)
- Без `Secure` → передаётся по HTTP (если MITM)
- Без `SameSite=Lax/Strict` → CSRF vector
- Long-lived session без idle timeout
