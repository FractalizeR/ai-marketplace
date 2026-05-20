# SSRF / HTTP Client / File operations / Uploads

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `ssrf` — исходящий запрос к user-controlled URL (host/protocol)
- `redirect_open` — открытый редирект через user input
- `path_traversal` — file ops с непроверенным путём
- `file_include_dynamic` — `include`/`require` с user-controlled путём (cross-ref `injection.md`)

## SSRF через HTTP Client

- HTTP-клиент любого фреймворка с user-controlled URL аргументом (`request($method, $userUrl)`)
- Guzzle с user-controlled base URI
- `file_get_contents($url)` где `$url` — user input (читает через HTTP wrapper)
- `curl_init($url)` с user URL
- Отсутствие whitelist хостов / схем (`http`/`https` только, блокировать `file://`, `gopher://`, `dict://`)
- Отсутствие блокировки private IP: `127.0.0.1`, `169.254.169.254` (AWS metadata), `10.0.0.0/8`, `192.168.0.0/16`
- DNS rebinding: проверка хоста до resolve, но actual resolution идёт позже — используй IP resolution и повторную проверку
- TOCTOU между validation (admin form / `SafeUrl` constraint при сохранении в БД) и use (HTTP request в worker) — если URL хранится между T1 и T2, атакующий может перевести DNS-запись на private IP в этом окне (классический DNS rebinding с TTL ≤ 30s). Особенно типично для Symfony Messenger pipelines: admin form → DB → async consumer → `httpClient->request($url, ...)`. Fix: revalidate URL перед HTTP-запросом, либо `RequestOptions::RESOLVE` (Guzzle) / `'resolve' =>` (Symfony HttpClient) с IP, зарезолвленным при validation, либо egress firewall на сетевом уровне

## SSRF через webhooks / callbacks

- User-configurable webhook URL без whitelist → SSRF на внутренние сервисы
- OAuth callback URL не валидируется против зарегистрированных redirects
- Image/PDF generators (wkhtmltopdf, Puppeteer), принимающие user URL — SSRF + потенциально RCE через браузер

## Open redirects

- `return $this->redirect($request->...->get('next'))` без whitelist
- Redirect response с user URL после login / action — phishing vector
- Protocol-relative URLs `//evil.com` — обходит naive `startswith('/')` check
- URL без валидации scheme (`javascript:...`, `data:...`)

## File operations — path traversal

- `file_get_contents($userPath)` без `realpath()` + whitelist базовой директории
- `fopen($userPath, ...)` с user input
- `readfile($userPath)` для download — прямо позволяет `../../../etc/passwd`
- `basename()` недостаточен — он возвращает последний сегмент, но user может задать `../sensitive/file`
- Sanitization только от `..` через `str_replace`, без учёта URL encoding (`%2e%2e%2f`)
- `realpath()` используется, но whitelist базы не применяется

## File uploads

- Отсутствие проверки MIME по содержимому (`finfo_file`) — полагание на `$_FILES['file']['type']` (client-controlled)
- Сохранение файла с оригинальным именем без санитизации → `../../../attack.php`
- Отсутствие проверки расширения из whitelist
- Upload в web-accessible директорию → executable PHP/PHAR files
- Отсутствие ограничения размера (`upload_max_filesize`, application-level)
- ZIP-bombs / decompression без лимитов
- Polyglot files (GIF+PHP) — MIME magic совпадает, но содержимое опасно
- Framework-уровневый `UploadedFile::move()` с user-controlled `$name`

## File inclusion

- `include($userPath . '.php')` — LFI, см. `injection.md`
- Template loaders с user-controlled path
- Локальные PHAR files с metadata — `file_exists()` на phar URL триггерит unserialize metadata

## Download endpoints

- `/download?file=...` без authz (см. также `auth.md` IDOR)
- `Content-Disposition` с user-controlled filename — возможность inject CRLF / path traversal в header
- MIME sniffing prevention: missing `X-Content-Type-Options: nosniff`

## Export / CSV injection

- User data в CSV exports без prefix escaping: ячейки, начинающиеся с `=`, `+`, `-`, `@`, могут исполняться при открытии в Excel/LibreOffice
- Экспорт в SVG с user content → XSS при открытии файла в браузере
