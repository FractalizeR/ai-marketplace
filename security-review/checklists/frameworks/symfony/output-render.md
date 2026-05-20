# Twig / Output rendering / SSTI (Symfony)

> Этот чек-лист дополняет `core/output-render.md` для проектов на symfony. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## `|raw` фильтр

- `{{ user_input|raw }}` — прямой XSS
- `{{ content|striptags|raw }}` — `striptags` не спасает от всех векторов (`javascript:` URIs, CSS expressions)
- User-controlled HTML, прошедший через HTMLPurifier — безопасно, но только если Purifier настроен правильно; без white-list — опасно

## Autoescape

- `{% autoescape false %}` блок с user input внутри
- `config/packages/twig.yaml` с `autoescape: false` глобально
- Кастомные extensions, возвращающие `Twig\Markup` над user input — эквивалентно `|raw`

## JavaScript context

- `<script>var data = {{ user_data|json_encode }};</script>` — **не безопасно**: `</script>` в данных ломает context. Нужен `json_encode` + `html_safe(false)` или `|e('js')`
- User input в `onclick="..."` без `|e('html_attr')`
- User input внутри `<a href="{{ url }}">` — проверка на `javascript:` / `data:` URIs обязательна

## SSTI через динамический template

- `$twig->createTemplate($userInput)->render([...])` — прямой SSTI, RCE через `{{ ['id']|map('system') }}`
- `$this->render($request->get('tpl') . '.html.twig')` — достижимость чужих шаблонов
- `{% include template_from_string(user_input) %}`
- `{{ include(user_input) }}`
- Mailer: `$email->htmlTemplate($userControlledName)` без whitelist — динамическое имя Twig-шаблона

## Mailer (Symfony Mailer)

- `TemplatedEmail::htmlTemplate($name)` с user-controlled `$name`
- `TemplatedEmail::textTemplate($name)` с user-controlled `$name`
- Passing user data в context без санитизации, затем `|raw` в шаблоне письма
- User-controlled subject, рендерящийся через Twig без escape

## Notifier (Symfony Notifier)

- `Notification::content($userInput)` — если content рендерится через Twig в каком-то канале
- Chat/SMS templates с `|raw` user input
- `EmailMessage::fromNotification()` с user-controlled context

## Error rendering

- Custom `ErrorRenderer`, рендерящий stacktrace / exception message в HTML без escape
- `KernelEvents::EXCEPTION` listener, возвращающий Response с user input в теле
- Default Symfony error page в production mode (должна быть отключена через `framework.web_link.enabled: false` и `debug: false`)

## XSS через неочевидные каналы

- User data в `<title>{{ user_title }}</title>` — Twig по умолчанию escape, но если `|raw` — XSS
- `<meta name="description" content="{{ user_desc }}">` — `|e('html_attr')` обязателен для атрибутов
- RSS/Atom feeds с user content без `|e` или CDATA
- PDF/Document generators, принимающие user HTML (Dompdf, TCPDF) — custom HTML sanitization нужен

## GraphQL output filtering (api-platform / overblog/graphql-bundle / webonyx)

GraphQL — это альтернативный output channel; те же правила disclosure / secret leakage, что и для REST/Twig. Field-level authz (кто видит) — в `auth.md`; здесь — что попадает в response payload.

- **api-platform Resource без `#[Groups]`** — все public-getter поля Entity сериализуются для каждой operation: `accessToken`, `refreshToken`, `passwordHash`, `mfaSecret`, `apiToken`, `webhookSecret` уезжают клиенту, если они существуют как property/getter Entity. Должны быть `#[Groups(['user:read'])]` на безопасных полях + `normalizationContext: ['groups' => ['user:read']]` на operation. Sink_kind: `secret_in_response` или `sensitive_field_unmasked` (root_cause_family: `disclosure`).
- **overblog/graphql-bundle resolver возвращает `$entity` напрямую**: `'resolve' => fn($value, $args) => $em->getRepository(User::class)->find($args['id'])` без projection / без mapping в DTO → schema-объявленные поля сериализуются, но любые `Computed`/`@Expose` extras тоже могут утечь. Грепать на resolver, возвращающий Doctrine entity без `->toArray()` / `->toPublicView()`.
- **webonyx native field resolver** не вызывает `->getPublicView()` / `->toArray()` фильтра, а возвращает `$entity` или `$entity->getRecord()` целиком → клиент через alias/fragment может выбрать любое объявленное в schema поле, включая чувствительные. Если в schema случайно объявлен secret-field — он доступен.
- **`Type::nonNull($userType)` + поле `passwordHash` в `$userType`**: даже если field-level authz есть, само наличие поля в schema — information disclosure через introspection. Удалять чувствительные поля из schema, не ограничиваться access control.
- **Error messages в response**: Doctrine exception (`UniqueConstraintViolationException`, `ForeignKeyConstraintViolationException`) пробрасывается до GraphQL response без обработки → клиент видит структуру таблиц / имена колонок. Sink_kind: `stacktrace_exposed`. В prod нужен ErrorHandler / formatter, маскирующий internal errors.

**Cross-link**: `secret_in_response` для polluted output — см. `core/crypto.md`. `sensitive_field_unmasked` — см. `core/disclosure.md`.
