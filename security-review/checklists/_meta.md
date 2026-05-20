# Конвенция чек-листа

Этот файл описывает формат и правила для всех `checklists/**/*.md` в плагине `fr-security-review`.

## Двухуровневая структура

```
checklists/
├── _meta.md
├── core/                       # активны всегда (любой проект, любой стек)
│   └── {theme}.md              # auth, crypto, disclosure, injection, data-access,
│                               # output-render, serialization, ssrf-fileops, fintech, frontend-js
└── frameworks/
    └── {stack}/                # активен, только если CONTEXT.md frontmatter содержит этот stack
        ├── _detect.md          # как detect срабатывает (для документации)
        └── {theme}.md          # та же тема, но framework-specific уточнения
```

**Правило резолва (см. `bin/plan_waves.py::resolve_checklists`):** для каждой темы волны worker получает `core/{theme}.md` всегда, и `frameworks/{stack}/{theme}.md` дополнительно — если для проекта детектирован соответствующий stack и файл существует. При отсутствии framework-файла (или `framework: none/unknown`) worker работает только с core.

**Приоритет при конфликте инструкций:** framework-файл **более специфичен**, его инструкции имеют приоритет над core. Worker загружает оба файла одновременно и применяет уточнение там, где оно есть.

**Anchor framework-файла.** Каждый `frameworks/{stack}/{theme}.md` начинается со стандартной шапки (после заголовка):

> Этот чек-лист дополняет `core/{theme}.md` для проектов на {stack}. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

## Обязательная шапка чек-листа

Каждый чек-лист (и core, и framework) включает стандартный блок методологии. **Не изменять формулировку** — воркеры распознают этот блок при загрузке:

> **Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

Для framework-файлов anchor (про приоритет над core) идёт **перед** этой шапкой.

## `## Recommended sink_kinds` — только в core-файлах

Каждый **core**-чек-лист перечисляет те значения из закрытого enum `sink_kind`, которые он покрывает. Воркер выбирает sink_kind для каждой находки из этого списка (или `other:<name>` для категорий, не уложившихся в enum).

**Framework-файлы НЕ объявляют свою секцию `## Recommended sink_kinds`** — они уточняют применимость sink_kind, объявленных в соответствующем `core/{theme}.md`. Это правило закреплено: framework checklist **не вводит новые `sink_kind`**, а сужает/уточняет применимость core sink_kind. Все находки воркера всегда классифицируются sink_kind из core enum.

Значения enum `sink_kind`:
`dql_concat`, `native_sql_concat`, `unsafe_html_render`, `template_raw`, `ssti`, `unserialize_untrusted`, `command_exec`, `file_include_dynamic`, `path_traversal`, `redirect_open`, `weak_hash`, `hardcoded_secret`, `cors_misconfig`, `missing_authz`, `idor_lookup`, `xxe`, `ssrf`, `mass_assignment`, `csrf_missing`, `decimal_arith`, `race_condition`, `webhook_unverified`, `pii_in_logs`, `stacktrace_exposed`, `type_juggling`, `oauth_state_missing`, `webhook_replay`, `weak_random`, `secret_in_response`, `sensitive_field_unmasked`.

### Замечание про `dql_concat` (overloaded имя)

`dql_concat` исторически назван в честь Doctrine DQL, но используется как **общая категория для любого ORM-query string concatenation**: Doctrine DQL (Symfony), Eloquent query builder с `whereRaw`/`orderByRaw` (Laravel), SQLAlchemy raw text expressions (Python), любые другие native ORM raw-query конкатенации. Альтернативное имя `orm_query_concat` рассматривалось, но переименование сломало бы дедуп-парсер и ключи fingerprint без значимого выигрыша. Имя зафиксировано — расширение семантики документировано здесь.

Для нативных SQL-конкатенаций (без ORM-обёртки, через PDO/mysqli/pg_*/cursor.execute) используй `native_sql_concat`.

### Закрытый enum `root_cause_family`

`injection`, `xss`, `authz`, `disclosure`, `crypto`, `deserialization`, `ssrf`, `webhook`, `business_logic`. Все имена **generic** (стек-нейтральные); никаких `doctrine`/`twig`/`voter`/`eloquent` в семантике. Кастомное имя через `other:<name>` (исключается из автодедупа).

### Мэппинг `sink_kind` → `root_cause_family`

| sink_kind | root_cause_family |
| --- | --- |
| `dql_concat`, `native_sql_concat` | `injection` |
| `unsafe_html_render`, `template_raw`, `ssti` | `xss` |
| `unserialize_untrusted` | `deserialization` |
| `command_exec`, `file_include_dynamic`, `path_traversal` | `injection` |
| `redirect_open` | `business_logic` |
| `weak_hash`, `hardcoded_secret` | `crypto` |
| `cors_misconfig` | `authz` |
| `missing_authz`, `idor_lookup`, `mass_assignment` | `authz` |
| `xxe`, `ssrf` | `ssrf` |
| `csrf_missing` | `authz` |
| `decimal_arith`, `race_condition`, `type_juggling` | `business_logic` |
| `webhook_unverified`, `webhook_replay` | `webhook` |
| `pii_in_logs`, `stacktrace_exposed`, `secret_in_response`, `sensitive_field_unmasked` | `disclosure` |
| `oauth_state_missing` | `authz` |
| `weak_random` | `crypto` |

## Формат пунктов

Пункты чек-листа — маркированный список с фокусом на паттерны кода или конфигурации. Не общие советы («используй HTTPS»), а конкретные признаки уязвимости в коде.

Примеры:

- ✅ `preg_replace()` с модификатором `/e` — RCE через динамическую оценку
- ❌ «Следуй best practices безопасности»

## Опциональная секция `## Confidence floor rules`

Если для категории есть однозначные паттерны, где confidence **не должен** варьироваться между воркерами — зафиксируй их в отдельной секции чек-листа. Это убирает лотерею «один воркер смелее, другой осторожнее» и даёт предсказуемый recall.

Формат: список пунктов вида «если код удовлетворяет условию X → confidence ≥ Y».

Пример:
```markdown
## Confidence floor rules

- Commited `.env` в git с `APP_SECRET`/`*_KEY`/`*_TOKEN` → confidence ≥ 8. Проверка prod-override — обязанность ревьюера, не бар для репорта.
- MD5/SHA1 для хэша пароля → confidence ≥ 9 (без исключений).
```

Floor rules **не заменяют** гейт качества (confidence ≥ 8, severity ≥ MEDIUM) — они его уточняют для конкретных паттернов.

Floor rules могут жить и в core, и во framework — там, где они наиболее специфичны. Если паттерн упоминается в обоих, framework-версия (более специфичная) имеет приоритет.

## Confidence floor — где живёт

| Тип паттерна | Куда |
| --- | --- |
| Generic (без framework-сигнатур): `==` для секретов, MD5 для пароля, `unserialize($_GET[...])` | `core/{theme}.md` |
| Framework-specific (`#[IsGranted]`, `security.yaml`, `Voter`, `#[Route]`, EasyAdmin/Sonata) | `frameworks/{stack}/{theme}.md` |

## Cross-theme дублирование (admin-CRUD)

Чек-листы `frameworks/symfony/auth.md` И `frameworks/symfony/data-access.md` оба содержат раздел про admin-bundle CRUD (EasyAdmin/Sonata) — намеренно. Worker, запускаясь в W1 (auth) и W2 (injection/data-access), оба раза получает admin-контекст. Это единственный санкционированный случай дублирования между файлами одного стека (учтено в дедупе через `flag=[CROSS_SINK_MERGE]` для находок на одной строке).

## Cross-theme дублирование (GraphQL)

Раздел про GraphQL присутствует в трёх темах одного стека:

- `frameworks/{stack}/auth.md` — field-level authz (resolver без `@guard`/`#[IsGranted]`/`@can`/voter check, introspection в prod как information disclosure).
- `frameworks/{stack}/data-access.md` — query depth/complexity DoS, alias batching, persisted-queries bypass, introspection как enumeration vector.
- `frameworks/{stack}/output-render.md` — output filtering (resolver возвращает Entity без `#[Groups]`/`$hidden`/Resource projection).

Распределение по темам отражает разные attack-классы; с одного места (например, schema YAML или единственный resolver) обычно эксплуатируется только одна категория. Дедуп уже знает: если две находки попали на один `(sink_file, sink_line)`, но с разным `sink_kind` — одна получает `[CROSS_SINK_MERGE]`, остальные становятся `alternative_sink_kinds`.

## Sink_kind disambiguation (3.4.0)

Новые `sink_kind` 3.4.0 близки по смыслу к существующим — для воркера зафиксированы границы, чтобы не было «лотереи» классификации:

| Кейс | sink_kind | Не путать с |
| --- | --- | --- |
| OAuth/OIDC callback без `state`/PKCE | `oauth_state_missing` | `csrf_missing` (общая CSRF на mutating form) |
| Webhook **с** HMAC, но без nonce/timestamp/idempotency | `webhook_replay` | `webhook_unverified` (без HMAC вообще) |
| Прямой вызов `mt_rand`/`rand`/`uniqid`/`microtime` для security-чувствительного значения | `weak_random` | `hardcoded_secret` (литерал в коде) |
| Token/secret leak в HTTP response body (JSON / template render) | `secret_in_response` | `pii_in_logs` (леак в лог/файл/backup) |
| Admin UI выводит raw token field без masking | `sensitive_field_unmasked` | `secret_in_response` (response body), `pii_in_logs` (логи) |

`Str::random()`, `random_bytes()`, `random_int()`, `Symfony\Component\String\ByteString::fromRandom()` — **НЕ** `weak_random`: внутри они опираются на CSPRNG.

## Структура core-файла

```markdown
# <Название категории>

<обязательная шапка — скопировать дословно>

## Recommended sink_kinds

- `<sink_kind1>` — комментарий
- `<sink_kind2>` — комментарий

## Confidence floor rules
(опционально)

- ...

## <Подкатегория A>

- пункт
- пункт
```

## Структура framework-файла

```markdown
# <Название категории> ({stack})

<anchor про приоритет над core — скопировать дословно из этого _meta>

<обязательная шапка методологии — скопировать дословно>

## Confidence floor rules
(опционально, framework-specific)

- ...

## <Подкатегория A>

- пункт
- пункт
```
