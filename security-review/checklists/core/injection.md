# Injection (generic) — command, code, XXE, path traversal

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `command_exec` — `exec`/`shell_exec`/`Process` с пользовательским вводом
- `file_include_dynamic` — `include`/`require` с динамическим путём
- `path_traversal` — file operations с непроверенным пользовательским путём
- `ssti` — Server-Side Template Injection (динамический template name / source)
- `xxe` — XML External Entity
- `mass_assignment` — неограниченное разворачивание данных в объекты (см. также `data-access.md`)

## Confidence floor rules

- **`exec()`/`shell_exec()`/`system()` с user input** (путь от `$request` / `$_GET` / `$_POST` до sink прослежен) → **confidence ≥ 9** для command_exec.
- **`eval()` с user-controlled данными** → **confidence ≥ 10** для ssti/command_exec.
- **`include(<dynamic>)` / `require(<dynamic>)`** с частью пути от user input без whitelist → **confidence ≥ 9** для file_include_dynamic.
- **`unserialize($userData)`** без `['allowed_classes' => false]` → **confidence ≥ 9** для unserialize_untrusted.

## Command injection

- `exec()`, `shell_exec()`, `system()`, `passthru()`, `popen()`, `` ` ` `` (backticks) с user input без `escapeshellarg`/`escapeshellcmd`
- Process abstraction с shell-string mode (например `Process::fromShellCommandline($str)`) с user input — опасно. Версия с массивом аргументов — безопасно
- `proc_open()` с user-controlled cmd
- Параметры, попадающие в shell через environment variables, если приложение использует их в shell-exec

## Code injection / dynamic execution

- `eval()` с user input — RCE
- `assert($user_string)` — legacy RCE (в старых версиях PHP)
- `create_function()` (удалён в 8.0, но legacy)
- `preg_replace()` с модификатором `/e` — RCE (до 7.0)
- Динамическое выполнение:
  - `$$variable` — variable variables с user-controlled name
  - `$object->$method()` — dynamic method call
  - `call_user_func($fn, ...)`, `call_user_func_array($fn, ...)` с user-controlled `$fn`
  - `ReflectionClass::newInstanceArgs()` с user input

## File include / path traversal

- `include($_GET['page'] . '.php')`, `require($path)` с user-controlled путём — LFI/RFI
- `file_get_contents()`, `fopen()`, `readfile()` с user-controlled путём без `realpath()` и whitelist
- `basename()` недостаточен: не защищает от `../../../etc/passwd` (basename возвращает только последний сегмент)
- Обход `open_basedir` через symbolic links и URL wrappers (`php://`, `phar://`)
- Sanitization только от `..` без учёта абсолютных путей (`/etc/passwd`), URL-wrappers

## SSTI (Server-Side Template Injection) — see also

Anti-patterns по template engines живут в `output-render.md` (core) и framework-чек-листах. Здесь только sink_kind enum.

## XXE

- `simplexml_load_string($data)` без `LIBXML_NOENT = false` и без `libxml_disable_entity_loader(true)`
- `DOMDocument::loadXML()` без `LIBXML_NONET` / `LIBXML_NOENT = false`
- `XMLReader::xml()` с user input, когда внешние сущности не отключены
- SOAP client с user-controlled WSDL
- SAML ответы, XML-RPC без защиты от entity expansion

## LDAP / XPath / NoSQL

- LDAP injection: `(&(uid=$user))` с user input без escape (`ldap_escape`)
- XPath injection: `$xml->xpath("//user[name='$name']")` без escape
- NoSQL injection (MongoDB, если используется): operator injection через JSON input (`{"$ne": null}` в поле password)

## PHP Object Injection

- `unserialize($_GET['data'])` с user-controlled input — RCE через магические методы `__wakeup()`, `__destruct()`, `__toString()`
- Сохранение cookies как serialized данные и десериализация без `allowed_classes`
- См. также `serialization.md`
