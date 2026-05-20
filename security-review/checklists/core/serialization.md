# Deserialization / object injection (generic)

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `unserialize_untrusted` — `unserialize()` или эквивалентный API на непроверенных данных
- `mass_assignment` — неограниченная денормализация в privileged objects
- `missing_authz` — обработчик async сообщения без проверки прав

## PHP native unserialize

- `unserialize($_GET['data'])` / cookies / session из ненадёжного источника — RCE через магию `__wakeup`, `__destruct`, `__toString`, `__call`
- `unserialize($data)` без `['allowed_classes' => false]` — принимает любые объекты
- Gadget chains: PHAR files с metadata, загружаемые через `file_exists($phar_path)` / `fopen('phar://...')`
- Десериализация из cache layer (memcached, redis) без контроля целостности

## YAML / JSON / TOML

- `yaml_parse()` с user input без `YAML_PARSE_NO_CODE` → RCE
- YAML loader с включёнными custom tags и user input (любой parser, поддерживающий выполнение тегов)
- `json_decode()` безопасен, но дальнейшая денормализация результата в объект без whitelist полей — mass assignment

## Cookies / sessions

- Custom session handler, сохраняющий объекты через `serialize()` и читающий через `unserialize()` — допустим, но если cookie защищена только подписью без шифрования и key скомпрометирован, возможен object injection
- `signed_cookie` / `encrypted_cookie` с weak keys (см. `crypto.md`)

## Webhook payloads

- Webhook deserialize без signature verification — атакующий отправляет любой payload (см. также `auth.md`)
- Идемпотентность: повторный deserialize same webhook → повторные side-effects
