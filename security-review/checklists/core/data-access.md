# Data access / SQL injection / Mass assignment (generic)

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `dql_concat` — конкатенация в ORM-query language (DQL/HQL и подобные)
- `native_sql_concat` — конкатенация в native SQL / driver-level execution
- `mass_assignment` — незащищённые setters / приём произвольных полей в денормализацию

## Native SQL / Connection-level execution

- Driver-level execute типа `$conn->executeQuery("SELECT ... WHERE id = " . $id)` без параметров
- Driver-level statement execution (`executeStatement`/equivalent) с конкатенацией
- Native query API (`createNativeQuery()` / equivalent) с ручной склейкой SQL
- PostgreSQL-специфика:
  - `array_agg()`, `string_agg()` с user input без escape
  - `jsonb_set()`, `jsonb_insert()` с контролируемым `path` аргументом
  - `COPY FROM STDIN` с user-controlled данными
- Dynamic table/column names: если user input попадает в SQL как identifier (не значение) — параметры не помогут, нужен whitelist

## Mass assignment / небезопасные setters (generic)

- `$entity->setX($request->...->get('x'))` без валидации / whitelist полей — любой framework, любой DTO mapper. Прямой setter privileged-полей (`setRoles`, `setIsAdmin`, `setPaid(true)`) достижим через body request → privilege escalation.
