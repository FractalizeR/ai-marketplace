# Data access / SQL injection / Mass assignment (generic)

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `dql_concat` — concatenation in ORM query language (DQL/HQL and similar)
- `native_sql_concat` — concatenation in native SQL / driver-level execution
- `mass_assignment` — unprotected setters / accepting arbitrary fields during denormalization

## Native SQL / Connection-level execution

- Driver-level execute like `$conn->executeQuery("SELECT ... WHERE id = " . $id)` without parameters
- Driver-level statement execution (`executeStatement`/equivalent) with concatenation
- Native query API (`createNativeQuery()` / equivalent) with manual SQL assembly
- PostgreSQL specifics:
  - `array_agg()`, `string_agg()` with user input without escape
  - `jsonb_set()`, `jsonb_insert()` with a controlled `path` argument
  - `COPY FROM STDIN` with user-controlled data
- Dynamic table/column names: if user input lands in SQL as an identifier (not a value), parameters do not help — a whitelist is required

## Mass assignment / unsafe setters (generic)

- `$entity->setX($request->...->get('x'))` without validation / whitelist of fields — any framework, any DTO mapper. A direct setter for privileged fields (`setRoles`, `setIsAdmin`, `setPaid(true)`) reachable via request body → privilege escalation.
