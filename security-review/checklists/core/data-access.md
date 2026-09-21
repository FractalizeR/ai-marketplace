# Data access / SQL injection / Mass assignment (generic)

> Some items in this file are adapted from `cloudflare/security-audit-skill` (MIT License) — see [`THIRD_PARTY_NOTICES.md`](../../../THIRD_PARTY_NOTICES.md) for the license text and the full list of affected files.

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

## Import / restore as injection and validation bypass

Import and restore code paths reconstruct records from untrusted (uploaded, previously-exported, or third-party) data. Treat the imported payload with the same suspicion as any other user input — provenance ("this came from our own export feature") is not validation.

- Bulk import (CSV/JSON/XLSX upload → entity creation) maps columns directly onto entity setters without the field whitelist the normal create/update endpoint enforces — a `role` or `is_admin` column in the uploaded file mass-assigns a privileged field.
- Import overwrites an existing record by a natural key (email, slug, external ID) supplied in the file, without verifying the current user owns that record — an attacker-controlled import file silently takes over another tenant's row.
- Restore-from-backup re-inserts records into the schema's current validation rules being skipped, because the import path calls the repository/ORM `persist()` directly instead of going through the same validators as the interactive create endpoint.
- Import target collection differs from what the UI implies: the endpoint accepts a `collection_id` / `folder_id` field in the payload and writes into it without checking the current user has write access to that collection.
- Restore of a previously-exported archive is not re-authorized against the *current* permission model — data exported while the source record was public is restored into a state where it should now be private (or vice versa), and the restore path does not resolve the (potentially changed) permission before writing.
