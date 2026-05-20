# Checklist convention

This file describes the format and rules for all `checklists/**/*.md` in the `fr-security-review` plugin.

## Two-level structure

```
checklists/
├── _meta.md
├── core/                       # always active (any project, any stack)
│   └── {theme}.md              # auth, crypto, disclosure, injection, data-access,
│                               # output-render, serialization, ssrf-fileops, fintech, frontend-js
└── frameworks/
    └── {stack}/                # active only if CONTEXT.md frontmatter contains this stack
        ├── _detect.md          # how detection fires (for documentation)
        └── {theme}.md          # the same theme, but framework-specific refinements
```

**Resolution rule (see `bin/plan_waves.py::resolve_checklists`):** for each wave theme, the worker always gets `core/{theme}.md`, and additionally `frameworks/{stack}/{theme}.md` — if the corresponding stack is detected for the project and the file exists. When no framework file is present (or `framework: none/unknown`), the worker uses only core.

**Priority on instruction conflict:** the framework file is **more specific**, its instructions take precedence over core. The worker loads both files at once and applies the refinement where one exists.

**Framework file anchor.** Each `frameworks/{stack}/{theme}.md` starts with a standard header (after the title):

> This checklist extends `core/{theme}.md` for projects on {stack}. On instruction conflict, this file takes precedence as the more specific one. The worker loads both files at once.

## Mandatory checklist header

Every checklist (both core and framework) includes a standard methodology block. **Do not change the wording** — workers recognize this block when loading:

> **These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

For framework files, the anchor (about precedence over core) goes **before** this header.

## `## Recommended sink_kinds` — only in core files

Each **core** checklist lists the values from the closed `sink_kind` enum that it covers. The worker picks `sink_kind` for each finding from this list (or `other:<name>` for categories that do not fit the enum).

**Framework files DO NOT declare their own `## Recommended sink_kinds` section** — they refine the applicability of `sink_kind` values declared in the corresponding `core/{theme}.md`. This rule is fixed: a framework checklist **does not introduce new `sink_kind` values**, but narrows/refines applicability of the core sink_kind. All worker findings are always classified by `sink_kind` from the core enum.

`sink_kind` enum values:
`dql_concat`, `native_sql_concat`, `unsafe_html_render`, `template_raw`, `ssti`, `unserialize_untrusted`, `command_exec`, `file_include_dynamic`, `path_traversal`, `redirect_open`, `weak_hash`, `hardcoded_secret`, `cors_misconfig`, `missing_authz`, `idor_lookup`, `xxe`, `ssrf`, `mass_assignment`, `csrf_missing`, `decimal_arith`, `race_condition`, `webhook_unverified`, `pii_in_logs`, `stacktrace_exposed`, `type_juggling`, `oauth_state_missing`, `webhook_replay`, `weak_random`, `secret_in_response`, `sensitive_field_unmasked`.

### Note on `dql_concat` (overloaded name)

`dql_concat` is historically named after Doctrine DQL but is used as a **general category for any ORM query string concatenation**: Doctrine DQL (Symfony), Eloquent query builder with `whereRaw`/`orderByRaw` (Laravel), SQLAlchemy raw text expressions (Python), any other native ORM raw-query concatenations. An alternative name `orm_query_concat` was considered, but renaming would break the dedupe parser and fingerprint keys without meaningful gain. The name is fixed — the semantic extension is documented here.

For native SQL concatenations (without an ORM wrapper, via PDO/mysqli/pg_*/cursor.execute) use `native_sql_concat`.

### Closed enum `root_cause_family`

`injection`, `xss`, `authz`, `disclosure`, `crypto`, `deserialization`, `ssrf`, `webhook`, `business_logic`. All names are **generic** (stack-neutral); no `doctrine`/`twig`/`voter`/`eloquent` in the semantics. A custom name via `other:<name>` (excluded from auto-dedupe).

### Mapping `sink_kind` → `root_cause_family`

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

## Item format

Checklist items are a bulleted list focused on code or configuration patterns. Not general advice ("use HTTPS"), but concrete vulnerability signs in code.

Examples:

- ✅ `preg_replace()` with the `/e` modifier — RCE via dynamic evaluation
- ❌ "Follow security best practices"

## Optional `## Confidence floor rules` section

If for a category there are unambiguous patterns where confidence **must not** vary between workers, fix them in a dedicated checklist section. This removes the lottery "one worker is bolder, another more cautious" and yields predictable recall.

Format: a list of items of the form "if the code satisfies condition X → confidence ≥ Y".

Example:
```markdown
## Confidence floor rules

- Committed `.env` in git with `APP_SECRET`/`*_KEY`/`*_TOKEN` → confidence ≥ 8. Checking the prod override is the reviewer's responsibility, not a bar for reporting.
- MD5/SHA1 for password hashing → confidence ≥ 9 (no exceptions).
```

Floor rules **do not replace** the quality gate (confidence ≥ 8, severity ≥ MEDIUM) — they refine it for specific patterns.

Floor rules may live in both core and framework — wherever they are most specific. If a pattern is mentioned in both, the framework version (more specific) takes precedence.

## Confidence floor — where it lives

| Pattern type | Where |
| --- | --- |
| Generic (no framework signatures): `==` for secrets, MD5 for password, `unserialize($_GET[...])` | `core/{theme}.md` |
| Framework-specific (`#[IsGranted]`, `security.yaml`, `Voter`, `#[Route]`, EasyAdmin/Sonata) | `frameworks/{stack}/{theme}.md` |

## Cross-theme duplication (admin-CRUD)

The checklists `frameworks/symfony/auth.md` AND `frameworks/symfony/data-access.md` both contain a section on admin-bundle CRUD (EasyAdmin/Sonata) — intentionally. A worker running in W1 (auth) and W2 (injection/data-access) gets admin context both times. This is the only sanctioned case of duplication between files of the same stack (handled in dedupe via `flag=[CROSS_SINK_MERGE]` for findings on the same line).

## Cross-theme duplication (GraphQL)

A section on GraphQL is present in three themes of one stack:

- `frameworks/{stack}/auth.md` — field-level authz (resolver without `@guard`/`#[IsGranted]`/`@can`/voter check, introspection in prod as information disclosure).
- `frameworks/{stack}/data-access.md` — query depth/complexity DoS, alias batching, persisted-queries bypass, introspection as enumeration vector.
- `frameworks/{stack}/output-render.md` — output filtering (resolver returns an Entity without `#[Groups]`/`$hidden`/Resource projection).

Distribution across themes reflects different attack classes; from a single location (for example, schema YAML or a single resolver) usually only one category is exploited. Dedupe already knows: if two findings land on the same `(sink_file, sink_line)` but with a different `sink_kind`, one gets `[CROSS_SINK_MERGE]`, the rest become `alternative_sink_kinds`.

## Sink_kind disambiguation (3.4.0)

The new `sink_kind` values in 3.4.0 are close in meaning to existing ones — for the worker, boundaries are fixed so there is no classification "lottery":

| Case | sink_kind | Do not confuse with |
| --- | --- | --- |
| OAuth/OIDC callback without `state`/PKCE | `oauth_state_missing` | `csrf_missing` (general CSRF on a mutating form) |
| Webhook **with** HMAC, but without nonce/timestamp/idempotency | `webhook_replay` | `webhook_unverified` (no HMAC at all) |
| Direct call of `mt_rand`/`rand`/`uniqid`/`microtime` for a security-sensitive value | `weak_random` | `hardcoded_secret` (literal in code) |
| Token/secret leak in HTTP response body (JSON / template render) | `secret_in_response` | `pii_in_logs` (leak to log/file/backup) |
| Admin UI displays a raw token field without masking | `sensitive_field_unmasked` | `secret_in_response` (response body), `pii_in_logs` (logs) |

`Str::random()`, `random_bytes()`, `random_int()`, `Symfony\Component\String\ByteString::fromRandom()` are **NOT** `weak_random`: internally they rely on a CSPRNG.

## Core file structure

```markdown
# <Category name>

<mandatory header — copy verbatim>

## Recommended sink_kinds

- `<sink_kind1>` — comment
- `<sink_kind2>` — comment

## Confidence floor rules
(optional)

- ...

## <Subcategory A>

- item
- item
```

## Framework file structure

```markdown
# <Category name> ({stack})

<anchor on precedence over core — copy verbatim from this _meta>

<mandatory methodology header — copy verbatim>

## Confidence floor rules
(optional, framework-specific)

- ...

## <Subcategory A>

- item
- item
```
