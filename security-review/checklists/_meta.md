# Checklist convention

This file describes the format and rules for all `checklists/**/*.md` in the `fr-security-review` plugin.

## Five-layer structure

```
checklists/
├── _meta.md
├── core/                              # always active (any project, any stack)
│   └── {theme}.md                     # auth, crypto, disclosure, injection, data-access,
│                                      # output-render, serialization, ssrf-fileops, fintech, frontend-js
├── languages/                         # generic language layer (PHP/Python/Node)
│   └── {language}/{theme}.md          # active iff CONTEXT.md frontmatter has `stack.language: <language>`
├── stacks/                            # framework layer (symfony, laravel, django, …)
│   └── {stack}/                       # active iff `stack.framework == <stack>` and stack ∉ {none, unknown}
│       ├── _detect.md                 # how detection fires (documentation)
│       ├── {theme}.md                 # framework-specific refinement of the theme
│       └── addons/                    # sub-framework / bundle layer (EasyAdmin, API Platform, …)
│           └── {addon}/{theme}.md     # active iff `<addon>` is in `stack.addons`
└── integrations/                      # vendor SDK / service integrations (auth0, stripe, …)
    └── {integration}/{theme}.md       # active iff `<integration>` is in `stack.integrations`
                                       # — independent of stack/language
```

**Resolution rule (see `bin/plan_waves.py::resolve_checklists`):** for each wave theme, the worker assembles a chain of up to five layers, from least specific to most specific:

1. `core/{theme}.md` — always loaded if present.
2. `languages/{language}/{theme}.md` — loaded if `ctx.language` is set (skip the whole layer otherwise).
3. `stacks/{stack}/{theme}.md` — loaded if `ctx.stack ∉ {none, unknown}` (skip the stack and addons layers otherwise).
4. `stacks/{stack}/addons/{addon}/{theme}.md` for each addon in `ctx.addons` (alphabetical, deterministic order).
5. `integrations/{integration}/{theme}.md` for each integration in `ctx.integrations` (alphabetical, deterministic order). Integrations are **independent of stack** — they apply even on a generic / unknown stack.

Missing files at any layer are silently skipped — every non-core layer is opt-in.

**Priority on instruction conflict:** the more specific layer wins. Precedence (high → low): `integrations > addons > stacks > languages > core`. The worker loads the whole chain at once and applies the most-specific refinement where one exists.

**Non-core file anchor.** Each non-core checklist (languages, stacks, addons, integrations) starts with a standard header (after the title):

> This checklist extends `core/{theme}.md` and follows the resolution chain (core → languages → stacks → addons → integrations). On instruction conflict, the more specific layer takes precedence. The worker loads the whole chain at once.

**Exception — integrations are stack-agnostic.** Files under `integrations/{integration}/` use a simplified anchor referencing only `core/{theme}.md` (the integration may activate on any stack, including `none`/`unknown`):

> This checklist extends `core/{theme}.md` for projects that use {integration purpose}. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

## Layer conventions

- **core/** — language-agnostic, stack-agnostic patterns. Generic vulnerability categories (SQL injection, XSS, weak crypto, missing authz) described in terms that apply to any code base. The closed `sink_kind` enum lives here.
- **languages/{language}/** — language-generic refinements that are not tied to any framework: PHP `preg_replace('/e')`, Python `pickle.loads`, Node `child_process.exec`, etc. Activated by `stack.language`.
- **stacks/{stack}/** — framework-level refinements: Symfony Voters / `#[IsGranted]`, Laravel Policies / `Auth::user()`, Django middleware, FastAPI dependencies. Activated by `stack.framework`.
- **stacks/{stack}/addons/{addon}/** — sub-frameworks or bundles that ride on top of a stack: EasyAdmin, Sonata, API Platform, Filament, Nova, Lighthouse. Activated by an entry in `stack.addons`.
- **integrations/{integration}/** — vendor SDK / service integrations: Auth0, AWS Cognito, Stripe, Okta, KeyCloak. Activated by an entry in `stack.integrations`. Independent of the stack — a generic-PHP project using Stripe still loads `integrations/stripe/`.

## Reserved (not yet populated)

The following layer slots are reserved for future content. Files do not exist yet, so resolution silently skips them; orchestrator may pre-create the directories to make intent visible.

- `languages/php/`, `languages/python/`
- `stacks/django/`, `stacks/fastapi/`
- `integrations/auth0/`, `integrations/aws-cognito/`

## Mandatory checklist header

Every checklist (core and every non-core layer) includes a standard methodology block. **Do not change the wording** — workers recognize this block when loading:

> **These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

For non-core files, the precedence anchor (about the resolution chain) goes **before** this header.

## `## Recommended sink_kinds` — only in core files

Each **core** checklist lists the values from the closed `sink_kind` enum that it covers. The worker picks `sink_kind` for each finding from this list (or `other:<name>` for categories that do not fit the enum).

**Non-core files (languages, stacks, addons, integrations) DO NOT declare their own `## Recommended sink_kinds` section** — they refine the applicability of `sink_kind` values declared in the corresponding `core/{theme}.md`. This rule is fixed: a non-core checklist **does not introduce new `sink_kind` values**, but narrows/refines applicability of the core sink_kind. All worker findings are always classified by `sink_kind` from the core enum.

`sink_kind` enum values:
`dql_concat`, `native_sql_concat`, `unsafe_html_render`, `template_raw`, `ssti`, `unserialize_untrusted`, `command_exec`, `file_include_dynamic`, `path_traversal`, `ldap_injection`, `xpath_injection`, `nosql_injection`, `redirect_open`, `weak_hash`, `hardcoded_secret`, `cors_misconfig`, `missing_authz`, `idor_lookup`, `xxe`, `ssrf`, `mass_assignment`, `csrf_missing`, `decimal_arith`, `race_condition`, `webhook_unverified`, `pii_in_logs`, `stacktrace_exposed`, `type_juggling`, `oauth_state_missing`, `webhook_replay`, `weak_random`, `secret_in_response`, `sensitive_field_unmasked`, `csp_missing`, `csp_unsafe_inline`, `clickjacking_unprotected`, `hsts_missing`, `mime_sniff_unprotected`, `jwks_spoof`, `oidc_misconfig`, `tls_validation_bypass`.

### Note on `dql_concat` (overloaded name)

`dql_concat` is historically named after Doctrine DQL but is used as a **general category for any ORM query string concatenation**: Doctrine DQL (Symfony), Eloquent query builder with `whereRaw`/`orderByRaw` (Laravel), SQLAlchemy raw text expressions (Python), any other native ORM raw-query concatenations. An alternative name `orm_query_concat` was considered, but renaming would break the dedupe parser and fingerprint keys without meaningful gain. The name is fixed — the semantic extension is documented here.

For native SQL concatenations (without an ORM wrapper, via PDO/mysqli/pg_*/cursor.execute) use `native_sql_concat`.

### Closed enum `root_cause_family`

`injection`, `xss`, `authz`, `disclosure`, `crypto`, `deserialization`, `ssrf`, `webhook`, `business_logic`, `clickjacking`. All names are **generic** (stack-neutral); no `doctrine`/`twig`/`voter`/`eloquent` in the semantics. A custom name via `other:<name>` (excluded from auto-dedupe).

### Mapping `sink_kind` → `root_cause_family`

| sink_kind | root_cause_family |
| --- | --- |
| `dql_concat`, `native_sql_concat` | `injection` |
| `unsafe_html_render`, `template_raw`, `ssti` | `xss` |
| `unserialize_untrusted` | `deserialization` |
| `command_exec`, `file_include_dynamic`, `path_traversal` | `injection` |
| `ldap_injection`, `xpath_injection`, `nosql_injection` | `injection` |
| `redirect_open` | `business_logic` |
| `weak_hash`, `hardcoded_secret` | `crypto` |
| `cors_misconfig` | `authz` |
| `missing_authz`, `idor_lookup`, `mass_assignment` | `authz` |
| `xxe`, `ssrf` | `ssrf` |
| `csrf_missing` | `authz` |
| `decimal_arith`, `race_condition`, `type_juggling` | `business_logic` |
| `webhook_unverified`, `webhook_replay` | `webhook` |
| `pii_in_logs`, `stacktrace_exposed`, `secret_in_response`, `sensitive_field_unmasked` | `disclosure` |
| `oauth_state_missing`, `oidc_misconfig` | `authz` |
| `weak_random`, `jwks_spoof`, `tls_validation_bypass` | `crypto` |
| `csp_missing`, `csp_unsafe_inline`, `mime_sniff_unprotected` | `xss` |
| `clickjacking_unprotected` | `clickjacking` |
| `hsts_missing` | `crypto` |

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

Floor rules may live in any layer — wherever they are most specific. If a pattern is mentioned in multiple layers, the more specific layer (per resolution chain) takes precedence.

## Optional `## Trusted patterns (do NOT flag)` section

If for a category there are common idioms that **look** risky but are safe by construction (auto-escape, CSPRNG wrappers, ORM parameter binding for scalar args), enumerate them under a dedicated `## Trusted patterns (do NOT flag)` section. The worker uses this section as a negative filter — patterns listed here are NOT vulnerabilities and should be skipped during search.

Use **sparingly** — only for patterns that workers consistently mis-classify as bugs. Each entry must be a concrete code pattern, not an abstract guideline.

Format: bullet list. Each item names the API/idiom, explains *why* it is safe by construction, and (when needed) calls out the narrower pattern that **does** still constitute a finding.

Example:
```markdown
## Trusted patterns (do NOT flag)

- `random_bytes()`, `random_int()` — CSPRNG, secure by construction. Not `weak_random`.
- Twig default auto-escape — `{{ var }}` in `.html.twig` is HTML-safe; flag only `|raw` or explicit `{% autoescape false %}` blocks.
```

Precedent: this convention is adapted from Anthropic's `claude-code-security-review` "PRECEDENTS" block, mapped onto our enum-driven model. Layer precedence follows the same chain as `## Confidence floor rules` — more specific layers can extend or override the trusted list.

## Confidence floor — where it lives

| Pattern type | Where |
| --- | --- |
| Generic (no framework signatures): `==` for secrets, MD5 for password, `unserialize($_GET[...])` | `core/{theme}.md` |
| Framework-specific (`#[IsGranted]`, `security.yaml`, `Voter`, `#[Route]`) | `stacks/{stack}/{theme}.md` |
| Bundle/addon-specific (EasyAdmin/Sonata/API Platform) | `stacks/{stack}/addons/{addon}/{theme}.md` |
| Capability-integration-specific (JWT, OAuth/OIDC — any vendor) | `integrations/{capability}/{theme}.md` |
| Vendor-SDK-specific (Stripe/Auth0/Cognito) | `integrations/{integration}/{theme}.md` |

## Cross-theme duplication (admin-CRUD)

Within `stacks/symfony/addons/{easyadmin,sonata}/`, both `auth.md` and `data-access.md` contain admin-CRUD sections — this is the sanctioned cross-theme duplication for admin-surface findings. A worker running in W1 (auth) and W2 (injection/data-access) gets admin context both times. The dedupe parser handles `[CROSS_SINK_MERGE]` on these collisions (findings on the same line with different `sink_kind`).

## Cross-theme duplication (GraphQL)

A section on GraphQL is present in three themes of one stack:

- `stacks/{stack}/auth.md` — field-level authz (resolver without `@guard`/`#[IsGranted]`/`@can`/voter check, introspection in prod as information disclosure).
- `stacks/{stack}/data-access.md` — query depth/complexity DoS, alias batching, persisted-queries bypass, introspection as enumeration vector.
- `stacks/{stack}/output-render.md` — output filtering (resolver returns an Entity without `#[Groups]`/`$hidden`/Resource projection).

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
| `X-Content-Type-Options: nosniff` missing on file-download / user-upload endpoint | `mime_sniff_unprotected` | `secret_in_response` (response leaks a secret) / `stacktrace_exposed` (response leaks debug info). Canonical exploit: stored XSS via SVG/HTML masquerade — hence family `xss`. JSON-as-HTML sniffing for XS-Search is a secondary path. |
| OAuth/OIDC `redirect_uri` matched by prefix/regex; missing `aud`/`iss` validation; attacker-controlled issuer URL | `oidc_misconfig` | `missing_authz` (no authz check in application code), `oauth_state_missing` (callback CSRF — distinct row) |
| N1QL / Couchbase string-concatenation in queries | `nosql_injection` | `native_sql_concat` (reserved for actual SQL drivers / PDO / mysqli / pg_* / cursor.execute) |
| LDAP filter built inside a Doctrine/ORM repository helper | `ldap_injection` | `dql_concat` (concatenation in DQL/ORM-query string proper) |
| XPath expression evaluated inside a Twig/template rendering helper | `xpath_injection` | `template_raw` (sink is the template renderer, not the XPath evaluator) |

See `core/auth.md` → Trusted patterns for the canonical CSPRNG list.

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

## Trusted patterns (do NOT flag)
(optional, layer-specific)

- ...

## <Subcategory A>

- item
- item
```

## Non-core file structure (languages / stacks / addons / integrations)

```markdown
# <Category name> ({layer-specific scope, e.g. {stack} / {addon} / {integration}})

<anchor on precedence and the resolution chain — copy verbatim from this _meta>

<mandatory methodology header — copy verbatim>

## Confidence floor rules
(optional, layer-specific)

- ...

## Trusted patterns (do NOT flag)
(optional, layer-specific)

- ...

## <Subcategory A>

- item
- item
```
