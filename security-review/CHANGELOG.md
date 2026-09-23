# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.4.1] — 2026-09-23

### A finding's checklist path no longer carries the auditing machine's install prefix

### Fixed

- **`findings.json`'s `discovered_via`, finding bodies in `REPORT/<root_cause_family>.md`, standalone `## Needs validation` / `## Hardening notes` entries in `REPORT.md`, and `REPORT.md`'s `## Checklist coverage` no longer leak the plugin install path.** A checklist path is only meaningful from its `checklists/` anchor onward, but all four places carried it as the worker or the wave plan wrote it — including the absolute prefix of wherever the plugin happened to be installed. This showed up whenever the wave plan consulted for `## Checklist coverage` was built by a different install than the one rendering the report: the absolute path didn't match either install's root, so it was left untouched. The same normalization now also fixes the per-checklist finding counts in that section, which silently read zero for every checklist under the same mismatch.

## [4.4.0] — 2026-09-23

### Recon survives the configs it did not model; bucket records find their finding

Six defects surfaced by a live control run, none of them introduced by the verdict-bucket work they were found alongside. Four of them ended an audit or silently narrowed what a worker was told; two made a report say something that was not true.

### Changed

- **A verdict-bucket record binds to a confirmed finding by sink, not by quoted text.** `needs_validation` / `hardening` records were bound only when their `sink_hash` matched, and `sink_hash` is computed from the worker's `sink_snippet` — so two workers quoting one sink slightly differently produced a finding plus a separate bucket row for the same place. Binding now falls back to `dedupe()`'s own merge keys, so a record binds exactly when `dedupe()` would have merged it had it been `confirmed`; a record bound that way carries `[ATTACHED_WITHOUT_HASH]` and REPORT.md says the binding was by location rather than by text. `findings.json` keeps its shape and `schema_version` — `matched_to` is now best-effort and the flag carries the stricter reading.

### Fixed

- **`access_control` parsing no longer aborts the whole audit.** The flow-mapping splitter in `bin/recon/recipes/symfony.py` counted brackets but not quotes, so a quoted CIDR list (`ips: '127.0.0.0/8,::1,10.0.0.0/8'`) was cut into fragments and `::1` became an empty key — which `bin/recon/yaml_emit.py` rejects, failing recon and with it the run. Quote handling is now shared by every layer that scans this text: comma splitting, brace nesting in a multi-line `- { … }` rule (a quoted `}` used to end the rule early and drop it), and escaped quotes inside double-quoted scalars.
- **One unmodelled YAML construct no longer costs the whole recon.** Rules parsed out of `security.yaml` are filtered against the CONTEXT.md emitter's key contract before they reach it, so a merge key (`<<: *common`) or any other construct the line parser does not model costs that key and a warning instead of the entire inventory.
- **YAML anchors and aliases in `access_control`.** A leading `&name` is stripped from the value instead of being carried into CONTEXT.md, and a whole-value `*name` alias resolves to its anchor's scalar. Resolution is positional — only anchors defined above the alias are eligible — so a name redefined later in the file cannot widen an address range a worker reads. Anchors on mapping / sequence / block-scalar nodes are not collected, and an unresolved alias stays literal rather than becoming a wrong value.
- **`.claude/` is excluded from the extractor walk.** A coding agent's git worktree parked under `.claude/worktrees/` was read as a second copy of the project tree, doubling every inventory counter and tripping the recon sanity gate. The Python and PHP copies of `DEFAULT_EXCLUDE` are now checked against each other by a test rather than by a comment.
- **`## Diff vs previous run` no longer diffs a run against itself.** The dedupe pass that follows adversarial refute (and any other re-render over the same wave files) reported every finding as recurring, because it compared against the snapshot the run's own first pass had just written. A run is now identified by its wave files, and a pass over the same ones inherits the baseline of the first instead of rotating it. `.findings_state.json` gains `baseline` and `run_id` as additive keys — the schema version deliberately does not move, so a rollback to an earlier build still reads the file and keeps the accumulated `resolutions` journal.
- **`console_gap_reason` distinguishes an operator's choice from an unresolved runner.** The Codex orchestrator templates passed `--no-console` when a containerized project supplied no `--console-cmd`, so the recorded reason read as `console_disabled_by_flag` although no flag had been passed; they now pass no flag, as the OpenCode templates already did, and the utility records `env_runner_unknown: containerized project …`. REPORT.md additionally spells the flag reason out in prose.

## [4.3.0] — 2026-09-21

### Verdict buckets, `findings.json`, cross-run memory

Workers no longer report only exploitable vulnerabilities. Each wave file now carries three verdicts — `confirmed` (the existing severity/confidence-gated finding), `needs_validation` (a traced path blocked on a fact outside the repo, e.g. "is this endpoint actually internet-facing"), and `hardening` (a traced observation with no affected principal or resource). Neither bucket carries severity or confidence; recall-first philosophy is unchanged. A `<!-- wave_format: 2 -->` marker as the first non-empty line of a wave file signals the new format; older wave files without it still parse under the legacy rules.

#### Added

- **`needs_validation` / `hardening` verdicts** in the worker contract (`agents/security.md`) and the wave-file parser (`bin/dedupe/parser.py`). Bucket records that share a `sink_hash` with a `confirmed` finding render as an annotation on it; unmatched records render in their own `## Needs validation` / `## Hardening notes` sections, index-`REPORT.md`-only.
- **`<review_root>/findings.json`** — a `schema_version`-gated public inter-plugin contract (`bin/dedupe/export.py`) listing every constituent finding across all three verdicts, including findings absorbed into a `MergedFinding.merged_from` group. No field varies run-to-run for unchanged inputs.
- **Cross-run verdict memory.** `<review_root>/.findings_state.json` moves to schema 2: alongside the existing New/Recurring/Closed snapshot, it now persists a `sink_hash → Resolution` map (adversarial-refute and `--verdicts-in` verdicts) as a read-modify-write merge, so a previously rejected finding is annotated "Previously rejected" instead of re-litigated on every run (a `reaffirmed` resolution cancels a prior rejection for the same `sink_hash` and renders nothing). The mark is invalidated by re-hashing the cited evidence location's normalized content, not its path — if the referenced protection code changes, the mark silently drops.
- **`dedupe_findings.py --verdicts-in=<path>`** — folds externally-produced verdicts (e.g. from a ticket-triage plugin) into remembered resolutions. Fail-closed: validated by content hash against the review root's pre-existing `findings.json`; any schema violation, unknown field, unknown `sink_hash`, duplicate, or stale hash aborts the whole run before any output is written. Requires cross-run state (incompatible with `--no-state`).
- Adversarial refute only ever considers `confirmed` findings — `needs_validation` and `hardening` are excluded from the refute slice the orchestrators build, since refute looks for blocking code in the repo and `needs_validation` is, by definition, blocked on a fact outside it.

#### Fixed

- **`bin/dedupe/parser.py` snippet truncation on `# TODO`.** `_extract_snippet_block` stopped a block scalar early on any line matching `^#+\s`, so a `sink_snippet` containing a `# TODO` PHP comment at column 0 was silently truncated — and `sink_hash`, computed from the truncated snippet, diverged from the same finding reported without the comment. Fixed; regression-tested.

## [4.2.0] — 2026-07-03

### Multi-environment support

The same audit engine now runs on **Codex CLI** and **OpenCode** in addition to Claude Code. The Claude behaviour is byte-for-byte unchanged; the secondary harnesses are **derived** from the Claude-authoritative command/agent prose by a build, so there is a single source of truth and no parallel implementation to drift. See [`harness/codex/INSTALL.md`](../harness/codex/INSTALL.md) and [`harness/opencode/INSTALL.md`](../harness/opencode/INSTALL.md) for install and model-setup on each harness.

On Claude, fan-out stays native `Task(model=…)` in batches of ≤6. On Codex/OpenCode the same waves fan out as external `codex exec -m <model>` / `opencode run -m <model>` processes (one per slice, ≤6 concurrent), because neither harness supports reliable in-process subagents. The worker→file contract (`<review_root>/waves/<slice_id>.md`) and the recon/plan/dedupe Python are identical everywhere.

#### Added

- **`bin/shared/` runtime helpers** (stdlib-only, ships with the plugin; Claude does not use them — they are the foundation the Codex/OpenCode derivations invoke as staged stage-commands).
  - **`model_resolver.py`** — model resolution as `discover → propose → confirm → persist` a `{high, fast}` tier map. Discovery is harness-shape-sniffed (`codex debug models` JSON vs `opencode models` lines); proposal ranks by capability signals (fast-first); the chosen map persists to `<review_root>/.model_map.json` and is reused on re-run unless `--remodel`. Non-interactive by default; `--models=high=<id>,fast=<id>` bypass; an unresolved tier fails loudly instead of silently picking. The Claude path returns the static `{high: opus, fast: sonnet}` and never persists.
  - **`dispatch.py`** — bounded external-process wave dispatcher (≤6 concurrent) plus a single-process `dispatch_role` for recon/refute. Planned wave files are deleted before fan-out, so a stale prior-run file plus a crashed worker is still counted as a gap (`timeout` / `crash` / `missing_write` distinguished). `--allow-gaps` writes `dispatch_gaps.json` and marks the run degraded instead of aborting the whole fan-out on one failed worker.
  - **`contracts.py`** — typed seams (`Roots`, `RunResult`, the runner/builder callables, typed exceptions). Subprocess is the single injected seam, so tests never spawn a real `codex` / `opencode`.
- **`dedupe_findings.py --dispatch-gaps=<path>`** — folds wave-dispatch gaps into REPORT.md's `## Coverage Gaps` (alongside the existing `console_gap`) and surfaces a prominent **INCOMPLETE** marker. With recorded gaps but zero wave files it renders a minimal INCOMPLETE report instead of erroring out.

#### Changed

- **`agents/security-recon.md` input contract** documents the harness-neutral `key=value` → `recon_inventory.py` flag mapping (e.g. `console_mode=off` → `--no-console`). The Codex/OpenCode recon dispatch passes flag-free `key=value` inputs to avoid a leading-`--` collision with the worker CLI's own option parsing; the agent is now the single documented source of that mapping.

#### Fixed

- **`bin/shared/dispatch.py` feeds workers EOF stdin** (`stdin=DEVNULL`). `codex exec` reads additional prompt input from stdin, so a fanned-out worker that inherited a non-EOF orchestrator stdin would block forever. Harness-neutral (a non-interactive worker must never read stdin); OpenCode is unaffected.

## [4.1.0] — 2026-05-23

### Environment-aware console enrichment

Recon no longer blindly runs `bin/console` on the host. It probes the project's execution environment first and, when the project runs inside a container (where host execution distorts the environment), asks the user how to run the console instead of silently degrading.

#### Added

- **`--console-cmd=<template>`** flag on `/security-project` and `/security-changes` (and `recon_inventory.py`). An explicit command for running the project console, e.g. `--console-cmd="docker compose exec -T php php bin/console"`. Supports a `{args}` placeholder for Makefile-style passthrough (`make console CMD={args}`); otherwise the subcommand is appended.
- **`bin/recon/environment.py`** — a standalone, stdlib-only environment probe (`--probe`). Detects containerization signals (`docker-compose.y*ml`, `Dockerfile`, `.ddev`, `.lando.yml`, `laravel/sail`, `.devcontainer`), host PHP presence/version, the PHP service in a compose file, and Makefile console targets (with their recipe body, for transparency). Emits ready-to-confirm runner suggestions. Never executes project code.
- **`environment` frontmatter block in CONTEXT.md** — records `containerized`, `container_signals`, `host_php_present`, `host_php_version`, `console_mode` (`host|container|custom|disabled`), `console_gap`, and `console_gap_reason`. Optional and backward-compatible (pre-4.x contexts still validate).
- **`## Coverage Gaps` section in REPORT.md** — when console enrichment did not run (containerized + no `--console-cmd`, or `--no-console`), `dedupe_findings.py` surfaces the gap at the top of the report so the reduced coverage is visible, not buried in the inventory.
- **Orchestrator "resolve console runner" step** (project step 3b / changes step 4c) — probes the environment and, when ambiguous, asks via `AskUserQuestion` with a **show + confirm** trust model: the container command is built deterministically in Python and shown verbatim; Makefile targets are shown with their recipe body; nothing repo-derived is auto-executed without the user's choice.
- **`CONSOLE_ENTRYPOINT` recipe contract attribute** — `["php","bin/console"]` for Symfony, `None` for Laravel/generic (console N/A; no coverage gap reported).

#### Changed

- **`sandbox.ConsoleRunner` abstraction.** `try_console_smoke` / `run_console_command` now take a `ConsoleRunner` (host / container / custom / disabled) instead of hard-coding `["php", bin/console]` on the host, and pick higher timeouts for container/custom modes. Console execution is now stack- and location-agnostic.
- **Containerization is the dominant gate.** A containerized project's console is never run on the host automatically — recon resolves a runner (interactively or via `--console-cmd`) or records a loud `console_gap` (ceiling=medium). In non-interactive/CI runs nothing blocks: the gap is recorded and surfaced.

### Composite repository support

Adds first-class support for monorepos where `composer.json` / framework configs live in a subdirectory below `cwd` and CLAUDE.md is shared at the monorepo root.

### Added

- **`--project-root=<path>`** flag on `/security-project` and `/security-changes`. Defaults to `cwd`. When set, all paths in recon, worker file resolution, CLAUDE.md exclusions, sanity coverage, refute normalization, and git operations resolve against this value. Required for composite repos (monorepo + PHP subproject).
- **Dual CLAUDE.md read.** Exclusions are merged from both `<cwd>/CLAUDE.md` and `<PROJECT_ROOT>/CLAUDE.md` when these differ. All paths in either file are interpreted as `PROJECT_ROOT`-relative; entries that don't resolve under `PROJECT_ROOT` are skipped with a user warning.
- **Worker `project_root` parameter.** `Task(security, ...)` now passes `project_root: <PROJECT_ROOT>` so workers prepend it when calling `Read` / `Grep` / `Glob` / `mcp__phpstorm__*` on project files. Without this, workers silently miss files in composite repos. Output paths in findings (`sink_file:sink_line`) remain `PROJECT_ROOT`-relative for dedup parser compatibility.

### Changed

- **`--review-root` is now strictly an output-directory flag.** Step 0.3 in both orchestrators rejects values that look like a source tree (basename in a blacklist of `src`, `app`, `lib`, `vendor`, `node_modules`, `public`, `templates`, `views`, `database`, `migrations`, `seeders`, `scripts`, `routes`, `build`, `dist`, `target`, `out`, `coverage`, `.next`, `.nuxt`, `__pycache__`, etc.), and values that equal or are a non-`security-review-`-prefixed subpath of `<PROJECT_ROOT>`. Past incident: `--review-root=src` clobbered the user's `src/.gitignore` with `*`. The guard also pre-checks that the resolved path is not an existing non-directory.
- **Absolute-path invariant.** After Step 0, all references to `<REVIEW_ROOT>` and `<PROJECT_ROOT>` in subsequent bash, `Task(...)`, and helper utility calls MUST use the resolved absolute paths. Past incident: `validate_context.py` received an absolute path while a later `ls` received a relative one, producing `ls: src/CONTEXT.md: No such file or directory` on a file that actually existed.
- **`validate_context.py --sanity` now receives `--project-root`** from the orchestrator. Removes the `WARNING: project_root not specified and could not be inferred — sanity coverage skipped` that fired on composite repos (where `parent(review_root)` had no `composer.json` / `package.json`).
- **`/security-changes` git operations** all use `git -C "<PROJECT_ROOT>"`. Without this, in a monorepo with `cwd != PROJECT_ROOT`, `git diff` would return paths relative to the monorepo root, which recon then could not match against `<PROJECT_ROOT>`-relative file globs (`touched_by_diff` would never set, the mode=changes contract would break silently). `Bash(git -C *)` added to `allowed-tools`. Step 0.2 verifies `PROJECT_ROOT` is a git repo before continuing.
- **Legacy v1 (`SECURITY_CONTEXT.md`) detection** probes both `<cwd>` and `<PROJECT_ROOT>`. Previous form only probed `cwd` and would silently miss legacy files in composite repos.

## [4.0.0] — 2026-05-21

### Five-layer checklist resolver and integrations layer

Major architectural release. The checklist resolver moves from a flat two-level scheme (`core/` + `frameworks/`) to a five-layer chain that scales to multiple languages, sub-framework addons, and vendor / capability integrations. First content lands in the new `addons/` and `integrations/` layers.

### Added

- **Resolution chain.** Five layers, less specific to more specific: `core/` → `languages/{lang}/` → `stacks/{stack}/` → `stacks/{stack}/addons/{addon}/` → `integrations/{integration}/`. Precedence on conflict: integration > addon > stack > language > core. Integrations apply even when stack is `none` / `unknown`. New `ResolutionContext` dataclass with normalized addons/integrations.
- **Symfony addons.**
  - `stacks/symfony/addons/easyadmin/` and `.../sonata/` extracted from inline stack-checklist sections into dedicated addon files. Recipe-driven recall via `recon_bags.addon.easyadmin.crud_controllers` and `recon_bags.addon.sonata.admin_classes`.
  - `stacks/symfony/addons/api-platform/` — REST and GraphQL coverage: `_detect.md`, `auth.md`, `data-access.md`, `output-render.md`, `disclosure.md`. New `recon_bags.addon.api-platform.resources` schema slot (PHP sandbox extractor deferred; placeholder bag).
- **Integrations layer (12 directories total).**
  - Generic capabilities: `jwt-generic`, `oauth-oidc`.
  - Identity providers: `auth0`, `aws-cognito`, `okta`, `keycloak`, `firebase-auth`. Provider detection auto-includes generic JWT and OAuth/OIDC layers via `PROVIDER_IMPLIES_INTEGRATIONS`.
  - Vendor / capability integrations: `stripe` (fintech), `aws-secrets-manager` (crypto), `vault` (crypto), `saml` (auth), `webauthn-passkeys` (auth).
- **New core theme `security-headers.md`** covering CSP, frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, COOP/COEP/CORP. Added as third theme of W3.
- **`## Trusted patterns (do NOT flag)`** convention (Anthropic `claude-code-security-review` precedent) — negative filter for safe-by-construction idioms. Seeded in `core/{auth, output-render, injection}.md` (CSPRNG primitives, default-escape templating, parameterized ORM queries).
- **Confidence caps** — new upper-bound rules complementing existing floors. `redirect_open` and `ssrf` capped at confidence 5 when only the URL path is attacker-controlled (host/scheme/port hardcoded). `race_condition` floor `≥ 8` only for TOCTOU on concrete state mutation; read-side cache races capped at 4.
- **`sink_kind` enum** extended from 30 to 41 values:
  - Security headers: `csp_missing`, `csp_unsafe_inline`, `clickjacking_unprotected`, `hsts_missing`, `mime_sniff_unprotected`.
  - JWT / OAuth: `jwks_spoof`, `oidc_misconfig`, `tls_validation_bypass`.
  - Injection sub-kinds: `ldap_injection`, `xpath_injection`, `nosql_injection`.
- **`root_cause_family` enum** extended with `clickjacking`.
- **Detection recipes** (10 new under `bin/recon/recipes/`): `easyadmin_detect.py`, `sonata_detect.py`, `api_platform_detect.py`, `jwt_generic_detect.py`, `oauth_oidc_detect.py`, `auth0_detect.py`, `aws_cognito_detect.py`, `okta_detect.py`, `keycloak_detect.py`, `firebase_auth_detect.py`, `stripe_detect.py`, `aws_secrets_manager_detect.py`, `vault_detect.py`, `saml_detect.py`, `webauthn_passkeys_detect.py`. Composer + env + bounded source-scan probes with vendor-skip and symlink containment.
- **`stack.addons` and `stack.integrations`** populated automatically in CONTEXT.md frontmatter from detection results; consumed by the resolver to load the corresponding checklist layers.
- 1024 unit/regression tests (+238 since 3.4.0).

### Changed

- **BREAKING.** Directory `checklists/frameworks/` renamed to `checklists/stacks/` (history preserved via `git mv`).
- **BREAKING.** `resolve_checklists(themes, stack, plugin_root)` signature changed to `resolve_checklists(themes, ctx: ResolutionContext, plugin_root)`. Callers must construct a `ResolutionContext` and read `stack.framework` from the frontmatter dict.
- **BREAKING.** CONTEXT.md bag namespace renamed: `framework_specific.{stack}.*` → `recon_bags.{kind}.{name}.*` where `kind ∈ {stack, addon, integration}`. Three-level shape replaces the previous two-level shape. ~240 references updated across code, tests, checklists, and worker prompts.
- **`_meta.md`** rewritten for the five-layer model with new diagrams, resolution chain, layer conventions, integration-anchor exception, disambiguation rows for the new sink_kinds, and the documented `## Trusted patterns` convention.
- **YAML subset emitter/parser** widened to accept kebab-case dict keys (needed for `recon_bags.addon["api-platform"].resources`). Leading-hyphen still rejected.
- **GraphQL detection** (`graphql_detect.py`) recognizes both `api-platform/core` (v3) and `api-platform/symfony` (v4).
- **`available_recipes()`** filters `*_detect.py` so addon/integration probes are not auto-loaded as stack recipes.
- **EasyAdmin and Sonata bag-collectors** moved into dedicated modules; backward-compat re-exports from `symfony.py` removed (no in-repo callers).
- **Symfony recipe `_empty_skeleton`** degraded path now runs composer-based addon and integration probes when `project_root` is available — addon / integration detection survives extractor failure.

### Fixed

- **`plan_waves.lookup_kind_for_file`** walked the bag at two levels after the namespace rename and silently returned `None` for every file. The masking unit test used the old two-level fixture shape. Fixed to walk three levels; new test exercises the addon namespace.
- **JWT and OAuth content** migrated from `core/auth.md` and `core/crypto.md` into `integrations/{jwt-generic,oauth-oidc}/`. Defense-in-depth `oauth_state_missing` floor retained in `core/auth.md` for projects that use custom OAuth without a detected SDK.
- **`#[ApiResource]` / GraphQL** sections previously embedded in `stacks/symfony/{auth, data-access, output-render}.md` moved into `stacks/symfony/addons/api-platform/` with the api-platform parts; overblog/webonyx-specific bullets remain in stack files. Section titles updated and breadcrumbs added.

### Composer-name accuracy

Two rounds of triple review (Stages 5 and 7) caught fictional composer package names in detector tables. Every package name in identity-provider and vendor-integration detectors is now packagist-verified against `https://repo.packagist.org/p2/...`. AWS Cognito, Okta, Auth0, Keycloak, Stripe, Vault, WebAuthn, and SAML lists were corrected. Worker tests that previously passed tautologically (using the same fake names as the detectors) now use real names.

### Notes

- **Provider integrations imply generic layers.** Detection of `auth0` / `aws-cognito` / `okta` / `keycloak` automatically activates `jwt-generic` and `oauth-oidc` layers. `firebase-auth` activates `jwt-generic` only (Firebase uses JWT but not standard OAuth/OIDC).
- **Stage 7 integrations are intentionally orthogonal** — `stripe`, `aws-secrets-manager`, `vault`, `saml`, `webauthn-passkeys` do NOT pull in `jwt-generic` or `oauth-oidc` (different protocol surfaces).
- **PHP sandbox extractor for `api-platform.resources` and JWT/OAuth call sites is deferred.** The bag is populated only with a placeholder status (`status: unknown` with a reason); content extraction lands in a follow-up release.
- **Reserved for future stages**: `languages/{php,python,node,go}/`, `stacks/{django,fastapi,express,nestjs}/`, additional providers (Azure AD B2C, Clerk, Supabase Auth), LLM-security integrations (prompt injection, output handling), compliance integrations (GDPR / HIPAA / PCI).

### Migration from 3.x

Internal-only refactor — no external consumers of the plugin format. Projects that use 3.4.0 CONTEXT.md fixtures need to:

1. Rename top-level `framework_specific:` → `recon_bags:` and restructure as `recon_bags.{kind}.{name}.<bag_key>` (kind ∈ `stack`, `addon`, `integration`).
2. Move EasyAdmin / Sonata bag entries from `framework_specific.symfony.easyadmin_crud_controllers` / `.sonata_admin_classes` to `recon_bags.addon.easyadmin.crud_controllers` / `recon_bags.addon.sonata.admin_classes`. Keep `admin_authz_coverage` under `recon_bags.stack.symfony.*` (cross-addon synthesis).
3. Add optional `stack.addons: [...]` and `stack.integrations: [...]` lists to the frontmatter; they're populated automatically by recon and consumed by the resolver to load the new layers.

## [3.4.0] — 2026-05-20

### Initial public release

First public release. Version 3.4.0 inherits the version number from a private predecessor for numbering continuity.

**What is included:**

- Slash commands `/fr-security-review:security-project` and `/fr-security-review:security-changes` for PHP projects.
- Recipe-driven recon with support for Symfony, Laravel, and generic PHP. Schema v2 (`<review_root>/CONTEXT.md` with frontmatter and closed shape specs).
- 6 focused worker waves: W1 auth/disclosure, W2 injection/data-access, W3 output-render, W4 serialization/crypto, W5 ssrf+fileops, W6 fintech + W∞ exploratory (cross-layer chains).
- Adversarial pass (second-pass refute) and the option to disable it via `--no-adversarial`.
- Detection: GraphQL (lighthouse, rebing-laravel, api-platform, webonyx), EasyAdmin, Sonata, Octane, messenger transports, sensitive columns.
- Detection regression: "removed-defense" — detection of removed validators/sanitizers in `/security-changes`.
- Deterministic deduplication (`dedupe_findings.py`) with split report `REPORT.md` + `REPORT/<root_cause_family>.md`.
- 767 unit/regression tests for recon, dedupe, and e2e pipeline (stdlib only, no third-party Python deps).
- Sandbox modes: `--no-console`, firejail, Docker.
- Project-level exclude via `<project_root>/CLAUDE.md` and `--exclude=<csv>`.

**License:** Elastic License 2.0.
