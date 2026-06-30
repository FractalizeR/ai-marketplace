# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This repo is **a Claude Code plugin marketplace** (`fractalizer-marketplace`, declared in `.claude-plugin/marketplace.json`) plus one in-tree plugin, `fr-security-review`, that makes up the bulk of the codebase. Adding another plugin means a new top-level directory plus an entry in `marketplace.json`.

`fr-security-review` is a framework-aware static-first security audit for PHP / Symfony / Laravel, driven by Claude Code slash commands. Implementation is stdlib-only Python under `security-review/bin/`, prompts under `security-review/agents/` and `security-review/commands/`, content under `security-review/checklists/`.

## Common commands

All commands are run from the repo root unless stated otherwise.

### Tests

The plugin's Python pipeline is covered by a stdlib-only `unittest` suite (~1130 tests, no third-party deps, no `pytest.ini`).

```bash
# Full suite (used as the CI gate; takes ~50 seconds)
python3 -m unittest discover -s security-review/bin/tests

# A single test module
python3 -m unittest security-review.bin.tests.test_dedupe_findings

# A single test method
python3 -m unittest security-review.bin.tests.test_plan_waves.PlanWavesTests.test_balanced_model_assignment
```

There are no linters or formatters wired into CI; rely on the unittest suite.

### Plugin validation (pre-commit hook)

A pre-commit hook in `.githooks/pre-commit` runs `claude plugin validate .` against the marketplace metadata. After cloning, enable the hook once:

```bash
git config core.hooksPath .githooks
```

Run the same check ad-hoc with `claude plugin validate .`.

### Installing / driving the plugin

The slash commands are exposed by Claude Code after the plugin is installed (`claude /plugin install fr-security-review@fractalizer-marketplace`):

- `/fr-security-review:security-project [flags]` — whole-project audit (`security-review/commands/security-project.md`).
- `/fr-security-review:security-changes [flags]` — diff-only audit against the base branch (`security-review/commands/security-changes.md`).

Both write artifacts to `security-review-<label>/` in cwd. The label is auto-picked by harness self-introspection (`claude | codex | gemini | deepseek | qwen | other-<short>`) unless `--label=` or `--review-root=` is passed.

## Architecture — `fr-security-review`

### Four-stage pipeline

Per slash command run, the orchestrator (`commands/*.md` prompt) executes four stages strictly in order:

1. **Recon** — the `security-recon` subagent runs `bin/recon_inventory.py`, which picks a recipe (`bin/recon/recipes/{symfony,laravel,generic_php}.py`), parses PHP via a sandboxed `bin/recon/extract_php_metadata.php` (token-only, no `require`/`include`), and writes `<review_root>/CONTEXT.md` (schema v2 — frontmatter + closed-shape sections). The agent then Edits any `status: pending_enrichment` sections in place; **only `recon_inventory.py` may `Write` CONTEXT.md** — the agent never overwrites it. Validation: `bin/validate_context.py [--sanity] --project-root <path>`.

   **Environment-aware console enrichment (4.1+).** Symfony recon may run `bin/console` (`debug:router`, `list`, …) to enrich the inventory — this executes the project's bootstrap. Before doing so, `bin/recon/environment.py` statically probes the execution environment (container signals, compose php-service, Makefile console targets, host `php`) and `recon_inventory.decide_console_runner` resolves a `recon.sandbox.ConsoleRunner` — `host` / `container` / `custom` / `disabled` — from the probe + `--console-cmd` / `--no-console`. **Containerization is the dominant gate:** a containerized project's console is never run on the host automatically; an unresolved runner records a loud `console_gap` (ceiling=medium) instead of silently degrading. The recipe declares its entrypoint via the optional `CONSOLE_ENTRYPOINT` module attribute (`["php","bin/console"]` for Symfony; `None` for Laravel/generic ⇒ console N/A, no gap). `environment.py` and `sandbox.ConsoleRunner` are stack- and path-agnostic; `bin/console` existence is the runner-builder's concern, not the sandbox's.

2. **Wave planning** — `bin/plan_waves.py` reads CONTEXT.md and emits a JSON plan of `slice_id`s. Each slice carries `themes`, resolved `checklists` (absolute paths), `target_files`, `entry_points_in_scope`, and a `model` (opus | sonnet from `WaveSpec.balanced_model`). Six base waves W1–W6 cover focused themes; W∞ is the cross-layer exploratory wave (on by default; `--quick` disables it).

3. **Workers** — the orchestrator launches `Task(subagent_type="security", model=<from plan>, ...)` in batches of ≤6 parallel calls. Each worker reads the slice's `target_files`, applies its checklist chain (see resolver below), and `Write`s findings to `<review_root>/waves/<slice_id>.md`. The model argument is the **balanced profile**: opus for trust-boundary waves (W1/W2/W6), sonnet for mechanical data-flow waves (W3/W4/W5/W∞). `--all-opus` forces opus everywhere (legacy).

4. **Dedupe + optional refute** — `bin/dedupe_findings.py` (package: `bin/dedupe/`) parses all `waves/*.md`, deduplicates by `sink_hash` (computed deterministically from the worker's normalized `sink_snippet`), and writes a split report: `<review_root>/REPORT.md` (executive summary + index) + `<review_root>/REPORT/<root_cause_family>.md` (per-family detail). State for cross-run "New / Recurring / Closed" is kept in `<review_root>/.findings_state.json`. The optional adversarial refute pass calls `security-refute` sequentially (parallelism forbidden — single `refute.md` writer) on batches of ≤20 findings; results are folded back via a second `dedupe_findings.py --refute=<path>` invocation. When recon recorded a `console_gap` (see the `environment` block), `dedupe_findings.py` leads REPORT.md with a `## Coverage Gaps` section so reduced coverage is surfaced, not buried.

### Five-layer checklist resolver

`bin/plan_waves.py:resolve_checklists` assembles each theme's checklist chain from five layers, least specific to most:

```
core/ → languages/{lang}/ → stacks/{stack}/ → stacks/{stack}/addons/{addon}/ → integrations/{integration}/
```

Precedence on conflict (most specific wins): `integrations > addons > stacks > languages > core`. Layers are opt-in — missing files are silently skipped. Activation comes from CONTEXT.md frontmatter: `stack.language`, `stack.framework`, `stack.addons[]`, `stack.integrations[]` (populated by detection recipes under `bin/recon/recipes/*_detect.py`). **Integrations are stack-agnostic** — `integrations/stripe/` activates on a generic-PHP project too.

Adding a new layer file: drop it under the right directory, ensure its anchor matches the convention in `checklists/_meta.md`, and the resolver will load it the next time CONTEXT.md frontmatter lists the corresponding addon/integration/language/stack. Non-core files do **not** declare their own `## Recommended sink_kinds` — they refine applicability of the core sink_kinds; the enum is closed and lives in `checklists/_meta.md` (and is referenced from `agents/security.md`).

### Detection recipes vs main recipes

`bin/recon/recipes/` mixes two concepts:
- **Main recipes** (`symfony.py`, `laravel.py`, `generic_php.py`) — the inventory builder for a stack. Exactly one runs per audit, picked by `recon_inventory.py --detect`.
- **Detect-only modules** (`*_detect.py`, e.g. `easyadmin_detect.py`, `auth0_detect.py`, `stripe_detect.py`) — composer + env + bounded source-scan probes that populate `stack.addons` / `stack.integrations`. `available_recipes()` filters these out so they're never selected as a main recipe.

### Schema v2 invariants

- **`<review_root>/CONTEXT.md`** is the single source of truth. Schema is markdown with YAML frontmatter + per-section blocks tagged by `<!-- section_id: ... -->` and `<!-- enrichment_marker: <id>__{pending|done}__<hash4> -->`. Validator: `bin/validate_context.py`. Old v1 (`SECURITY_CONTEXT.md` in project root) is detected but not read — orchestrator warns and continues.
- **`recon_bags.{kind}.{name}.<bag_key>`** is the **only** namespace for stack/addon/integration data inside CONTEXT.md (kind ∈ `stack | addon | integration`). The pre-4.0 `framework_specific.{stack}.*` flat shape was removed; tests and `plan_waves.lookup_kind_for_file` walk exactly three levels.
- **`environment` frontmatter block (4.1+).** Records how console enrichment was resolved: `containerized`, `container_signals`, `host_php_present`, `host_php_version`, `console_mode` (`host|container|custom|disabled`), `console_gap`, `console_gap_reason`. Built by `recon_inventory._environment_block`; optional and backward-compatible (pre-4.1 contexts validate without it — see `validate_context.py`). `dedupe_findings.py` reads `console_gap` / `console_gap_reason` to render the `## Coverage Gaps` section of REPORT.md.
- **`project_root` vs cwd.** Composite-repo support (monorepo + PHP subproject) means the orchestrator and workers receive an explicit `project_root` that may differ from cwd. All `target_files`, `entry_points_in_scope`, and item paths inside CONTEXT.md are **`project_root`-relative**, not cwd-relative; the recon utility uses `Path.relative_to(project_root).as_posix()`. When editing worker / recipe code, never assume cwd == project_root, and never resolve project paths without `project_root` (see `agents/security.md` "PATH RESOLUTION").
- **`--review-root` is output-only.** Step 0.3 in both orchestrator prompts rejects values that look like a source tree (basenames in a blacklist, equal to project root, or non-`security-review-`-prefixed subpaths). Past incident: `--review-root=src` clobbered the user's `src/.gitignore` with `*`.
- **Closed enums.** `sink_kind` (41 values) and `root_cause_family` (10 values) are duplicated in three places that must stay in sync: `checklists/_meta.md`, `agents/security.md`, and the parser/dedupe code (`bin/dedupe/`). `test_enum_consistency.py` enforces alignment.

## Adding to this codebase

- **New stack** (e.g., Django, FastAPI): add a main recipe under `bin/recon/recipes/`, register it via `available_recipes()`, populate `checklists/stacks/<stack>/<theme>.md` files, and extend `bin/plan_waves.py` `CONCEPT_RESOLVERS` with the stack's `recon_bags.stack.<stack>.*` paths for each concept. If the stack has a runnable console for enrichment, declare its entrypoint via the `CONSOLE_ENTRYPOINT` module attribute (e.g. `["php","artisan"]`); leave it `None` (or absent) for a fully-static recipe — `recon.recipes.console_entrypoint` reads it defensively and the console machinery treats `None` as N/A.
- **New addon or integration**: add a `*_detect.py` probe under `bin/recon/recipes/`, populate `checklists/{stacks/<stack>/addons/<addon>|integrations/<integration>}/<theme>.md`, and (for provider integrations) consider whether it implies others — see `PROVIDER_IMPLIES_INTEGRATIONS` (Auth0/Cognito/Okta/Keycloak imply `jwt-generic` + `oauth-oidc`).
- **New `sink_kind`**: update the enum in all three places above and add the sink_kind → family row to `checklists/_meta.md`. `test_enum_consistency.py` will fail until the lists line up.
- **New plugin in the marketplace**: create a top-level directory with `plugin.json` + `commands/` + `agents/`, append the entry to `.claude-plugin/marketplace.json`, and bump versions where appropriate. The pre-commit hook revalidates the marketplace before commit.

## Working conventions

- **Russian for human-facing conversation, English for code, prompts, and docs.** All in-tree content (README, CHANGELOG, plugin prompts, checklists, tests) is English — match that style when editing.
- **stdlib only in Python.** No `requirements.txt`, no `pip install`. Don't introduce third-party deps in `bin/` without an explicit ask.
- **Idempotency in recon and dedup.** Both `recon_inventory.py` and `dedupe_findings.py` overwrite their outputs on every run. Tests rely on this. Don't add append-only side effects.
- **Worker output is the contract.** Workers communicate solely through `<review_root>/waves/<slice_id>.md`; the orchestrator has a safety-net that extracts findings from a worker's response message if the file is missing, but tests assume the file path. When changing worker output format, update `bin/dedupe/parser.py` and the agent prompt together.
- **No commits of review artifacts.** `<review_root>/.gitignore` is written with content `*` to ignore everything inside, including itself. The project-level `.gitignore` is never modified by the plugin.
- **Direct-to-`main` workflow — no feature branches.** This repo commits and pushes straight to `main` (overrides the global "branch from master" default). Still split work into logical Conventional Commits; just don't open branches/PRs here.
