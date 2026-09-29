# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This repo is **a Claude Code plugin marketplace** (`fractalizer-marketplace`, declared in `.claude-plugin/marketplace.json`) with two in-tree plugins:

- `fr-security-review` (`security-review/`) — the bulk of the codebase: a framework-aware static-first security audit for PHP / Symfony / Laravel, driven by one slash command. Stdlib-only Python under `security-review/bin/`, prompts under `security-review/{commands,agents}/`, content under `security-review/checklists/`. Also shipped to Codex CLI as a derived bundle (see "Codex derivation").
- `fr-audit-triage` (`audit-triage/`) — Claude Code only: turns an audit's `findings.json` into code-verified units of work and hands verdicts back via `dedupe_findings.py --verdicts-in`. It is the audit's false-positive filter; the audit has no refute pass of its own.

Adding another plugin means a new top-level directory with `plugin.json` + `commands/` + `agents/`, plus an entry in `.claude-plugin/marketplace.json`.

## Commands

All commands run from the repo root.

```bash
python3 -m unittest discover -s security-review/bin/tests   # engine suite (about a minute)
python3 -m unittest discover -s build/tests                 # build tooling suite (fast)
python3 -m unittest discover -s audit-triage/bin/tests      # triage suite (fast)
python3 -m unittest discover -s scripts/tests               # frsr launcher suite (fast)
python3 -m unittest security-review.bin.tests.test_dedupe_findings                  # one module
python3 -m unittest security-review.bin.tests.test_plan_waves.ModelSelectionTests   # one class
```

There are no linters or formatters; rely on the unittest suites.

### Validation — no CI

There is no CI and no Sentry; every gate runs locally, and commits go straight to `main`. After any substantive change, run the full gate before committing — `make check` (several minutes; run it with a long timeout or in the background):

```bash
python3 build/build.py --harness=codex --mode=check   # Codex derivation gates
python3 -m unittest discover -s build/tests
python3 -m unittest discover -s security-review/bin/tests
python3 -m unittest discover -s audit-triage/bin/tests
python3 -m unittest discover -s scripts/tests
claude plugin validate .                              # marketplace metadata
scripts/leakcheck.sh --all                            # internal-identifier leak check
```

The `.githooks/pre-commit` hook runs the fast subset (`claude plugin validate .`, the Codex `--mode=check`, the build suite, `leakcheck.sh --staged`). Enable it once per clone: `git config core.hooksPath .githooks`.

Other `make` targets (`make help`): `build-codex` (bundle into `dist/codex`), `install-codex` (build + register + install on the local Codex CLI; re-run to update — it bumps the plugin cachebuster), `install-launchers` (bake the repo path into `scripts/frsr` and install it into `BINDIR`, default `~/.local/bin`). The `Makefile` and `scripts/` are dev tooling, not shipped inside a plugin.

### Driving the audit

- Claude Code: `/fr-security-review:security-project [flags]` (`security-review/commands/security-project.md`). Artifacts go to `security-review-<label>/` in cwd; the label comes from harness self-introspection unless `--label=` or `--review-root=` is passed.
- Codex: `frsr [project] --models high=<id>,fast=<id> [--console-cmd <tpl>] [--go] -- <orchestrator flags>`. Orchestrator flags (`--quick`, `--no-console`, …) go after `--`; an unknown option before `--` is an error. Without `--go`, `frsr` only prints the prepared command (Codex runs the orchestrator unsandboxed to spawn workers). `--models` is required on the first run for a review root, then reused from `<review_root>/.model_map.json`; ids come from `codex debug models`.

## Codex derivation (`build/`)

The Claude prose under `security-review/{commands,agents}/` is authoritative; the Codex skill and read-follow worker files are derived from it by dev-only tooling under `build/` (not shipped).

- CLI: `python3 build/build.py --harness=codex --mode={check,write,refresh-hashes} [--out=<dir>]`. `check` (default) renders in memory and runs the gates, never writes (exit 0 clean / 1 gate / 2 error). `write` builds the bundle (default `dist/codex`, gitignored).
- `build/sections.py` splits an artifact at headings outside frontmatter, fenced blocks and `Task` directives. `build/derive.py` replaces a section **iff** `harness/codex/sections/<artifact>/<anchor>.md` exists (`<anchor>` = heading slug, e.g. `8-parallel-worker-launch`); every other section gets frontmatter handling (command → skill `name` + `description`, agent → stripped) and token substitution (`${CLAUDE_PLUGIN_ROOT}` → `${FR_SECURITY_CORE_ROOT}`, `$ARGUMENTS` / prose `AskUserQuestion` / `mcp__…` → neutral phrases).
- If you edit a templated section of `security-project.md` (the anchors in `derive.REQUIRED_TEMPLATES`) → the check fails with `… is stale`. Update the matching template to the new Claude prose, then run `python3 build/build.py --mode=refresh-hashes` (rewrites each template's `<!-- source-sha256: … -->` first line). Never refresh a hash without reviewing the template.
- If you rename or renumber a heading → its template becomes orphaned and the check fails. Do not renumber steps in `security-project.md`; if a rename is unavoidable, rename the template file to the new anchor, review it, and refresh the hash.
- If you add a `Task(...)` directive or a labeled `AskUserQuestion:` block to a section without a template → the no-leak gate (`build/gates.py`) fails. Author a Codex template for that section.
- If you add or remove a template → update `derive.REQUIRED_TEMPLATES` in the same change; the check fails on a listed template that is missing (the leak gate cannot see one for a section without `Task`/AUQ tokens) and on a template directory that names no artifact.
- Dispatch templates (`4-recon-phase`, `8-parallel-worker-launch`) must wire `codex exec` + `-m` + `--add-dir` + a read-follow ref to a bundled `agents/<role>.md` (gated). In the fan-out `--worker-cmd-template` use the `dispatch.py` placeholder `{core_root}/agents/…` (a literal `${FR_SECURITY_CORE_ROOT}` there breaks `str.format` before any worker starts); recon uses `<FR_SECURITY_CORE_ROOT>`-style slots the orchestrator substitutes. Pass worker inputs as flag-free `key=value` (`console_mode=…`, `exclude=…`) — a leading `--` is eaten by the harness CLI.
- Bundle topology: `dist/codex/` is a marketplace root (`.fr-codex-bundle` sentinel + `.agents/plugins/marketplace.json` + `plugins/fr-security-review/{.codex-plugin/plugin.json, skills/security-project/SKILL.md, core/{bin,checklists,agents/*.md}, adapter.json, INSTALL.md}`). `core/` is what `FR_SECURITY_CORE_ROOT` points at.
- Authored configs under `harness/codex/` (`plugin.json`, `marketplace.json`, `adapter.json`, `INSTALL.md`) are copied verbatim and validated in both modes by `build/codex_manifest.py` (a stdlib mirror of Codex's `validate_plugin.py`: strict-semver `version`, required `interface` fields, no `[TODO:`).
- The write path refuses an existing `--out` that is an authored source tree, or is neither under the repo's `dist/` nor carrying the `.fr-codex-bundle` sentinel, and swaps the bundle in atomically. Reinstalling an already-installed Codex plugin needs a cachebuster version bump (done by `make install-codex`); keep the committed `harness/codex/plugin.json` a clean semver.

## Shared runtime helpers (`security-review/bin/shared/`)

Used only by the Codex harness (Claude fans out with native `Task`).

- `model_resolver.py --models high=<id>,fast=<id> --review-root <dir>` writes `.model_map.json` `{high, fast}`; without `--models` the saved map is used; neither → exit 2. No discovery, no id validation.
- `dispatch.py` — `dispatch_waves` runs one `codex exec` per plan slice (≤6 concurrent); `dispatch_role` runs the single `recon` process. Planned slices' wave files are deleted before fan-out, so a stale file plus a crashed worker is still a gap; a fresh `waves/<slice_id>.md` is success regardless of exit code. `--allow-gaps` writes `dispatch_gaps.json`, which `dedupe_findings.py --dispatch-gaps` folds into REPORT.md as INCOMPLETE; a clean run removes a stale one.
- `contracts.py` — typed seams; subprocess is the single injected seam. Tests pass a fake runner and never spawn a real `codex`.

## Architecture — `fr-security-review`

### Pipeline

The orchestrator (`commands/security-project.md`) runs four stages in order.

1. **Recon.** The `security-recon` agent runs `bin/recon_inventory.py`, which picks a main recipe (`bin/recon/recipes/{symfony,laravel,generic_php}.py`), parses PHP through the sandboxed token-only `bin/recon/extract_php_metadata.php` (180 s timeout, `FR_SECURITY_EXTRACTOR_TIMEOUT` overrides; never walks a directory whose basename starts with `.`, independently of `--exclude`), and writes `<review_root>/CONTEXT.md`.
   - **Only `recon_inventory.py` writes CONTEXT.md.** The agent only Edits `pending_enrichment` sections in place and never copies secret values into it (`<redacted>`).
   - Section statuses: `ok`; `partial` = evidence found but not interpreted; `unknown` = no evidence; `none`; `pending_enrichment` (core scalar sections such as `auth_layer`, `secrets`, for the agent to enrich; `recon_bags` are never pending). A failed extractor call marks the affected sections `partial` with `extractor_failed: <kind>: <warning>` (Symfony and Laravel); the first timeout latches and later `--kind=` calls are skipped.
   - **Console.** Symfony may run `bin/console` (`debug:router`, `debug:config`) — this executes the project's bootstrap. The orchestrator boot-tests the runner up front (`recon_inventory.py --console-preflight`); a required console that doesn't boot stops the run with the fix-it flags (`--console-cmd=<tpl>`, `FR_SECURITY_CONSOLE_CMD`, `--no-console`). A recipe declares its entrypoint via `CONSOLE_ENTRYPOINT` (`None` ⇒ not applicable).
   - **Config is interpreted only through the console.** `_symfony_introspection.ConsoleSession` asks `debug:config <alias> --format=json` for `security`/`framework`/`messenger`/`twig` for every alias (a failure warning is suppressed only when the alias has no config evidence). There is no static config parser: without a tree (`--no-console`, a failed console, a tree that doesn't match the located files for `security`, an env mismatch) the sections go `partial` (`auth_layer` stays `pending_enrichment`) with `config_uninterpreted: <alias>: <no_console|console_failed|tree_mismatch|env_mismatch>` and the evidence files in `source_files`. `--resolve-env` is never passed; secret-looking keys and `secrets` snippets are masked before they reach CONTEXT.md.
   - **Sanity** (`validate_context.py --sanity --project-root <p> --gaps-out <review_root>/recon_gaps.json`) exits non-zero only for a structurally invalid CONTEXT.md. Coverage gaps, extractor failures, uninterpreted config and list sections left pending are `WARNING:` lines plus records in `recon_gaps.json` (`{schema_version: 1, items}`); sections without a probe fall back to the recipe's `SOURCE_ROOTS` glob; the user's excludes come from the `exclude_paths_user` frontmatter list. `recon_confidence` is display-only.
2. **Wave planning.** `bin/plan_waves.py` emits a JSON plan of slices (`themes`, absolute `checklists`, `target_files`, `entry_points_in_scope`, `model`, `mode: project`). W1–W6 are focused waves; W∞ is exploratory (on by default, `--quick` disables it); `--recon-gaps` adds `WGAP_PART<n>` slices on opus from `recon_gaps.json` (survive `--quick`, honour `--scope-glob`, skip files other slices carry, capped at `GAP_MAX_FILES`). Routing: list sections route when `ok|partial`, scalar sections' `source_files` when `ok|partial|pending_enrichment`; `unknown` sections are **not** routed — their files reach workers only through `recon_gaps.json` → WGAP. Models come from `WaveSpec.balanced_model` (opus for W1/W2/W6/WGAP, sonnet otherwise); `--all-opus` promotes W4/W5/W∞, W3 stays sonnet.
3. **Workers.** `Task(subagent_type="security", model=<from plan>, …)` in batches of ≤6. Each worker applies its checklist chain and Writes `<review_root>/waves/<slice_id>.md`; a `WGAP_` slice first reads `recon_gaps.json`.
4. **Dedupe.** `bin/dedupe_findings.py` (package `bin/dedupe/`) parses `waves/*.md` (verdicts `confirmed` / `needs_validation` / `hardening`), deduplicates `confirmed` findings by `sink_hash`, and writes `REPORT.md` + `REPORT/<root_cause_family>.md` + `findings.json` (public inter-plugin contract, `schema_version` 1, every constituent finding of all three verdicts — `bin/dedupe/export.py`). Bucket records bind to a confirmed finding by exact `sink_hash`, then `dedupe()`'s Pass-2 key, then its Pass-3 location key (`[ATTACHED_WITHOUT_HASH]` when not by hash). `## Coverage Gaps` shows `console_gap`, dispatch gaps and each `recon_gaps.json` entry split into reviewed / NOT reviewed files (needs `--waves-plan`). External verdicts come in via `--verdicts-in=<path>`; there is no cross-run finding diff.

### Four-layer checklist resolver

`plan_waves.resolve_checklists` builds each theme's chain `core/ → stacks/{stack}/ → stacks/{stack}/addons/{addon}/ → integrations/{integration}/`; the most specific layer wins on conflict. Missing files are skipped. Activation comes from CONTEXT.md frontmatter `stack.framework`, `stack.addons[]`, `stack.integrations[]` (populated by `*_detect.py` probes). Integrations are stack-agnostic. Non-core files do not declare `## Recommended sink_kinds`; the closed enum lives in `checklists/_meta.md`.

### Detection recipes vs main recipes

`bin/recon/recipes/` holds **main recipes** (`symfony.py`, `laravel.py`, `generic_php.py` — exactly one runs, picked by `recon_inventory.py --detect`) and **detect-only modules** (`*_detect.py` — composer/env/bounded source-scan probes filling `stack.addons` / `stack.integrations`; `available_recipes()` excludes them).

### Schema v2 invariants

- `<review_root>/CONTEXT.md` is the single source of truth: YAML frontmatter + sections tagged `<!-- section_id: ... -->` and `<!-- enrichment_marker: <id>__{pending|done}__<hash4> -->`. Validator: `bin/validate_context.py`. Extra frontmatter keys stay valid (old contexts with `scope` / fingerprints pass).
- `recon_bags.{stack|addon|integration}.{name}.<bag_key>` is the only namespace for stack/addon/integration data; every reader walks exactly three levels below `recon_bags`.
- The optional `environment` frontmatter block records how the console was resolved (`console_mode` `host|container|custom|disabled`, `console_gap`, `console_gap_reason`, …); dedupe renders `console_gap` in `## Coverage Gaps`.
- **`project_root` vs cwd.** All `target_files`, `entry_points_in_scope` and CONTEXT.md item paths are `project_root`-relative. In worker/recipe code never assume cwd == project_root and never resolve project paths without it (`agents/security.md` "PATH RESOLUTION").
- **`--review-root` is output-only.** Step 0.3 rejects source-tree-looking values (a past `--review-root=src` clobbered `src/.gitignore`). Keep that guard.
- **Closed enums.** `sink_kind` (41) and `root_cause_family` (10) live in `checklists/_meta.md`, `agents/security.md` and `bin/dedupe/`; `test_enum_consistency.py` enforces alignment.
- `.findings_state.json` (schema 2) holds only the verdict journal; any other schema version reads as an empty journal with a warning.

## Adding to this codebase

- **New stack:** add a main recipe under `bin/recon/recipes/` (register via `available_recipes()`, set `SOURCE_ROOTS`, set `CONSOLE_ENTRYPOINT` or leave it `None`), add `checklists/stacks/<stack>/<theme>.md`, extend `plan_waves.py` `CONCEPT_RESOLVERS` with its `recon_bags.stack.<stack>.*` paths.
- **New addon or integration:** add a `*_detect.py` probe and `checklists/{stacks/<stack>/addons/<addon>|integrations/<integration>}/<theme>.md`; for provider integrations check `PROVIDER_IMPLIES_INTEGRATIONS`.
- **New `sink_kind`:** update all three enum places and add the sink_kind → family row to `checklists/_meta.md`.
- **Releasing:** bump `security-review/plugin.json`, the marketplace `metadata.version` in `.claude-plugin/marketplace.json` (one minor per release), `harness/codex/plugin.json` when the bundle changes, and add a `security-review/CHANGELOG.md` entry; never edit older CHANGELOG entries.

## Working conventions

- **Russian for human-facing conversation, English for code, prompts and docs.**
- **stdlib only in Python.** No `requirements.txt`, no `pip install` in `bin/` without an explicit ask.
- **Idempotent outputs.** `recon_inventory.py` and `dedupe_findings.py` overwrite their outputs wholesale each run, and tests rely on it; don't add append-only side effects. The one exception is the verdict journal (`resolutions`) in `.findings_state.json`, which `dedupe/state.save_state` merges read-modify-write by `sink_hash`.
- **Worker output is the contract.** Workers communicate only through `<review_root>/waves/<slice_id>.md` (the orchestrator's safety net recovers a missing file from the response). When changing the worker output format, update `bin/dedupe/parser.py` and `agents/security.md` together.
- **No commits of review artifacts.** `<review_root>/.gitignore` contains `*`. The plugin never edits the project `.gitignore`; for already-tracked artifacts it only prints the fix command.
- **Public repo — synthetic examples only.** No example, fixture, test comment or checklist illustration may describe a real vulnerability in a real system (live or fixed); label examples as synthetic with placeholder identifiers. No internal service, queue, host or symbol names — `scripts/leakcheck.sh` enforces the identifier half; the synthetic-example half is a review obligation.
- **Direct-to-`main`, no feature branches** (overrides the global branching default). Still split work into logical Conventional Commits.
