# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This repo is **a Claude Code plugin marketplace** (`fractalizer-marketplace`, declared in `.claude-plugin/marketplace.json`) plus one in-tree plugin, `fr-security-review`, that makes up the bulk of the codebase. Adding another plugin means a new top-level directory plus an entry in `marketplace.json`.

`fr-security-review` is a framework-aware static-first security audit for PHP / Symfony / Laravel, driven by Claude Code slash commands. Implementation is stdlib-only Python under `security-review/bin/`, prompts under `security-review/agents/` and `security-review/commands/`, content under `security-review/checklists/`.

## Common commands

All commands are run from the repo root unless stated otherwise.

### Tests

The plugin's Python pipeline is covered by a stdlib-only `unittest` suite (~1219 tests, no third-party deps, no `pytest.ini`).

```bash
# Full engine suite (~1219 tests, ~50 seconds)
python3 -m unittest discover -s security-review/bin/tests

# Build tooling suite (fast; multi-environment build, see below)
python3 -m unittest discover -s build/tests

# A single test module
python3 -m unittest security-review.bin.tests.test_dedupe_findings

# A single test method
python3 -m unittest security-review.bin.tests.test_plan_waves.PlanWavesTests.test_balanced_model_assignment
```

There are no linters or formatters; rely on the unittest suites (engine under
`security-review/bin/tests`, build tooling under `build/tests`).

### No CI — validation is local

This repo has **no CI pipeline and no Sentry**. Every gate runs on the maintainer's
machine; commits go straight to `main` (see "Direct-to-`main` workflow" below).
The `.githooks/pre-commit` hook runs the *fast* subset automatically; the full gate
below is run manually after any substantive change before committing.

**Full local validation gate** (run all, all must pass):

```bash
python3 build/build.py --harness=claude   --mode=check   # byte-identity anti-drift (exit 0)
python3 build/build.py --harness=opencode --mode=check   # OpenCode structural gates
python3 build/build.py --harness=codex    --mode=check   # Codex structural gates
python3 -m unittest discover -s build/tests              # build tooling suite (~241, fast)
python3 -m unittest discover -s security-review/bin/tests # engine suite (~1219, ~50s)
claude plugin validate .                                 # marketplace metadata
```

The whole gate is also wrapped as **`make check`**. Other `make` targets (see
`make help`): `build-{codex,opencode}` (write a bundle to `dist/`),
`install-{codex,opencode}` (build + install the derived bundle on the local
Codex/OpenCode CLI via `scripts/install-*.sh` — idempotent, re-run to update),
`test-build`, `test-engine`. The `Makefile` and `scripts/` are dev tooling, not
shipped inside the plugin.

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

### Multi-environment build (Phase 1: Claude round-trip)

Dev-only tooling under repo-top `build/` (NOT shipped inside the plugin) that will
derive Codex/OpenCode artifacts from the Claude-authoritative command/agent prose.
**Phase 1 ships only the foundation: a byte-preserving partitioner IR + the Claude
renderer**, proven by rebuilding the five artifacts byte-for-byte. The OpenCode
renderer landed in Phase 2B-core (below); the Codex renderer is still a stub
(`NotImplementedError`).

- `build/extract.py` partitions an artifact's exact decoded text into typed
  `Segment`s (neutral prose vs. tagged harness tokens); `build/build.py` is a pure
  fold that renders each segment via a harness adapter (`build/adapters.py`) and
  concatenates. For Claude the round-trip is byte-identical by construction (only
  the `CORE_ROOT` canonical renderer can break it — a small, tested surface).
- CLI: `python3 build/build.py --harness=claude --mode={check,write}`. `check`
  (default) rebuilds in memory and diffs vs. on-disk **without writing** (exit 0
  identical / 1 drift / 2 error) — this is the anti-drift gate that protects the
  authoritative files. `write` rewrites in place only when bytes differ.
- Inventories: `build/TOKENS.md` (the 8 token categories + counts) and
  `build/PROSE_COUPLING.md` (the structured register of harness-coupled *prose* —
  parallel-Task fan-out, the Write-safety-net, AskUserQuestion fallbacks — that
  later renderers must rewrite, not just re-tokenize). See
  `build/ADR-0001-artifacts-are-prompts.md` for why prose, not only tokens, is the
  rewrite surface.
- Tests: `python3 -m unittest discover -s build/tests`. The `.githooks/pre-commit`
  hook runs `build --mode=check` + the build suite (fast); the ~1219 engine suite
  stays manual (no CI — see "No CI — validation is local").

### Multi-environment build (Phase 2B-core: OpenCode derivation)

The OpenCode renderer adds a **second, coarser IR layer** alongside the Phase-1
token partition: `build/sections.py` splits the *same* artifact text into `### N`
**sections** (independent of the token partition; both stay byte-faithful). Claude
is untouched — it keeps the token fold (`build`) and is byte-identical; only
OpenCode walks sections (`build_sectioned`). A guard test asserts `ClaudeAdapter`
has no `render_section`, so Claude can never enter the section path.

- **Coupling is pin-driven.** A section is *coupled* iff it contains a
  `PROSE_COUPLING.md` pin (`build/prose_coupling.py` loads them). Coupled sections
  are replaced by an authored template under
  `harness/opencode/sections/<artifact>/<section_anchor>.md` (one per section, keyed
  by `(artifact_basename, section_anchor)`); neutral sections are token-rendered.
  `task_block` and `labeled-block AskUserQuestion` tokens are *completeness guards*
  (`assert_coupling_guards`) — they must sit inside a coupled section or the build
  errors. A bare `AskUserQuestion` *prose-mention* token-renders to a neutral phrase.
- **Token rendering** (`OpenCodeAdapter`, `build/adapters.py`): `${CLAUDE_PLUGIN_ROOT}`
  → `${FR_SECURITY_CORE_ROOT}`; `$ARGUMENTS` kept verbatim (OpenCode commands support it
  natively); **both command and agent frontmatter → synthesized `description`-only
  block** (≤1024, re-quoted/escaped) — an OpenCode agent needs a `description` to
  register under `--agent <name>`; the model comes from the dispatcher's `-m <tier>`,
  not artifact text (2B-pkg corrected the earlier "strip agent frontmatter" choice);
  `mcp__…` → neutral phrase; sibling-artifact `*.md` file refs have their `.md`
  stripped (broken in a standalone skill).
- **Structural gates** (`build/gates.py`, no byte oracle for non-Claude): no-leak
  (Claude-specific subset of `tokens.REGISTRY` — CORE_ROOT/Task/AUQ/MCP — so the bare
  `Task subagent_type=` form is caught; `$ARGUMENTS` is *not* a leak), `allowed-tools`/
  `argument-hint` forbidden only in the synthesized frontmatter, a positive xref gate
  (no `security-*.md` survives), determinism (two builds identical), and a
  template↔dispatcher assertion (every dispatch template wires `opencode run` +
  `--agent <name>` + `-m`, strengthened in 2B-pkg from the old `opencode run`-substring
  check). All run in `build --harness=opencode --mode=check`; `--mode=write` re-gates
  before emitting to `dist/opencode/` (gitignored).
- **Scope.** 2B-core is build-time only — it proves the *derivation mechanism*
  structurally. Live `opencode run` smoke (semantic parity) is 2C; bundling
  bin+checklists, `opencode.json` scoped perms, and `adapter.json` are 2B-pkg. The
  templates wire `dispatch.py` with `--allow-gaps` (strict mode would abort the whole
  fan-out on one crashed worker); note the shipped `dispatch.py` CLI does not auto-invoke
  `recover_capture`, so the OpenCode safety-net recovery is an orchestrator step (read
  the capture, Write the wave file), mirroring the Claude harness.

### Multi-environment build (Phase 2B-pkg: OpenCode bundle)

2B-pkg turns the derived texts into a self-contained, installable bundle
`dist/opencode/` (gitignored) via `build/bundle.py` + the `--out` path in `build.py`.
Build-time only — live `opencode run` smoke (semantic parity) remains 2C.

- **Topology.** `dist/opencode/` = `core/{bin,checklists}` (= `${FR_SECURITY_CORE_ROOT}`) +
  `commands/{security-project,security-changes}.md` + `agents/{security,security-recon,
  security-refute}.md` + authored `opencode.json`/`adapter.json`/`INSTALL.md` + a
  `.fr-opencode-bundle` sentinel. **Orchestrators are OpenCode _commands_** (flat
  `commands/<name>.md`, invoked `/name` with `$ARGUMENTS`); **workers are _agents_**
  (`agents/<name>.md`, dispatched `opencode run --agent <name>`). This corrected the
  provisional 2B-core `skills/<name>/SKILL.md` topology (verified against OpenCode
  1.17.10 docs + binary: skills are a distinct on-demand primitive).
- **Shared core + env var (`${FR_SECURITY_CORE_ROOT}`).** The engine is copied **once** into
  `core/` and both commands + all agents reference `${FR_SECURITY_CORE_ROOT}` — a plain shell
  variable the operator exports (OpenCode has no `${CLAUDE_PLUGIN_ROOT}`-style
  substitution). The dispatcher forwards it as `--core-root` → `core_root=` to each
  worker. `bundle_core` copies `bin/` (minus `tests/`/`__pycache__`/`.pyc`/`.DS_Store`)
  + `checklists/` via a sorted walk → byte-deterministic; the PHP sandbox
  (`recon/extract_php_metadata.php`) is included.
- **Authored static configs** live under `harness/opencode/` (beside `sections/`) and
  are copied verbatim (build is a copier+renderer, not a config generator).
  `adapter.json` = the §4 per-harness manifest (`entrypoint_kind:"command"`,
  `fanout:"external_process"`, `worker_invocation`, `model_discovery_cmd:"opencode
  models"`, …; metadata, not read by OpenCode at runtime). `opencode.json` = scoped
  perms: `external_directory`/`bash`/`read`/`edit` allow (runtime paths outside the
  worktree; headless can't answer `ask`), `task:"deny"` (encodes AD4: no in-process
  fan-out), `webfetch`/`websearch:"deny"` (offline auditor).
- **Write path is guarded + rename-aside atomic.** `build --harness=opencode
  --mode=write --out=<dir>` validates configs → builds into a staging dir beside
  `<out>` → moves any existing bundle aside → swaps staging in → deletes the old
  (a crash leaves *either* the old or new tree, never partial). `_guard_out` refuses
  to overwrite anything that is not under the repo's `dist/`, an authored source tree,
  or a dir carrying the `.fr-opencode-bundle` sentinel (the `--review-root=src`
  incident class; the sentinel is a dedicated dotfile, **not** `adapter.json`, which is
  a tracked source name). `--out` is opencode-only (no-op for claude); `--artifact` is
  rejected in opencode write (a bundle must be complete). `validate_static_configs`
  runs in **both** modes — `check` vets the in-git authored files, `write` is
  fail-closed. `dist/` is gitignored; tests build into a tmp `--out`, never the real dist.

### Multi-environment build (Phase 3A-core: Codex derivation)

Codex is the **second** derived harness over the *same* section IR as OpenCode
(`build/sections.py` + the same `PROSE_COUPLING.md` pins + the same 12 coupled
`(artifact, anchor)` pairs + `DISPATCH_ANCHORS`). 3A-core is build-time only — it
proves the derivation *mechanism* structurally; bundle/manifest/`dist/codex`/live
`codex exec` are 3B-pkg / 3C. Claude stays byte-identical (token fold, never the
section path).

- **Token rendering** (`CodexAdapter`, `build/adapters.py`) — diverges from OpenCode
  on four tokens: `${CLAUDE_PLUGIN_ROOT}`→`${FR_SECURITY_CORE_ROOT}` (same); **`$ARGUMENTS`→a
  neutral phrase** (Codex has NO `$ARGUMENTS` substitution, unlike OpenCode commands —
  so it also JOINS the no-leak set); **command frontmatter→a *skill* block (`name`
  from the artifact stem + `description`)** (OpenCode = description-only); **agent
  frontmatter→stripped** (a Codex worker is a plain read-follow file, no registration);
  MCP/AUQ→the same neutral phrases (`MCP_PHRASE`/`AUQ_PHRASE`). Xrefs use
  `_strip_codex_xrefs` — it strips **only** the two ORCHESTRATOR refs
  (`security-project.md`/`security-changes.md`), and **preserves** agent read-follow
  refs (`agents/*.md`, `security-recon.md`…) because for Codex those are REAL bundled
  files a worker opens under `${FR_SECURITY_CORE_ROOT}/agents/` (C1). The skill `name` reaches the
  `_splice` frontmatter via instance state set in `render_section` (the frontmatter
  lives in the uncoupled `_preamble`, which has no ctx).
- **Read-follow worker contract.** Codex has no named agents: `codex exec [PROMPT]`
  reads instructions from its arg. Each dispatch template names an exact bundled
  `agents/<role>.md` + "read and follow it" + the per-role inputs (the analog of
  OpenCode's `--agent <name>`). Worker prose lands at `core/agents/<role>.md` (under
  `${FR_SECURITY_CORE_ROOT}`, 3B). In the **fan-out** `--worker-cmd-template` the path uses the
  `dispatch.py` `{core_root}` placeholder — `${FR_SECURITY_CORE_ROOT}/agents/…` would raise
  `str.format` KeyError before any process launches (E-C10); recon/refute role
  templates use `<FR_SECURITY_CORE_ROOT>`-style slots the orchestrator pre-substitutes. Inputs are
  authored **flag-free `key=value`** (`console_mode=` / `exclude=` / `diff_files=`),
  the read-follow agent maps them to `recon_inventory.py` flags — no leading-`--` CLI
  collision (the OpenCode 2C `--` incident class).
- **Structural gates** (`build/gates.py`, additive — OpenCode's gates unchanged, R-C3):
  `check_codex_output(text, *, is_skill)` = no-leak over `CODEX_FORBIDDEN_CATS`
  (+`$ARGUMENTS`) + frontmatter (skills positively assert non-empty `name`+`description`
  and no `allowed-tools`/`argument-hint`; agents must NOT carry a leading `---` block,
  E-C3) + codex-xref (only orchestrator refs are a violation). `check_codex_dispatch_template`
  asserts `codex exec` + `-m` + `--add-dir` (the composite-repo write invariant, M1-DS)
  + a bundled `agents/<role>.md` read-follow ref (NOT `--agent`) + no `${FR_SECURITY_CORE_ROOT}/agents/`.
  Both run in `build --harness=codex --mode=check` (exit 0 clean / 1 gate / 2 error);
  `--mode=write` builds the bundle (Phase 3B-pkg below). Templates live under
  `harness/codex/sections/<artifact>/<anchor>.md` (same 12 anchors as `harness/opencode/
  sections/`, authored fresh). The pre-commit hook gates all three harnesses'
  `--mode=check` (claude byte-identity + opencode + codex structural gates).

### Multi-environment build (Phase 3B-pkg: Codex bundle)

3B-pkg turns the 3A-core derivation into a self-contained, installable **self-hosted
Codex marketplace bundle** `dist/codex/` (gitignored) via a codex path in `build/bundle.py`
+ the `--out` write path in `build.py`. Build-time only — live `codex exec` smoke (semantic
parity) is 3C. Mirrors the OpenCode 2B-pkg bundle but diverges in topology (a marketplace
ROOT + `.codex-plugin` + skills + read-follow agents under `core/`).

- **Topology.** `dist/codex/` = the dir handed to `codex plugin marketplace add` (a marketplace
  ROOT): a bundle-root sentinel `.fr-codex-bundle` + `.agents/plugins/marketplace.json` +
  `plugins/fr-security-review/{.codex-plugin/plugin.json, skills/{security-project,security-changes}/
  SKILL.md, core/{bin,checklists,agents/{security,security-recon,security-refute}.md}, adapter.json,
  INSTALL.md}`. **Orchestrators are Codex _skills_** (`skills/<name>/SKILL.md`, name+description
  frontmatter); **workers are read-follow files under `core/`** (`core/agents/<role>.md`, frontmatter
  stripped) — placed under `${FR_SECURITY_CORE_ROOT}` so the dispatch templates' `{core_root}/agents/<role>.md`
  (fan-out) and `<FR_SECURITY_CORE_ROOT>/agents/<role>.md` (recon/refute) resolve. This is the deliberate
  divergence from OpenCode's top-level *registered* `agents/`. The `<plugin-name>` is read once from
  the authored `plugin.json.name` and gate-reconciled with the marketplace entry name / `source.path`.
- **Manifest gate = stdlib mirror.** The authoritative Codex `validate_plugin.py` imports PyYAML
  (non-stdlib) + is codex-tooling-local, so `build/codex_manifest.py` re-implements its manifest +
  marketplace + skill-frontmatter shape checks in pure stdlib: allowed top-level keys, strict-semver
  `version`, `author.name`, `interface` (displayName/shortDescription/longDescription/developerName/
  category non-empty + `capabilities` array-of-strings + `defaultPrompt|default_prompt` present),
  recursive `[TODO:` reject, `skills` normalizes to `"skills"`. The **oracle covers only the plugin
  manifest + skills** (the real validator never reads a marketplace file), so DoD pins that half with a
  **durable skip-if-PyYAML-absent test** that runs the REAL `validate_plugin.py` on the emitted bundle,
  and the marketplace half is anchored by a golden-shape test. `interface.defaultPrompt` is authored as
  an **array** (spec + all bundled manifests use one; the validator only existence-checks it).
- **Authored static configs** under `harness/codex/` (`plugin.json`, `marketplace.json`, `adapter.json`,
  `INSTALL.md`) are copied verbatim (copier, not generator). `validate_codex_configs` runs in **both**
  modes — `check` vets the in-git files, `write` is fail-closed. `adapter.json` (§4) diverges from
  opencode's: `entrypoint_kind:"command"`→**`"skill"`**, `worker_invocation` is a `codex exec` string
  (checked by `check_codex_dispatch_template`, not the opencode one), `model_discovery_cmd:"codex debug
  models"`, `permission_config:null` (Codex has no `opencode.json`-style perm file — the offline posture
  rests on the `codex exec -s workspace-write` sandbox default, documented in INSTALL.md, verified at 3C).
- **Write path** = the OpenCode rename-aside atomic swap: `build --harness=codex --mode=write
  --out=dist/codex` validates configs + runs codex gates on every rendered artifact → builds a staging
  tree beside `--out` (both roots: marketplace + plugin) → asserts every `agents/<role>.md` a dispatch
  template reads was actually emitted (fail-closed) → `_guard_out` (now marker-parametrized, defaulting
  to the opencode sentinel so the existing caller is untouched; protects `harness/codex` too, and refuses
  an `--out` carrying the OTHER harness's sentinel) → swaps. `bundle_core` is reused verbatim and already
  appends `core/` (so the write passes the plugin dir, not `.../core`). `--artifact` is rejected in codex
  write; `--out` defaults per harness (`dist/codex` vs `dist/opencode`) and is ignored for claude. Build
  is byte-deterministic (`diff -r` of two writes empty). **Reinstalling an already-installed plugin needs
  a cachebuster version bump + re-`codex plugin add` — a documented 3C step (done on a smoke copy so the
  committed `plugin.json` stays a clean semver), not a build change.**

### Multi-environment runtime (Phase 2A: shared helpers)

Stdlib-only helpers under `security-review/bin/shared/` (a subpackage like
`bin/dedupe/`, so it bundles with the engine and rides the engine test suite — NOT
repo-top `shared/`). These are the harness-neutral foundation the **Codex/OpenCode**
SKILLs will invoke as staged stage-commands; **Claude does not use them** (native
`Task` fan-out). Phase 2A ships the helpers fully unit-tested; no harness artifact /
SKILL derivation / live CLI yet (those are Phase 2B/2C).

- `shared/model_resolver.py` — AD7 model resolution: `discover → propose → confirm →
  persist` a `{high, fast}` tier map (`LABEL_TO_TIER = {opus→high, sonnet→fast}`).
  Discovery is shape-sniffed (codex JSON `.models[].slug` vs opencode `provider/model`
  lines), `shlex`-split, sorted; proposal ranks by name pattern (fast-first, so
  `pro-lite`→fast) with context-window/provider tiebreak; persists
  `<review_root>/.model_map.json`. CLI is **non-interactive by default**;
  `--interactive` binds a stdin checkpoint. The Claude path (`discovery_cmd=None`)
  returns the static `{high: opus, fast: sonnet}` and never persists.
- `shared/dispatch.py` — AD4 external-process fan-out: `dispatch_waves` launches one
  worker per plan slice (≤6 concurrent via `ThreadPoolExecutor`) and `dispatch_role`
  runs one process for recon/refute. **Freshness protocol (AD-2A8):** planned slices'
  wave files are deleted before fan-out, so a stale prior-run file + a crashed worker
  is still a gap. Gaps are classified two-step — a fresh `waves/<slice_id>.md` is
  success regardless of exit/timeout, else `timeout > crash > missing_write`.
  `--allow-gaps` (`strict=False`) writes `dispatch_gaps.json`; a clean run clears any
  stale one. `recover_capture` must **materialize** recovered text to the wave file
  (the worker→file contract is the only thing dedupe reads).
- `shared/contracts.py` — typed seams: `Roots`, `RunResult`, the `Runner` /
  `WaveCommandBuilder` / `RoleCommandBuilder` / `RecoverCapture` / `Checkpoint`
  callables, and `DispatchConfigError` / `DispatchGapError` / `ResolverError`.
  Subprocess is the **single injected seam** — every test passes a fake runner; no
  test spawns a real `opencode`/`codex`.
- Engine delta: `dedupe_findings.py --dispatch-gaps=<path>` folds wave-dispatch gaps
  into REPORT.md's `## Coverage Gaps` (alongside `console_gap`) and surfaces a
  prominent **INCOMPLETE** marker; with zero wave files but recorded gaps it renders a
  minimal INCOMPLETE report instead of erroring out.

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
