---
description: "Security review of changes in the current branch relative to master — with reverse-grep and forward-grep heuristics to surface regressions. Artifacts go to `security-review-{label}/`."
argument-hint: "[--label=<x>] [--review-root=<out-dir>] [--project-root=<path>] [--interactive] [--skip-recon] [--force-skip-recon] [--all-opus] [--no-console] [--console-cmd=<template>] [--exclude=<csv>]"
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Task
  - Bash(git rev-parse *)
  - Bash(git ls-files *)
  - Bash(git diff HEAD*)
  - Bash(git diff origin/*)
  - Bash(git diff main*)
  - Bash(git diff master*)
  - Bash(git diff --diff-filter=D *)
  - Bash(git diff --merge-base *)
  - Bash(git status *)
  - Bash(git log *)
  - Bash(git -C *)
  - Bash(ls *)
  - Bash(mkdir *)
  - Bash(rm *)
  - Bash(mv *)
  - Bash(cat *)
  - Bash(printf *)
  - Bash(test *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/bin/*.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/bin/recon/*.py *)
  - AskUserQuestion
---

You are the orchestrator of a security review for the current branch diff. Recon, reverse-grep, forward-grep, parallel workers in `mode=changes`, deterministic dedup.

## ARGUMENTS

Parse flags from `$ARGUMENTS`:

- `--label=<x>` — orchestrator label, forms `<review_root> = security-review-{label}` relative to cwd. If the flag is not passed — do **self-introspection** (see step 0).
- `--review-root=<out-dir>` — override of the **review-root output directory** (artifacts: `CONTEXT.md`, `waves/`, `REPORT.md`). For Docker/CI/firejail isolation. Accepts a relative path (resolved from cwd) or absolute. If set — `--label` is ignored. **This flag does NOT specify what to scan** — use `--project-root=<path>` to point at a non-cwd project (the diff itself limits scope for this command).
- `--project-root=<path>` — corner of the audited project (where `composer.json` / framework configs live). Defaults to `cwd`. Use in composite repos where CLAUDE.md / cwd is one directory above the actual project root (for example monorepo with `api/` PHP subproject + shared top-level CLAUDE.md). Recon, exclude paths, sanity coverage, and refute path normalization all resolve against this value. Accepts a relative (from cwd) or absolute path.
- `--interactive`, `--skip-recon`, `--force-skip-recon`, `--all-opus` — as in `security-project`. By default W4/W5 on sonnet (balanced profile); `--all-opus` forces opus everywhere.
- `--no-console` — static-only recon: the utility does NOT run the project's console. Use when auditing hostile/untrusted repos, when runtime credentials are absent, or in CI scenarios. Ceiling=medium (intentionally). Alternative — isolation via firejail/Docker without the flag.
- `--console-cmd=<template>` — explicit command for running the project console (e.g. `--console-cmd="docker compose exec -T php php bin/console"`) when the project runs inside a container. May contain a `{args}` placeholder for Makefile passthrough; otherwise the subcommand is appended. When neither this nor `--no-console` is passed and the project looks containerized, **step 4c asks interactively** instead of silently degrading. `--no-console` wins. **On the derived Codex/OpenCode harnesses** a space-containing value here is truncated by the whitespace-split argument contract — set the console command via the `FR_SECURITY_CONSOLE_CMD` environment variable instead (e.g. `frsr --console-cmd "…"`), which step 4c honors.
- `--exclude=<csv>` — additional path prefixes (relative to `<project_root>`) that will NOT be parsed by the PHP extractor (see semantics in `security-project.md`). Combined with whatever is found in `<project_root>/CLAUDE.md` in step 4a.
- `--no-adversarial` — disable the adversarial refute pass (ON by default). Semantics and contract — as in `security-project.md` (see step 12.5 below).
- `--exploratory` and `--scope=` for diff mode are **not supported** — the diff itself limits the scope.

## STEPS

### 0. Resolve label, review_root, project_root

#### 0.1. Resolve `REVIEW_ROOT`

**If `--review-root=<path>` is set** (absolute or relative):

1. Resolve the path relative to cwd, if it is relative. Always convert to **absolute** form (no `.`, no `..`, no symlinks left unresolved).
2. Set `REVIEW_ROOT = <resolved absolute path>`.
3. `--label` (if any) is **ignored** — the path is explicit.

**Otherwise**, if `--label=<x>` is set:

1. Normalize `<x>` to the dictionary `claude | codex | gemini | deepseek | qwen | other-<short>` (kebab-case, ≤ 16 characters).
2. `REVIEW_ROOT = security-review-<x>`, then resolve to **absolute** relative to cwd.

**Otherwise** (neither `--review-root` nor `--label`):

Do **self-introspection**: determine your model and the harness you are running in, and pick `{label}` from the dictionary:

| Harness / CLI       | label      |
|---------------------|------------|
| Claude Code (Anthropic)             | `claude`     |
| Codex CLI (OpenAI)                  | `codex`      |
| Gemini CLI (Google)                 | `gemini`     |
| DeepSeek CLI                        | `deepseek`   |
| Qwen CLI (Alibaba)                  | `qwen`       |
| Any unrecognized model/CLI          | `other-<short>` (≤ 16 characters, kebab-case) |

Level — **harness/CLI**, not the exact model. `claude-opus-4-7` vs `claude-sonnet-4-6` is not our concern — what matters is only protection against collisions between parallel runs of **different** models on the same project.

`REVIEW_ROOT = security-review-<label>`, resolved to **absolute** relative to cwd.

**Known limitation.** Open-weight fine-tunes may erroneously report themselves as Claude (SFT artifact). If confidence is low — the user will have to pass `--label` explicitly.

#### 0.2. Resolve `PROJECT_ROOT`

**If `--project-root=<path>` is set:** resolve to absolute (relative paths resolve from cwd). Set `PROJECT_ROOT = <resolved absolute path>`. If the resolved path is not an existing directory — abort with a clear error.

**Otherwise:** `PROJECT_ROOT = <cwd, absolute>`.

**Then verify `PROJECT_ROOT` is a git repository** (this command is diff-driven; without git we cannot compute the base diff):

```bash
git -C "<PROJECT_ROOT>" rev-parse --git-dir > /dev/null 2>&1
```

If it fails — abort with: `ERROR: --project-root=<path> is not a git repository. /security-changes requires git to compute the diff against the base branch.`

#### 0.3. Validate `REVIEW_ROOT` (sanity guard against misuse)

`--review-root` is for **output artifacts**, not for narrowing the audit. Abort with the error message below if any of these hold:

- the resolved `REVIEW_ROOT` already exists as a non-directory (regular file, symlink to file, special file) — `mkdir -p` in Step 1 would fail downstream, **or**
- the resolved `REVIEW_ROOT` equals `PROJECT_ROOT` exactly, **or**
- the resolved `REVIEW_ROOT` is a subpath of `PROJECT_ROOT` AND its **basename** does **not** start with `security-review` (`security-review`, `security-review-claude`, `security-review-foo`, etc.), **or**
- the resolved `REVIEW_ROOT` basename is one of the known source-tree / framework directory names (case-insensitive): `src`, `app`, `lib`, `source`, `tests`, `test`, `spec`, `vendor`, `node_modules`, `public`, `web`, `bin`, `config`, `assets`, `resources`, `var`, `storage`, `templates`, `views`, `database`, `migrations`, `seeders`, `scripts`, `routes`, `build`, `dist`, `target`, `out`, `coverage`, `.next`, `.nuxt`, `__pycache__`.

Error message:

```
ERROR: --review-root=<path> looks like a project source directory or the project root itself.
This flag specifies WHERE the review WRITES its artifacts (CONTEXT.md, waves/, REPORT.md, .gitignore=*),
NOT what to scan.

  • For diff-mode the scope is limited by the diff itself — no scope flag is needed.
  • To point at a non-cwd project (composite repos) — use --project-root=<path>.
  • Default review root is security-review-<label>/ inside cwd; usually no flag is needed.

If you really want to write into <REVIEW_ROOT>, rename it to start with `security-review`
(e.g. `security-review-staging`) and re-run.
```

#### 0.4. Absolute-path invariant

After step 0 is complete, **all subsequent references to `<REVIEW_ROOT>` and `<PROJECT_ROOT>` MUST use the resolved absolute paths**. Do not re-derive them from the original flag values, do not pass relative forms to subagents (`Task(...)`), and do not let `cd` between steps change their meaning. Subagents inherit cwd from the orchestrator, but they may resolve paths in a different working directory — only absolute strings are safe to forward.

After resolution **print to the user**:

```
review_root:  <REVIEW_ROOT> (label: <label or "explicit override">)
project_root: <PROJECT_ROOT>
```

### 1. Ensure review_root layout

Create the directory and local `.gitignore` (content: a single line `*`) idempotently:

```bash
mkdir -p "<REVIEW_ROOT>"
test -f "<REVIEW_ROOT>/.gitignore" || printf '*\n' > "<REVIEW_ROOT>/.gitignore"
mkdir -p "<REVIEW_ROOT>/waves"
```

### 2. Legacy v1 detection (warning, not abort)

If an **old** `SECURITY_CONTEXT.md` is detected (probe both `<cwd>` and `<PROJECT_ROOT>`):

```bash
test -f "<cwd>/SECURITY_CONTEXT.md"          && echo "found-at-cwd"
test -f "<PROJECT_ROOT>/SECURITY_CONTEXT.md" && echo "found-at-project-root"
```

If either probe succeeds → print a warning, **do not touch the file**. Name the location:

```
⚠️  Legacy v1 detected: SECURITY_CONTEXT.md at <found_path> (schema v1)
    The file is not modified. Fresh recon will be written to <REVIEW_ROOT>/CONTEXT.md.
```

### 3. Determine base branch and diff

All git commands run with `-C "<PROJECT_ROOT>"` so they target the audited project's repository, not whatever git the orchestrator's cwd happens to be in (critical for composite repos with `--project-root`).

```bash
# Try origin/master, then origin/main, then master, main
BASE_BRANCH=$(git -C "<PROJECT_ROOT>" rev-parse --verify origin/master 2>/dev/null \
  || git -C "<PROJECT_ROOT>" rev-parse --verify origin/main 2>/dev/null \
  || git -C "<PROJECT_ROOT>" rev-parse --verify master 2>/dev/null \
  || git -C "<PROJECT_ROOT>" rev-parse --verify main 2>/dev/null)
```

Get the list of changed files. Paths in the output are **`PROJECT_ROOT`-relative** (matching the format that recon uses inside `CONTEXT.md`):

```bash
git -C "<PROJECT_ROOT>" diff ${BASE_BRANCH}...HEAD --name-only > "<REVIEW_ROOT>/diff_files.txt"
```

If the diff is empty — abort with the message "No changes relative to the base branch".

### 4. Clean up artifacts

```bash
rm -f "<REVIEW_ROOT>/waves/"*.md
if [ -f "<REVIEW_ROOT>/REPORT.md" ]; then
    mv "<REVIEW_ROOT>/REPORT.md" "<REVIEW_ROOT>/REPORT.prev.md"
fi
rm -f "<REVIEW_ROOT>/waves/"*.pre-retry.md
```

`<REVIEW_ROOT>/.findings_state.json` (snapshot of the previous run for cross-run diff) is **not cleaned** — dedupe will read it before writing REPORT.md and overwrite it at the end. The diff (New / Recurring / Closed) appears in the Executive Summary automatically.

### 4a. Collecting the exclude list (CLAUDE.md + flag)

Same as `security-project.md` step 3a: read **both** `<cwd>/CLAUDE.md` **and** `<PROJECT_ROOT>/CLAUDE.md` (if `PROJECT_ROOT != cwd` — these are two distinct files, common in monorepos with a top-level CLAUDE.md and a subproject-specific one). Find sections of the form `## Code review exclusions` (or equivalent), extract path prefixes. Combine with the orchestrator's `--exclude=<csv>`.

**Path semantics.** All paths (from either CLAUDE.md and the `--exclude` flag) are interpreted as **`PROJECT_ROOT`-relative**. The orchestrator does **NOT** strip any prefix; users must write project-root-relative paths. If a path does not resolve to an existing directory inside `PROJECT_ROOT`, skip it with a one-line warning that names its source file. The result — `EXCLUDE_CSV`. The built-in `DEFAULT_EXCLUDE` is applied by the utility itself.

If something was taken from CLAUDE.md or the flag — print a line (mention which file the entries came from when both were read):

```
Exclude (CLAUDE.md @ <cwd>):          <list or "none">
Exclude (CLAUDE.md @ <PROJECT_ROOT>): <list or "none">   # only if PROJECT_ROOT != cwd
Exclude (--exclude flag):             <list or "none">
Exclude (skipped, outside PROJECT_ROOT): <list or none>  # warnings for entries that didn't resolve
```

### 4b. Detect removed defenses in diff

The goal — find in the diff removed lines that were `denyAccessUnlessGranted`, `#[IsGranted]`, `middleware('auth')`, CSRF enables, and similar defensive constructs. If a defense was removed — the security review should pay special attention to the controller / route / method losing the defense, and its consumers.

#### 4b.1. Collect the full diff

```bash
git -C "<PROJECT_ROOT>" diff "${BASE_BRANCH}...HEAD" -- '*.php' '*.yaml' '*.yml' '*.blade.php' \
  > "<REVIEW_ROOT>/full_diff.patch"
```

#### 4b.2. Regex scan of removed defenses

Run the `diff_removed_defenses.py` utility — it applies tightened regex to removed lines (prefix `-`) and writes JSON with category, file, line number in the OLD version, and pair-detection label:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/diff_removed_defenses.py \
  "<REVIEW_ROOT>/full_diff.patch" \
  > "<REVIEW_ROOT>/removed_defenses.json"
```

Covered categories (source of truth — `bin/diff_removed_defenses.py::REMOVED_DEFENSE_PATTERNS`):

| Category (`pattern_matched`) | What is detected |
|---|---|
| `symfony_attr_isgranted` | `#[IsGranted(...)]` attribute |
| `symfony_call_denyaccess` | `denyAccessUnlessGranted(...)` call |
| `laravel_blade_can` | blade directive `@can(...)` |
| `laravel_can_with_string` | `->can('string')` (filters out `$collection->can()` without argument) |
| `laravel_authorize` | `->authorize(...)` / `Gate::authorize(...)` |
| `laravel_gate_define` | `Gate::define(...)` / `Gate::before(...)` (policy removal) |
| `middleware_auth_single` | `->middleware('auth')` (string argument) |
| `middleware_auth_array` | `->middleware([..., 'auth', ...])` (array) |
| `middleware_throttle_single` / `_array` | `throttle:N,M` (rate limit) |
| `symfony_csrf_protection` | `'csrf_protection' => true` (CSRF enable) |
| `hash_equals` | timing-safe compare |
| `random_secure` | `random_bytes` / `random_int` |

**Pair detection** (refactor, not removal). The utility automatically sets `added_equivalent_detected: true` if within a ±10-line radius of THE SAME file an added (`+`) line with an equivalent defense is found (see `_EQUIVALENCE_BUCKETS` in the module). Such entries the orchestrator must NOT include in `--extra-target-files` — this is a refactor; the controller is still protected.

#### 4b.3. Structural detection: Voter/Policy/Middleware files removed entirely

Find files removed entirely by this diff:

```bash
git -C "<PROJECT_ROOT>" diff --diff-filter=D --name-only "${BASE_BRANCH}...HEAD" \
  > "<REVIEW_ROOT>/deleted_files.txt"
```

For each removed file:

1. **Classify kind**: voter / policy / middleware. Source of truth:
   - **If** `<REVIEW_ROOT>/CONTEXT.md` from the **base branch** exists (for example, a past run saved `CONTEXT.prev.md`) — look at the sections `recon_bags.stack.symfony.voters`, `recon_bags.stack.laravel.policies`, `recon_bags.stack.laravel.middleware_groups` and match the path.
   - **Otherwise** (CONTEXT base unavailable) — fallback by naming heuristic: `*Voter.php`, `*Policy.php`, `*Middleware.php`. Document in the output that the fallback fired.

2. **Collect consumers** of these classes through the built-in `Grep` tool. Search inside `<PROJECT_ROOT>`, not in the orchestrator's cwd (in composite repos these differ):

   ```
   Grep(pattern="use App\\\\Security\\\\<ClassName>;", path="<PROJECT_ROOT>", glob="*.php", output_mode="files_with_matches")
   Grep(pattern="<ClassName>::", path="<PROJECT_ROOT>", glob="*.php", output_mode="files_with_matches")
   ```

   (Do not use shell `grep -rn` — `Bash(grep:*)` is not in allowed-tools.)

3. Augment `<REVIEW_ROOT>/removed_defenses.json` with a `removed_files` block:

```json
{
  "removed_defenses": [...],
  "removed_files": [
    {
      "file": "src/Security/PostVoter.php",
      "kind": "voter",
      "consumers": ["src/Controller/PostController.php", "src/Controller/Admin/PostAdminController.php"]
    }
  ]
}
```

(The utility from 4b.2 writes only `removed_defenses`. The `removed_files` block is added by the orchestrator manually on top.)

#### 4b.4. Forwarding to plan_waves

Assemble the candidate file list for `--extra-target-files`:

- from `removed_defenses[]` — the `file` field of each entry **where `added_equivalent_detected != true`** (refactor pairs are skipped);
- from `removed_files[].consumers` — all consumer files.

Deduplicate, pass as CSV to `plan_waves.py` in step 9.

`plan_waves.py --extra-target-files=<csv>` will add these files to `target_files` of all waves (including WINF, if `--exploratory` is requested). This guarantees that workers look at the consumers of the removed defense, even if the consumer files themselves are not in the diff.

Print a summary to the user:

```
Removed defenses: <N entries>
  - genuine removals: <N>
  - pair-detected refactors (skipped): <N>
Removed defense files (whole-file deletes): <N>
Extra target files for waves: <N> (will be merged into every wave's target_files)
```

### 4c. Resolve console runner (environment-aware)

Identical logic to `security-project` step 3b — decide HOW to run the project console (the only recon step that executes the project), asking the user rather than silently degrading when the project looks containerized. Skip when `--no-console` (wins) / `--console-cmd=<tpl>` was passed (forward it), **when `FR_SECURITY_CONSOLE_CMD` is set in the environment** (a launcher/CI exported the console command out-of-band → set `CONSOLE_CMD = env`, forward no console flag; the utility reads the variable itself — do **not** echo its space-containing value into the prompt), or when `--skip-recon` is taken. Otherwise:

1. Detect the recipe (`recon_inventory.py "<PROJECT_ROOT>" --detect`); console enrichment applies to **Symfony** only — for other recipes proceed with no console flags.
2. Probe: `python3 ${CLAUDE_PLUGIN_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"` (read-only, safe).
3. If `containerized == false` AND `host_php_present == true` → proceed with no console flags (utility auto-selects host).
4. Else → `AskUserQuestion` built from the probe's `suggestions` (**show + confirm** trust model: present the Python-built `docker compose exec -T <service> php bin/console`; for Makefile suggestions show `detail`/recipe body; offer run-on-host, custom command, and skip). Map to `--console-cmd="<chosen>"` or, for skip, `--no-console`.
5. Set `CONSOLE_CMD` and forward it to the recon agent in step 5.

> Non-interactive / CI: do not block — proceed with no flag; the utility records a loud `console_gap` (surfaced in REPORT.md). Pass `--console-cmd`/`--no-console` explicitly in CI.

### 5. Recon phase

Recon collects the inventory **across the whole project** (for full context), but the recipe marks `touched_by_diff: true/false` on applicable items per the list of changed files.

**If `--skip-recon` AND `<REVIEW_ROOT>/CONTEXT.md` exists:** fingerprint validation as in `security-project` (see step 4 there).

**Otherwise:**

Forward `--diff-files=` to the recon agent (it forwards to the utility as-is — see contract in `agents/security-recon.md`). Forward the console decision from step 4c (`CONSOLE_CMD`: `--no-console`, `--console-cmd=<tpl>`, `env` → no console flag since the utility reads `FR_SECURITY_CONSOLE_CMD`, or nothing). If step 4a collected a non-empty `EXCLUDE_CSV` — add `--exclude=<EXCLUDE_CSV>`:

```
Task(subagent_type="security-recon", prompt="""
  project_root: <PROJECT_ROOT>
  review_root: <REVIEW_ROOT>
  --diff-files=<REVIEW_ROOT>/diff_files.txt
  [--no-console | --console-cmd=<tpl>]   # CONSOLE_CMD resolved in step 4c
  [--exclude=<EXCLUDE_CSV>]              # only if 4a collected a non-empty list
""")
```

Both paths are forwarded as **absolute** (per the Step 0.4 invariant).

The `--diff-files=` field is the only signal to the recon agent that `scope=changes` is needed. If the field is passed as `diff_files:` without `--`, recon will silently run in project mode and `touched_by_diff` will NOT be set — the entire mode=changes pipeline will break.

After return — check `RECON_OK`. If `RECON_*_FAILED` is received — abort with a clear error.

Run filesystem coverage sanity-check:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity --project-root "<PROJECT_ROOT>"
```

`--project-root` is required here — without it `validate_context.py` falls back to inferring from `parent(review_root)`, which fails for composite repos (parent has no `composer.json` / `package.json`) and prints `WARNING: project_root not specified and could not be inferred — sanity coverage skipped`. The fallback exists for legacy CLI callers; the orchestrator must always be explicit.

For `changes` mode the sanity is informational: if recon skipped >20% of controllers/handlers/voters/listeners from the filesystem, reverse/forward-grep may not find consumers for changed services. Behavior by threshold ladder — as in `security-project` (warning 5–20 %, error >20 %).

### 6. Summary and optional checkpoint

Print a summary to the user with emphasis on touched items (section names — those present in this CONTEXT.md):

```
Recon complete (recon_confidence: <level>, ceiling: <level>).
Stack: <framework>
Console: <frontmatter.environment.console_mode> <if environment.console_gap: "⚠️ coverage gap — " + environment.console_gap_reason>
Diff touched:
  - attack_surface: <N touched of M total>
  - data_access: <N touched>
  - authz_usage / recon_bags.stack.<stack>.<authz key>: <touched listing>
  - serialization / file_operations / http_clients: <touched listing>
  - secrets / fintech_markers / recon_bags.stack.<stack>.* config: <touched|untouched>
```

If `--interactive` — checkpoint as in `security-project`.

### 7. Reverse-grep (changed service → consumers)

For each changed file in `<REVIEW_ROOT>/diff_files.txt` that **is not** an entry point (controller/command/handler/listener/voter/route-config/security config):

1. Determine the FQN of the class from the file path (PSR-4: `src/Service/PaymentService.php` → `App\Service\PaymentService`).
2. Find FQN usages through the **built-in `Grep` tool** (it is in the orchestrator's allowed-tools, not shell). Use `<PROJECT_ROOT>/src` as the `path` (composite repos: cwd may differ from `<PROJECT_ROOT>`):

   ```
   Grep(pattern="PaymentService", path="<PROJECT_ROOT>/src", glob="*.php", output_mode="files_with_matches")
   ```

3. Additionally — for this class's public methods (if the name is longer than 6 characters OR CamelCase, for example `findByDynamicCriteria`, but not `find`, `get`, `save`):

   ```
   Grep(pattern="->findByDynamicCriteria\\(", path="<PROJECT_ROOT>/src", glob="*.php", output_mode="files_with_matches")
   ```

4. If `mcp__phpstorm__search_symbol` is available — verify results via `{type: "method_call"}` (more accurate than regex over PHP).
5. Found consumers (Controllers, Handlers, Commands) — add to `entry_points_in_scope` of the corresponding waves.

**Important:** do not use shell `grep -rn` — `Bash(grep:*)` is not in this command's allowed-tools. Only the built-in `Grep` tool.

### 8. Forward-grep (changed entry → downstream) — strictly 1 level

For each changed file that **is a PHP entry point** (controller with route attribute, message handler, command, voter, listener):

**Algorithm (4 steps, depth = 1):**

1. **Parse constructor injected types** of the changed file: find `public function __construct(` and extract parameter types (including constructor promotion: `public function __construct(private readonly FooService $foo)`). Map: `property_name → FQN`.

2. **Find in the changed file** via `Grep` tool the pattern `\$this->([a-zA-Z_]+)->([a-zA-Z_]+)\(` → extract pairs `(field_name, method_name)`. Do not use shell grep — `Bash(grep:*)` not in allowed-tools.

3. **Resolve field_name → FQN** via the map from step 1.

4. **Add FQN to `entry_points_in_scope`** of the corresponding waves. If MCP is available — verify via `mcp__phpstorm__search_symbol`.

**Config files (yaml/xml) — forward-grep is not done.** When centralized configs change (for example `config/packages/security.yaml`, `config/routes/*` for Symfony), the recipe will already set `touched_by_diff: true` on corresponding items of sections (`recon_bags.stack.<stack>.firewalls` / `attack_surface` / `authz_usage` / etc.) during recon. The mode=changes worker will take them from CONTEXT.md by contract and trace data flow from them.

**Known limitation (documented in plan):** property injection, service locator, message bus dispatch (`MessageBusInterface` and analogs), chains of services 2+ steps long, `__invoke`, dynamic methods — not covered. For critical reviews `/security-project` in full is recommended.

### 8a. Distribution of consumers across waves (deterministic)

Reverse-grep (step 7) and forward-grep (step 8) gave a list of consumer files to add to `entry_points_in_scope` of the corresponding waves. To remove the LLM heuristic "guess which wave to add to" — call:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/map_consumers_to_waves.py \
  --review-root "<REVIEW_ROOT>" \
  --consumer <path1> --consumer <path2> ...
```

Or via file (convenient with many items):

```bash
printf '%s\n' <path1> <path2> > /tmp/consumers.txt
python3 ${CLAUDE_PLUGIN_ROOT}/bin/map_consumers_to_waves.py \
  --review-root "<REVIEW_ROOT>" \
  --consumers-file /tmp/consumers.txt
```

The utility reads CONTEXT.md, looks for each consumer in `attack_surface` (and recon_bags.stack.<stack>.* sections with `kind`), maps kind → wave_ids via the static inverse index from WAVES. Output:

```json
{
  "src/Controller/Foo.php": {"kind": "http_route", "waves": ["W1", "W2", "W3", "W5"]},
  "src/Service/Bar.php":     {"kind": null, "waves": []}
}
```

When launching workers (step 10) — for each consumer with non-empty `waves`, add its file to `entry_points_in_scope` ONLY for the listed waves. Consumers with `kind: null / waves: []` (not found in inventory) — add to ALL waves as fallback (used to do so for all). This preserves recall on unknown-kind and removes noise for known-kind.

### 9. Wave plan generation

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/plan_waves.py "<REVIEW_ROOT>/CONTEXT.md" \
  --plugin-root="${CLAUDE_PLUGIN_ROOT}" \
  --save-plan="<REVIEW_ROOT>/waves_plan.json" \
  [--all-opus] \
  --diff-files "<REVIEW_ROOT>/diff_files.txt" \
  [--extra-target-files="<csv from step 4b.4>"]
```

`--save-plan` saves the JSON plan for the coverage block in REPORT.md (steps 12 / 12.5.2).

**`--plugin-root` is required** — otherwise workers will not find checklists (the path resolves to the project's cwd, not the plugin's).

`--extra-target-files=<csv>` (optional) — list of consumer files of removed defenses from step 4b.4 (Voter / Policy / Middleware consumers + controllers with removed authz where `added_equivalent_detected != true`). The utility will add these paths to `target_files` of each wave (including WINF), even if the files themselves are not in the diff. This guarantees review of files affected by regression.

The script filters waves (skips those whose slice does not intersect the diff) and adds the `_CHANGES` suffix to slice_id. WINF (exploratory) in diff mode is not launched if there is no intersection of the diff with relevant items.

Print the plan to the user (see the analogous item in `security-project.md`).

### 10. Parallel worker launch in `mode=changes`

For each wave from the plan, additionally feed the reverse/forward-grep entry points found:

```
Task(subagent_type="security", model=<from plan, field "model">, prompt="""
  review_root: <REVIEW_ROOT>
  project_root: <PROJECT_ROOT>
  relevant_section_paths: <from plan>
  checklists: <from plan>
  entry_points_in_scope: <from plan + reverse/forward-grep finds>
  target_files: <from plan (only touched)>
  slice_id: <from plan with _CHANGES>
  mode: changes
""")
```

**Important:** the `model` parameter is passed as a Task call argument, not in the prompt text. The value is taken from the `"model"` field of the JSON plan.

`project_root` is required (per Step 0.4 absolute-path invariant) so the worker resolves `target_files` / `entry_points_in_scope` / paths inside `CONTEXT.md` correctly when `project_root != cwd` (composite repos). Without it the worker reads files relative to cwd and silently misses them in monorepos.

### 10a. Safety net + progress (CRITICAL)

For each Task worker return — same logic as in `security-project.md`:

1. `ls "<REVIEW_ROOT>/waves/<slice_id>.md"` — check existence.
2. If the file is missing — extract markdown from the worker's response (blocks `# Vulnerability ...`) and write it yourself via Write to the absolute path `<REVIEW_ROOT>/waves/<slice_id>.md`.
3. If markdown is also missing — create a stub file with the reason.
4. Print a status line `✓ <slice_id>: ...` or `⚠ recovered` or `✗ failed`.

This is an **always-on** protection against the case where the worker returned findings only in the response message and did not execute Write.

### 11. Reporting criterion (built into the worker's contract)

The worker reports a finding **only if the exploit path contains a changed node**:
- sink in target_files
- OR entry point with `touched_by_diff: true` (in items of CONTEXT.md)
- OR changed authz config / centralized route config / event listener / voter

Hard-wired checks for "security.yaml"/"voter" in the worker **do not exist** — this is a framework-agnostic worker; it takes specifics from `relevant_section_paths` and checklists.

### 11a. Merge pre-retry files (if any)

If `*.pre-retry.md` files remain from previous retries:

```bash
for pre in "<REVIEW_ROOT>/waves/"*.pre-retry.md; do
  [ -f "$pre" ] || continue
  base="${pre%.pre-retry.md}.md"
  if [ -f "$base" ]; then
    cat "$pre" >> "$base"
  fi
done
```

Dedup will handle duplicates.

### 12. Deduplication and summary

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json"
```

Dedup produces a split report: index `<REVIEW_ROOT>/REPORT.md` + folder `<REVIEW_ROOT>/REPORT/` with detail files by `root_cause_family` and `manual_review.md` (including parse-failed findings with the `[PARSE_FAILED]` flag). The index outputs a callout "⚠️ Action required: N" on non-zero manual count. For single-file output — flag `--single-file`.

### 12.5. Adversarial refute pass (optional, on by default)

If the orchestrator was launched with `--no-adversarial` — **skip this step** (then directly to step 13).

#### 12.5.1. Launching the refute wave

Read the `<REVIEW_ROOT>/REPORT.md` index table. Split rows into batches of ≤20 findings (first 20 → batch_index=0, etc.).

For each batch — sequential Task call (parallelism is **forbidden** — the refute agent writes to a single file `<REVIEW_ROOT>/refute.md` in Append mode):

```
Task subagent_type=security-refute prompt="
review_root: <REVIEW_ROOT>
batch_index: <0..N-1>
findings_slice: <markdown slice of REPORT.md index ≤ 20 finding rows>
"
```

Soft timeout 10 minutes per call. If the Task did not return within timeout — the orchestrator prints a warning "adversarial pass partial — N from M findings reviewed" and continues with partial refute.

#### 12.5.2. Apply refute results

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json" \
  --refute "<REVIEW_ROOT>/refute.md" \
  --project-root "<PROJECT_ROOT>"
```

This re-runs dedup and applies refute tags. On output:
- In `REPORT.md`, each refute-marked finding receives a `[REFUTE_CLAIMED]` marker with a `refute_file:refute_line` tail.
- A new file `<REVIEW_ROOT>/REPORT/refute_invalid.md` — refute records that did not pass auto-validation.
- Executive summary shows counters `confirmed / refute_claimed / refute_invalid / manual_review / parse_failed`.

### 13. Output to user

```
Security review of changes complete.
  Index: <REVIEW_ROOT>/REPORT.md
  Details by category: <REVIEW_ROOT>/REPORT/<family>.md
  Base branch: <branch>
  Changed files: <N>
  Uncovered slices: [<list> or none]
```

## PRINCIPLES

- reverse-grep and forward-grep are heuristics; they give ~80% coverage in typical projects with DI by type
- Indirect DI (property injection, service locator, message bus dispatch) is not covered
- For critical reviews — periodically run `/security-project` in full

## Known limitations

- Without a full call graph some regressions through old code may be missed
- Worker retry is absent — on worker crash the slice is marked "not covered"
