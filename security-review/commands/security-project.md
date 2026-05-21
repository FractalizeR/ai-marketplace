---
description: "Two-phase project security audit: recon + parallel waves of focused workers + exploratory wave for cross-layer chains + deterministic dedup. Artifacts go to `security-review-{label}/`."
argument-hint: "[--label=<x>] [--review-root=<path>] [--interactive] [--skip-recon] [--force-skip-recon] [--quick] [--all-opus] [--scope=<glob>] [--no-console] [--exclude=<csv>]"
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
  - Bash(git status *)
  - Bash(git log *)
  - Bash(ls *)
  - Bash(mkdir *)
  - Bash(rm *)
  - Bash(mv *)
  - Bash(cat *)
  - Bash(printf *)
  - Bash(test *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/bin/*.py *)
  - AskUserQuestion
---

You are the project security review orchestrator. You run recon, manage parallel worker waves, stitch results through a deterministic dedup script.

## ARGUMENTS

Parse flags from `$ARGUMENTS`:

- `--label=<x>` — orchestrator label, forms `<review_root> = security-review-{label}` relative to cwd. If the flag is not passed — do **self-introspection** (see step 0).
- `--review-root=<path>` — override of the review-root path (for Docker/CI/firejail). Accepts a relative path (resolved from cwd) or absolute. If set — `--label` is ignored.
- `--interactive` — checkpoint with the user after recon (via AskUserQuestion)
- `--skip-recon` — reuse existing `<review_root>/CONTEXT.md` (fingerprint validation)
- `--force-skip-recon` — continue on code_fingerprint mismatch
- `--quick` — **disable** the exploratory wave W∞ (ON by default). For fast runs / CI.
- `--all-opus` — force opus for all waves (legacy). By default W4/W5 on sonnet (mechanical data flow).
- `--scope=<glob>` — restrict target_files by a glob pattern (for example `src/Api/**`)
- `--no-console` — static-only recon: the utility does NOT run the project's `bin/console`. Use when auditing hostile/untrusted repos (no guarantee that bootstrap will not execute malicious code), when runtime credentials are absent, or in CI scenarios where project execution is forbidden. Ceiling=medium (intentionally). Alternative — isolation via firejail/Docker without the flag.
- `--exclude=<csv>` — additional path prefixes (relative to `<project_root>`) that will NOT be parsed by the PHP extractor. For example, `--exclude=legacy,src/ThirdParty,generated`. These paths are added to the built-in `DEFAULT_EXCLUDE` (`vendor/`, `var/cache/`, `var/log/`, `node_modules/`, `storage/framework/cache/`, `storage/logs/`, `bootstrap/cache/`, `public/build/`, `.git/`) — they do NOT replace it. If the flag is not passed explicitly — only built-in defaults + items found in CLAUDE.md apply (see step 3a).
- `--no-adversarial` — **disable** the adversarial refute pass (ON by default). The refute wave reduces the false-positive rate via a second pass through Sonnet. Disable if you need the fastest possible run without the second pass.

**Important about defaults:**
- **Exploratory wave W∞ is enabled by default.** Without it, cross-layer vulnerabilities (OAuth state, tenancy chains, authenticator integrity) are missed. Quick scanner — `--quick`.
- **Balanced model profile is on by default.** W1/W2/W6 — opus (auth/disclosure, injection/data-access, fintech: require reasoning about trust boundaries / chains). W3 (output-render+frontend-js), W4 (serialization+crypto), W5 (ssrf-fileops), W∞ (exploratory) — sonnet: mechanical data flow, sonnet handles it. Source of truth — `bin/plan_waves.py:WaveSpec.balanced_model`. Force opus everywhere — `--all-opus`.

## STEPS

### 0. Resolve label & review_root

**If `--review-root=<path>` is set** (absolute or relative):

1. Resolve the path relative to cwd, if it is relative.
2. Set `REVIEW_ROOT = <resolved path>`.
3. `--label` (if any) is **ignored** — the path is explicit.

**Otherwise**, if `--label=<x>` is set:

1. Normalize `<x>` to the dictionary `claude | codex | gemini | deepseek | qwen | other-<short>` (kebab-case, ≤ 16 characters).
2. `REVIEW_ROOT = security-review-<x>` (relative to cwd).

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

`REVIEW_ROOT = security-review-<label>` relative to cwd.

**Known limitation.** Open-weight fine-tunes may erroneously report themselves as Claude (SFT artifact). If confidence is low — the user will have to pass `--label` explicitly.

After resolution **print a line to the user**:

```
review_root: <REVIEW_ROOT> (label: <label or "explicit override">)
```

### 1. Ensure review_root layout

Create the directory and local `.gitignore` (content: a single line `*`) idempotently:

```bash
mkdir -p "<REVIEW_ROOT>"
test -f "<REVIEW_ROOT>/.gitignore" || printf '*\n' > "<REVIEW_ROOT>/.gitignore"
mkdir -p "<REVIEW_ROOT>/waves"
```

This **does not modify the project's `.gitignore`** and does not enter git.

### 2. Legacy v1 detection (warning, not abort)

If in the project root (cwd) an **old** `SECURITY_CONTEXT.md` is detected (this is the v1 layout, before the v3 redesign):

```bash
test -f SECURITY_CONTEXT.md && echo "found"
```

→ Print a warning to the user, **do not touch the file**:

```
⚠️  Legacy v1 detected: SECURITY_CONTEXT.md in project root (schema v1)
    The file is not modified. Fresh recon will be written to <REVIEW_ROOT>/CONTEXT.md.
    The old file can be removed manually after a successful run.
```

### 3. Clean up previous artifacts

```bash
# Remove intermediate wave reports from previous runs
rm -f "<REVIEW_ROOT>/waves/"*.md
# Save the previous summary as .prev.md (if any)
if [ -f "<REVIEW_ROOT>/REPORT.md" ]; then
    mv "<REVIEW_ROOT>/REPORT.md" "<REVIEW_ROOT>/REPORT.prev.md"
fi
# Previous pre-retry snapshots (if the orchestrator did a retry in a past run)
rm -f "<REVIEW_ROOT>/waves/"*.pre-retry.md
```

`<REVIEW_ROOT>/REPORT/` (split detail) is **not cleaned** — dedupe will rewrite it at the dedup step.

`<REVIEW_ROOT>/.findings_state.json` (snapshot of the previous run for cross-run diff) is **not cleaned** — dedupe will read it before writing REPORT.md and overwrite it at the end. On the next run "New / Recurring / Closed" will appear in the Executive Summary automatically.

### 3a. Collecting the exclude list (CLAUDE.md + flag)

The goal — assemble a single `EXCLUDE_CSV` to forward to the recon utility. Sources:

1. **`<project_root>/CLAUDE.md`** (if the file exists). Read it and find explicit instructions to exclude directories from the security review. Typical signals: a section of the form `## Code review exclusions` / `## Security review exclusions` listing paths; or explicit suggestions "do not analyze legacy/", "exclude src/ThirdParty/", "the generated/ folder is autogen, no review needed". Extract only relative path prefixes (directories and/or specific subdirs), without glob patterns and `*.ext`. If CLAUDE.md is absent or does not contain such a section — the list is empty.
2. The orchestrator's **`--exclude=<csv>` flag** (if passed) — parse into a list.

Combine both sources, remove duplicates and empties. The result — `EXCLUDE_CSV` (comma-separated string) or empty.

> The built-in `DEFAULT_EXCLUDE` (`vendor/`, `var/cache/`, `var/log/`, `node_modules/`, `storage/framework/cache/`, `storage/logs/`, `bootstrap/cache/`, `public/build/`, `.git/`) is ALWAYS applied by the utility — there is no need to add it to `EXCLUDE_CSV`.

If something was taken from CLAUDE.md — print a line to the user:

```
Exclude (CLAUDE.md): <list>
Exclude (--exclude flag): <list or "none">
```

This gives transparency: the user sees which directories will not be analyzed before leaving for the run.

**Recommended section format in CLAUDE.md** (for user information — we do not write it ourselves):

```markdown
## Code review exclusions
Do not analyze in security review:
- legacy/                — outdated code, to be removed in Q4
- src/ThirdParty/        — vendored code, not our contract
- generated/             — autogenerated, no review needed
```

### 4. Recon phase

**If `--skip-recon` is passed AND `<REVIEW_ROOT>/CONTEXT.md` exists:**

1. Validate the schema: `python3 ${CLAUDE_PLUGIN_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>"`
2. Compute current fingerprints: `python3 ${CLAUDE_PLUGIN_ROOT}/bin/compute_fingerprint.py . --json`
3. Extract `project_fingerprint` and `code_fingerprint` from the frontmatter of the existing `<REVIEW_ROOT>/CONTEXT.md`, compare:
   - **project_fingerprint mismatch** → `abort`: "Configuration/dependencies changed, full recon required"
   - **project_fingerprint match + code_fingerprint match** → use context as-is
   - **project_fingerprint match + code_fingerprint mismatch**:
     - If `--force-skip-recon` → continue with warning
     - Else if `--interactive` → `AskUserQuestion`: "Code changed, context may be stale. Continue?"
     - Else → `abort` with the hint `--force-skip-recon`

**Otherwise (full recon):**

Launch the recon agent. It will pick the recipe itself (detect) and call `recon_inventory.py`, which writes `<REVIEW_ROOT>/CONTEXT.md`. If the orchestrator received `--no-console` — forward it to the prompt. If step 3a collected a non-empty `EXCLUDE_CSV` — forward `--exclude=<EXCLUDE_CSV>`:

```
Task(subagent_type="security-recon", prompt="""
  project_root: <cwd>
  review_root: <REVIEW_ROOT>
  [--no-console]            # only if the flag was passed to the orchestrator
  [--exclude=<EXCLUDE_CSV>] # only if 3a collected a non-empty list
""")
```

**In normal mode `--no-console` is not needed** — the recon utility decides itself (if console enrichment is available — uses it, otherwise sets ceiling=medium). Pass the flag only on explicit sandbox requirement (hostile-repo audit, CI without credentials).

After return — check `RECON_OK` in the agent's response. If `RECON_*_FAILED` is received — stop, print the error.

Then additionally run sanity-check with filesystem coverage:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity
```

`--sanity` imports the recipe (per `recipe_used` from frontmatter), calls `recipe.sanity_probes()`, compares declared `file:` in sections against the actual filesystem. **Coverage threshold ladder** (rev v3):

- diff ≤ 5 % → ok, `recon_confidence: high`
- diff 5–20 % → warning, `recon_confidence: medium`, rationale in `frontmatter.warnings`
- diff > 20 % → error, `recon_confidence: low`, exit 1

If validation fails (ERROR exit 1) — stop, show errors to the user.

If only warnings (sanity diff 5–20 %) — use the following logic depending on whether this is the first recon or a repeat (`RECON_RETRY_DONE`):

**First recon (RECON_RETRY_DONE = false):** show warnings to the user and offer a choice via AskUserQuestion:
- (a) Repeat recon (`rm <REVIEW_ROOT>/CONTEXT.md` + start over) — recommended if many files are missed
- (b) Continue with awareness of the gaps

If the user picked (a): set `RECON_RETRY_DONE = true`, remove `<REVIEW_ROOT>/CONTEXT.md`, restart the recon agent, run validation and sanity-check again.

**Repeat recon (RECON_RETRY_DONE = true):** if coverage is still in the warning range — **do not ask again**. Show the warning and automatically continue:

```
⚠️  Sanity-check after repeat recon: coverage improved, but warning remains.
   Possibly some files are outside expected directories or follow non-standard naming.
   Continuing with the available inventory — workers will cover the declared entry points.
```

### 5. Summary for the user

Read `<REVIEW_ROOT>/CONTEXT.md`, show a brief summary (section names — those that are present in this CONTEXT.md; below is an example for Symfony, for other stacks names differ):

```
Recon complete (recon_confidence: <level>, ceiling: <level>).
Stack: <framework name from frontmatter.stack.framework>
Found (top-level core sections):
  - attack_surface: <N items>
  - data_access: <N items> (with diff. sources: <M>)
  - authz_usage: <N items>
  - serialization: <N items>
  - file_operations / http_clients: <N> / <M>
  - secrets: <status>
  - fintech_markers: <present|none>
Framework-specific (if present): <list of recon_bags.stack.<stack>.* keys with statuses>
Missing sections / warnings: [<list>]
```

### 6. Optional `--interactive` checkpoint

If `--interactive`:

```
AskUserQuestion:
  "Is the inventory correct? What to add, refine, prioritize?"
```

The user's answer — record in a comment on the slice when launching workers (`prompt` field). **CONTEXT.md is not modified** — the recon agent is authoritative.

### 7. Wave plan generation

Determine flag values:
- `EXPLORATORY` = on if `--quick` is NOT specified (default). Off if `--quick` is specified.
- `ALL_OPUS` = on if `--all-opus` is specified.
- `SCOPE_GLOB` = value after `--scope=`, or empty.

Call:
```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/plan_waves.py "<REVIEW_ROOT>/CONTEXT.md" \
  --plugin-root="${CLAUDE_PLUGIN_ROOT}" \
  --save-plan="<REVIEW_ROOT>/waves_plan.json" \
  [--all-opus]            # if ALL_OPUS \
  [--exploratory]         # if EXPLORATORY \
  [--scope-glob=<SCOPE_GLOB>]   # if set
```

`--save-plan` saves the plan to JSON for the subsequent coverage block in REPORT.md (step 11 / 11.5.2).

**`--plugin-root` is required** — otherwise `plan_waves` will not find `checklists/` (the relative path resolves to the project's cwd, not the plugin's). The script prefixes checklists with an absolute path.

**`--exploratory` is passed by default** (except in `--quick` mode). This gives the W∞ wave — key for cross-layer vulnerabilities (OAuth chains, tenancy integrity, authenticator flows).

It returns a JSON array with a list of slices. Each slice's fields:
- `slice_id`, `wave_id`, `themes`, `checklists` (absolute paths)
- `relevant_section_paths` (dot-notation), `entry_points_in_scope`, `target_files`
- `model` (opus|sonnet), `mode` (project)

### 7a. Print the plan to the user

Before launching workers, show the user a plan summary:

```
Launching <N> waves (mode: <balanced|all-opus>):
  W1 (opus, <M> files): auth+disclosure
  W2 (opus, <M> files): injection+data-access
  W3 (sonnet, <M> files): output-render+frontend-js
  W4 (sonnet, <M> files): serialization+crypto
  W5 (sonnet, <M> files): ssrf-fileops
  W6 (opus, <M> files): fintech (if triggered)
  W∞ (sonnet, exploratory): union themes
```

This gives visibility — the user sees what will be launched before going off into parallel processing for ~5-15 minutes.

### 8. Parallel worker launch

Split waves into batches of **6 workers** and launch batch by batch:

1. Take the first 6 waves from the plan → launch in parallel in one block of Task calls
2. Wait for all 6 to complete → process results (step 9) → launch the next batch
3. Repeat until waves are exhausted

Task call format for each wave:

```
Task(subagent_type="security", model=<from plan, field "model">, prompt="""
  review_root: <REVIEW_ROOT>
  relevant_section_paths: <list of dot-notation paths>
  checklists: <list of absolute paths>
  entry_points_in_scope: <list>
  target_files: <list>
  slice_id: <from plan>
  mode: project
""")
```

**Important:** the `model` parameter is passed as a Task call argument, not in the prompt text. This guarantees that the worker runs on the needed model (opus/sonnet from the balanced profile). The value is taken from the `"model"` field of the JSON plan.

**Important:** maximum 6 parallel Task calls at once. With many waves — several batches sequentially.

### 9. Safety net + progress per worker

For **each** Task worker return:

1. Check file existence:
   ```bash
   ls "<REVIEW_ROOT>/waves/<slice_id>.md"
   ```
2. **Safety net (always):** if the file is **missing**, the worker did not perform a Write — extract the markdown body from its response message (it should contain `# Vulnerability ...` blocks) and write it yourself via Write to `<REVIEW_ROOT>/waves/<slice_id>.md`. This guarantees that dedup receives all findings as input.
3. **If the response also has no markdown blocks** (worker returned only text or crashed) — create a file with a header:
   ```markdown
   # Wave <slice_id> — no findings or worker failed
   <short message from worker response or fail reason>
   ```
4. Print a one-line status to the user:
   - `✓ <slice_id>: saved <N> findings (Critical: x, High: y, Medium: z)` — found
   - `✓ <slice_id>: clean (0 findings)` — checked, clean
   - `⚠ <slice_id>: worker returned no file, recovered from response` — safety net fired
   - `✗ <slice_id>: failed — <reason>` — could not get a meaningful result

We do not retry workers. Continue with the remaining.

### 9a. Merge pre-retry files (if any)

If the orchestrator (or user) previously did a worker retry and `*.pre-retry.md` files remain:

```bash
for pre in "<REVIEW_ROOT>/waves/"*.pre-retry.md; do
  [ -f "$pre" ] || continue
  base="${pre%.pre-retry.md}.md"
  if [ -f "$base" ]; then
    cat "$pre" >> "$base"
  fi
done
```

The dedup script will automatically merge duplicates — better duplicate than losing a security case.

### 10. Warning for large projects with exploratory

If `EXPLORATORY=on` (by default) AND >100 files in scope — print a warning **before launching** the W∞ Task:

```
⚠️  Exploratory wave (W∞) on a project >100 files — may be expensive.
   W∞ loads the union of all thematic checklists and runs across all target files
   in chunks of 65 files on sonnet — cost grows linearly with project size.
   W4/W5 are already on sonnet by default (no option here).

   Options to save:
     • --quick           — disable W∞ entirely. We lose cross-layer analysis:
                           OAuth state chains, multi-tenancy boundaries,
                           authenticator integrity, prompt injection chains.
                           Focused waves W1–W6 continue to work.
     • --scope=<glob>    — narrow target_files to a subset (for example,
                           --scope='src/Api/**'). W∞ stays enabled,
                           but runs only on matches — proportionally cheaper.
```

The W∞ Task is launched automatically in the common loop (step 8) — a separate step is not needed; `plan_waves.py --exploratory` already included it in the plan.

### 11. Deduplication and summary

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json"
```

Dedup produces a **split report** (by default):
- `<REVIEW_ROOT>/REPORT.md` — executive summary + index table of all findings with links to details
- `<REVIEW_ROOT>/REPORT/<root_cause_family>.md` — finding details by category (authz.md, injection.md, disclosure.md, crypto.md, ssrf.md, webhook.md, business_logic.md, xss.md, deserialization.md)
- `<REVIEW_ROOT>/REPORT/manual_review.md` — findings requiring manual check: those that did not pass auto-promote (custom sink_kind + non-critical) **and** parse-failed (worker did not emit `sink_file`, flag `[PARSE_FAILED]`). The index outputs a callout "⚠️ Action required: N" on non-zero count.

For legacy mode (everything in one file) — flag `--single-file`.

### 11.5. Adversarial refute pass (optional, on by default)

If the orchestrator was launched with `--no-adversarial` — **skip this step** (then directly to step 12).

#### 11.5.1. Launching the refute wave

Read the `<REVIEW_ROOT>/REPORT.md` index table. Split rows into batches of ≤20 findings (first 20 → batch_index=0, next 20 → batch_index=1, etc.).

For each batch — sequential Task call (parallelism is **forbidden** — the refute agent writes to a single file `<REVIEW_ROOT>/refute.md` in Append mode):

```
Task subagent_type=security-refute prompt="
review_root: <REVIEW_ROOT>
batch_index: <0..N-1>
findings_slice: <markdown slice of REPORT.md index ≤ 20 finding rows>
"
```

Soft timeout 10 minutes per call. If the Task did not return within timeout — the orchestrator prints a warning "adversarial pass partial — N from M findings reviewed" and continues with partial refute. Refute does not block the main report.

#### 11.5.2. Apply refute results

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json" \
  --refute "<REVIEW_ROOT>/refute.md" \
  --project-root "<PROJECT_ROOT>"
```

This re-runs dedup (fast) and applies refute tags. On output:
- In `REPORT.md` — each refute-marked finding receives a `[REFUTE_CLAIMED]` marker with a `refute_file:refute_line` tail.
- A new file `<REVIEW_ROOT>/REPORT/refute_invalid.md` — refute records that did not pass auto-validation (for audit).
- Executive summary shows counters `confirmed / refute_claimed / refute_invalid / manual_review / parse_failed`.

### 12. Output to user

```
Security review complete.
  Index: <REVIEW_ROOT>/REPORT.md
  Details by category: <REVIEW_ROOT>/REPORT/<family>.md
  Intermediate reports (for audit): <REVIEW_ROOT>/waves/*.md
  Uncovered slices: [<list> or none]
```

## PRINCIPLES

- Never commit artifacts — the local `.gitignore` inside `<REVIEW_ROOT>/` already ignores all content + the `.gitignore` itself. The user decides themselves to commit via `git add -f`, if they wish.
- Worker failure ≠ abort the whole review — continue with the remaining
- Keep all intermediate `<REVIEW_ROOT>/waves/*.md` for audit, do not delete between steps
