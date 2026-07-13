### 5. Recon phase

Recon collects the inventory **across the whole project** (for full context), but the recipe marks `touched_by_diff: true/false` on applicable items per the list of changed files.

**If `--skip-recon` AND `<REVIEW_ROOT>/CONTEXT.md` exists:** run fingerprint validation — `python3 ${FR_SECURITY_CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>"` then `python3 ${FR_SECURITY_CORE_ROOT}/bin/compute_fingerprint.py . --json`, comparing `project_fingerprint` / `code_fingerprint` against the existing CONTEXT.md frontmatter. project_fingerprint mismatch → abort (full recon required); both match → reuse as-is; project match + code mismatch → continue only with `--force-skip-recon`, otherwise abort with that hint (OpenCode cannot prompt, so there is no interactive confirm — `--interactive` downgrades the abort to a stale-context warning and continues with `recon_confidence: medium`, no auto-retry).

**Otherwise:**

Launch **one** recon process. OpenCode has no in-process subagent — recon runs as a single external `opencode run` invocation (the recon SKILL), driven through the shared role dispatcher (`shared/dispatch.py`, `dispatch_role`) so freshness, stdout capture, and gap classification match every other stage. The recon process detects the recipe and calls `recon_inventory.py`, which writes `<REVIEW_ROOT>/CONTEXT.md`.

Forward `--diff-files=<REVIEW_ROOT>/diff_files.txt` to the recon process (it forwards to the utility as-is — see contract in `agents/security-recon.md`). Forward the console decision from step 4c (`CONSOLE_CMD`: `--no-console`, `--console-cmd=<tpl>`, `env` → no console flag since the utility reads `FR_SECURITY_CONSOLE_CMD`, or nothing). If step 4a collected a non-empty `EXCLUDE_CSV`, add `--exclude=<EXCLUDE_CSV>`. Both paths are forwarded **absolute** (Step 0.4 invariant):

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/dispatch.py \
  --role recon \
  --project-root "<PROJECT_ROOT>" \
  --review-root "<REVIEW_ROOT>" \
  --core-root "${FR_SECURITY_CORE_ROOT}" \
  --role-cmd-template 'opencode run -m <HIGH_TIER> --agent security-recon -- "project_root=<PROJECT_ROOT> review_root=<REVIEW_ROOT> --diff-files=<REVIEW_ROOT>/diff_files.txt [--no-console | --console-cmd=<tpl>] [--exclude=<EXCLUDE_CSV>]"'
```

**Placeholder discipline.** `dispatch.py --role-cmd-template` substitutes only `{…}`-form placeholders (`{project_root}`, `{review_root}`, `{core_root}` — the same ones the fan-out worker template uses), never `<…>` slots. Replace every `<…>` slot in the template string — `<HIGH_TIER>`, `<PROJECT_ROOT>`, `<REVIEW_ROOT>`, and the console/`<EXCLUDE_CSV>` choices — with its concrete value **before** invoking `dispatch.py`. An unsubstituted `<HIGH_TIER>` reaches `opencode run` verbatim (`-m <HIGH_TIER>`) and the recon process fails; the dispatcher will not expand it for you.

**`<HIGH_TIER>` — read it from the already-resolved model map; do NOT re-resolve.** `<REVIEW_ROOT>/.model_map.json` was written by the launcher (`frsr`) or the INSTALL "Resolve models" step and is the single source of the `high` / `fast` model ids; `<HIGH_TIER>` is its `high` value — read it directly (`python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["high"])' "<REVIEW_ROOT>/.model_map.json"`). When the map already exists, do **NOT** re-resolve or run `opencode models` discovery — that silently overrides an explicit `--models` pin (the map's `provenance` is then `cli`). **Only** if `<REVIEW_ROOT>/.model_map.json` is absent, create it once, non-interactively — `python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/model_resolver.py --discovery-cmd 'opencode models' --review-root "<REVIEW_ROOT>"` — then read it.

**Keep the `--` before the message.** This recon message carries `--diff-files=`, `--no-console` / `--console-cmd=`, and `--exclude=` — all starting with `--`. `dispatch.py` shlex-splits the template into argv, so without the `--` terminator `opencode run` consumes those as *its own* CLI flags (prints help, exits 1) and recon never runs — even when the quotes around the message are dropped while resolving the `[…|…]` choice. The `--` stops OpenCode's option parsing; everything after it is joined into the agent's `$ARGUMENTS` verbatim (empirically verified), so the flags reach `recon_inventory.py` intact regardless of quoting.

The `--diff-files=` field is the only signal to the recon process that `scope=changes` is needed. If it is passed as `diff_files:` without `--`, recon silently runs in project mode and `touched_by_diff` will NOT be set — the entire mode=changes pipeline breaks.

After the process returns — success means `<REVIEW_ROOT>/CONTEXT.md` was materialized and `opencode run` exited 0 (the dispatcher reports `output_present`). If CONTEXT.md is missing or the process failed — abort with a clear error.

Run filesystem coverage sanity-check:

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity --project-root "<PROJECT_ROOT>"
```

`--project-root` is required here — without it `validate_context.py` falls back to inferring from `parent(review_root)`, which fails for composite repos (parent has no `composer.json` / `package.json`) and prints `WARNING: project_root not specified and could not be inferred — sanity coverage skipped`. The fallback exists for legacy CLI callers; the orchestrator must always be explicit.

For `changes` mode the sanity is informational: if recon skipped >20% of controllers/handlers/voters/listeners from the filesystem, reverse/forward-grep may not find consumers for changed services. Threshold ladder: warning 5–20 % (`recon_confidence: medium`), error >20 % (exit 1). There is no retry prompt on OpenCode — on a warning, print it and continue with the available inventory at `recon_confidence: medium`; on an error, stop.

