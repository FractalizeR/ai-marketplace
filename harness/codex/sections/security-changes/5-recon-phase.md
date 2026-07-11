### 5. Recon phase

Recon collects the inventory **across the whole project** (for full context), but the recipe marks `touched_by_diff: true/false` on applicable items per the list of changed files.

**If `--skip-recon` AND `<REVIEW_ROOT>/CONTEXT.md` exists:** run fingerprint validation — `python3 ${FR_SECURITY_CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>"` then `python3 ${FR_SECURITY_CORE_ROOT}/bin/compute_fingerprint.py . --json`, comparing `project_fingerprint` / `code_fingerprint` against the existing CONTEXT.md frontmatter. project_fingerprint mismatch → abort (full recon required); both match → reuse as-is; project match + code mismatch → continue only with `--force-skip-recon`, otherwise abort with that hint (Codex runs headless, so there is no interactive confirm — `--interactive` downgrades the abort to a stale-context warning and continues with `recon_confidence: medium`, no auto-retry).

**Otherwise:**

Launch **one** recon process. Codex has no named agents and no in-process subagent — recon runs as a single external `codex exec` invocation that **reads and follows** the bundled recon agent file, driven through the shared role dispatcher (`shared/dispatch.py`, `dispatch_role`) so freshness, stdout capture, and gap classification match every other stage. The recon process detects the recipe and calls `recon_inventory.py`, which writes `<REVIEW_ROOT>/CONTEXT.md`.

Forward the changed-file list (the only signal that `scope=changes` is needed), the console decision from step 4c (`CONSOLE_MODE`), and, if step 4a collected a non-empty exclude list, `EXCLUDE_CSV`. All paths are forwarded **absolute** (Step 0.4 invariant):

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/dispatch.py \
  --role recon \
  --project-root "<PROJECT_ROOT>" \
  --review-root "<REVIEW_ROOT>" \
  --core-root "${FR_SECURITY_CORE_ROOT}" \
  --role-cmd-template 'codex exec -m <HIGH_TIER> -C <PROJECT_ROOT> -s workspace-write --add-dir <REVIEW_ROOT> --skip-git-repo-check -o <REVIEW_ROOT>/captures/recon.capture.txt "read and follow <FR_SECURITY_CORE_ROOT>/agents/security-recon.md then run recon: project_root=<PROJECT_ROOT> review_root=<REVIEW_ROOT> diff_files=<REVIEW_ROOT>/diff_files.txt console_mode=<CONSOLE_MODE> exclude=<EXCLUDE_CSV>"'
```

**Author the inputs flag-free (`key=value`).** `codex exec` takes a single positional PROMPT, so the whole read-follow instruction is one quoted argument — never a leading-`--` flag that could collide with `codex exec`'s own options if the quotes are lost. The recon agent maps `diff_files` → `--diff-files=<path>`, `console_mode` (`off` | `auto` | a container/Makefile command) → `--no-console` / `--console-cmd=<tpl>`, and `exclude` → `--exclude=<csv>` when it invokes `recon_inventory.py`; the read-follow file is the single source of that mapping.

`diff_files` is the **only** signal to the recon process that `scope=changes` is needed. If it is dropped, recon silently runs in project mode and `touched_by_diff` will NOT be set — the entire mode=changes pipeline breaks.

**Placeholder discipline.** `dispatch.py --role-cmd-template` substitutes only `{…}`-form placeholders (`{project_root}`, `{review_root}`, `{core_root}` — the same ones the fan-out worker template uses), never `<…>` slots. Replace every `<…>` slot in the template string — `<HIGH_TIER>`, `<PROJECT_ROOT>`, `<REVIEW_ROOT>`, `<FR_SECURITY_CORE_ROOT>`, `<CONSOLE_MODE>`, `<EXCLUDE_CSV>` — with its concrete value **before** invoking `dispatch.py`. An unsubstituted `<HIGH_TIER>` reaches `codex exec` verbatim (`-m <HIGH_TIER>`) and the recon process fails; the dispatcher will not expand it for you.

**`<HIGH_TIER>` — read it from the already-resolved model map; do NOT re-resolve.** `<REVIEW_ROOT>/.model_map.json` was written by the launcher (`frsr`) or the INSTALL "Resolve models" step and is the single source of the `high` / `fast` model ids; `<HIGH_TIER>` is its `high` value — read it directly (`python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["high"])' "<REVIEW_ROOT>/.model_map.json"`). When the map already exists, do **NOT** run model discovery, `model_resolver.py`, `codex models` / `codex debug models`, or read `~/.codex/config.toml` — that silently overrides an explicit `--models` pin (the map's `provenance` is then `cli`). **Only** if `<REVIEW_ROOT>/.model_map.json` is absent, create it once, non-interactively — `python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/model_resolver.py --discovery-cmd 'codex debug models' --review-root "<REVIEW_ROOT>"` — then read it. `--add-dir <REVIEW_ROOT>` grants the CONTEXT.md write (the review root lies outside `project_root` in a composite repo, so `workspace-write` would otherwise deny it).

After the process returns — success means `<REVIEW_ROOT>/CONTEXT.md` was materialized and `codex exec` exited 0 (the dispatcher reports `output_present`). If CONTEXT.md is missing, the captured last message (`-o …/recon.capture.txt`) is the partial safety net: read it and recover CONTEXT.md, otherwise abort with a clear error.

Run filesystem coverage sanity-check:

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity --project-root "<PROJECT_ROOT>"
```

`--project-root` is required here — without it `validate_context.py` falls back to inferring from `parent(review_root)`, which fails for composite repos (parent has no `composer.json` / `package.json`) and prints `WARNING: project_root not specified and could not be inferred — sanity coverage skipped`. The fallback exists for legacy CLI callers; the orchestrator must always be explicit.

For `changes` mode the sanity is informational: if recon skipped >20% of controllers/handlers/voters/listeners from the filesystem, reverse/forward-grep may not find consumers for changed services. Threshold ladder: warning 5–20 % (`recon_confidence: medium`), error >20 % (exit 1). There is no retry prompt on Codex — on a warning, print it and continue with the available inventory at `recon_confidence: medium`; on an error, stop.
