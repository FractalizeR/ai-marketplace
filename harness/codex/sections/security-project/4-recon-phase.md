### 4. Recon phase

**If `--skip-recon` is passed AND `<REVIEW_ROOT>/CONTEXT.md` exists:**

1. Validate the schema: `python3 ${CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>"`
2. Compute current fingerprints: `python3 ${CORE_ROOT}/bin/compute_fingerprint.py . --json`
3. Extract `project_fingerprint` and `code_fingerprint` from the frontmatter of the existing `<REVIEW_ROOT>/CONTEXT.md`, compare:
   - **project_fingerprint mismatch** → `abort`: "Configuration/dependencies changed, full recon required"
   - **project_fingerprint match + code_fingerprint match** → use context as-is
   - **project_fingerprint match + code_fingerprint mismatch**:
     - If `--force-skip-recon` → continue with warning
     - Else → `codex exec` runs headless (approval `never`), so there is no interactive confirm. Default to **abort** with the hint `--force-skip-recon`. If `--interactive` was passed (the user signalled they want to proceed through checkpoints, but Codex cannot prompt), **continue with awareness** instead of aborting: print a stale-context warning, set `recon_confidence: medium`, and do **not** auto-retry.

**Otherwise (full recon):**

Launch **one** recon process. Codex has no named agents and no in-process subagent — recon runs as a single external `codex exec` invocation that **reads and follows** the bundled recon agent file, driven through the shared role dispatcher (`shared/dispatch.py`, `dispatch_role`) so freshness, stdout capture, and gap classification match every other stage. The recon process picks the recipe itself (detect) and calls `recon_inventory.py`, which writes `<REVIEW_ROOT>/CONTEXT.md`. Forward the same inputs the in-process path forwarded — both paths **absolute** (Step 0.4 invariant), the console decision from step 3b (`CONSOLE_MODE`), and, if step 3a collected a non-empty exclude list, `EXCLUDE_CSV`:

```bash
python3 ${CORE_ROOT}/bin/shared/dispatch.py \
  --role recon \
  --project-root "<PROJECT_ROOT>" \
  --review-root "<REVIEW_ROOT>" \
  --core-root "${CORE_ROOT}" \
  --role-cmd-template 'codex exec -m <HIGH_TIER> -C <PROJECT_ROOT> -s workspace-write --add-dir <REVIEW_ROOT> --skip-git-repo-check -o <REVIEW_ROOT>/captures/recon.capture.txt "read and follow <CORE_ROOT>/agents/security-recon.md then run recon: project_root=<PROJECT_ROOT> review_root=<REVIEW_ROOT> console_mode=<CONSOLE_MODE> exclude=<EXCLUDE_CSV>"'
```

**Author the inputs flag-free (`key=value`).** `codex exec` takes a single positional PROMPT, so the whole read-follow instruction is one quoted argument — never a leading-`--` flag that could collide with `codex exec`'s own options if the surrounding quotes are lost while resolving values. The recon agent maps `console_mode` (`off` | `auto` | a container/Makefile command) and `exclude` to the corresponding `recon_inventory.py` flags (`--no-console` / `--console-cmd=<tpl>` / `--exclude=<csv>`); the read-follow file is the single source of that mapping.

`<HIGH_TIER>` is the high-tier model id from the resolved `<REVIEW_ROOT>/.model_map.json` (`shared/model_resolver.py`); recon runs on the high tier. `-C <PROJECT_ROOT>` sets the worker's cwd; `--add-dir <REVIEW_ROOT>` grants write access to the review root — in a composite repo it lies **outside** `project_root`, and the `workspace-write` sandbox would otherwise deny the CONTEXT.md write silently. `--skip-git-repo-check` lets `codex exec` run in a non-git subtree. Recon is a single process — no fan-out — so `dispatch_role` launches one `codex exec` and treats the presence of `<REVIEW_ROOT>/CONTEXT.md` as success.

After the process returns — success means `<REVIEW_ROOT>/CONTEXT.md` was materialized and `codex exec` exited 0 (the dispatcher reports `output_present`). If CONTEXT.md is missing, the captured last message (`-o …/recon.capture.txt`) is the partial safety net: read it and recover CONTEXT.md, otherwise stop and print the error.

Then additionally run sanity-check with filesystem coverage:

```bash
python3 ${CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity --project-root "<PROJECT_ROOT>"
```

`--project-root` is required here — without it `validate_context.py` falls back to inferring from `parent(review_root)`, which fails for composite repos (parent has no `composer.json` / `package.json`) and prints `WARNING: project_root not specified and could not be inferred — sanity coverage skipped`. The fallback exists for legacy CLI callers; the orchestrator must always be explicit.

`--sanity` imports the recipe (per `recipe_used` from frontmatter), calls `recipe.sanity_probes()`, compares declared `file:` in sections against the actual filesystem. **Coverage threshold ladder** (rev v3):

- diff ≤ 5 % → ok, `recon_confidence: high`
- diff 5–20 % → warning, `recon_confidence: medium`, rationale in `frontmatter.warnings`
- diff > 20 % → error, `recon_confidence: low`, exit 1

If validation fails (ERROR exit 1) — stop, show errors to the user.

If only warnings (sanity diff 5–20 %) — Codex runs headless with no retry prompt, so **do not auto-retry**: print the warning and continue with the available inventory at `recon_confidence: medium`. Workers will cover the declared entry points; the medium confidence and the rationale in `frontmatter.warnings` record the reduced coverage.

```
⚠️  Sanity-check: coverage in the warning range (5–20 %).
   Possibly some files are outside expected directories or follow non-standard naming.
   Continuing with the available inventory (recon_confidence: medium) — workers will cover the declared entry points.
   To improve coverage, re-run recon (drop --skip-recon) or widen the recipe's expected directories.
```
