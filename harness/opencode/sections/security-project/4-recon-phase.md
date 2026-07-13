### 4. Recon phase

**If `--skip-recon` is passed AND `<REVIEW_ROOT>/CONTEXT.md` exists:**

1. Validate the schema: `python3 ${FR_SECURITY_CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>"`
2. Compute current fingerprints: `python3 ${FR_SECURITY_CORE_ROOT}/bin/compute_fingerprint.py . --json`
3. Extract `project_fingerprint` and `code_fingerprint` from the frontmatter of the existing `<REVIEW_ROOT>/CONTEXT.md`, compare:
   - **project_fingerprint mismatch** → `abort`: "Configuration/dependencies changed, full recon required"
   - **project_fingerprint match + code_fingerprint match** → use context as-is
   - **project_fingerprint match + code_fingerprint mismatch**:
     - If `--force-skip-recon` → continue with warning
     - Else → OpenCode has no interactive confirm. Default to **abort** with the hint `--force-skip-recon`. If `--interactive` was passed (the user signalled they want to proceed through checkpoints, but OpenCode cannot prompt), **continue with awareness** instead of aborting: print a stale-context warning, set `recon_confidence: medium`, and do **not** auto-retry.

**Otherwise (full recon):**

Launch **one** recon process. OpenCode has no in-process subagent — recon runs as a single external `opencode run` invocation (the recon SKILL), driven through the shared role dispatcher (`shared/dispatch.py`, `dispatch_role`) so freshness, stdout capture, and gap classification match every other stage. The recon process picks the recipe itself (detect) and calls `recon_inventory.py`, which writes `<REVIEW_ROOT>/CONTEXT.md`. Forward the same inputs the in-process path forwarded — both paths **absolute** (Step 0.4 invariant), the console decision from step 3b (`CONSOLE_CMD`: `--no-console`, `--console-cmd=<tpl>`, `env` → forward **no** console flag since the utility reads `FR_SECURITY_CONSOLE_CMD` from the environment, or nothing), and, if step 3a collected a non-empty `EXCLUDE_CSV`, `--exclude=<EXCLUDE_CSV>`:

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/dispatch.py \
  --role recon \
  --project-root "<PROJECT_ROOT>" \
  --review-root "<REVIEW_ROOT>" \
  --core-root "${FR_SECURITY_CORE_ROOT}" \
  --role-cmd-template 'opencode run -m <HIGH_TIER> --agent security-recon -- "project_root=<PROJECT_ROOT> review_root=<REVIEW_ROOT> [--no-console | --console-cmd=<tpl>] [--exclude=<EXCLUDE_CSV>]"'
```

**Keep the `--` before the message.** The recon message carries `--no-console` / `--console-cmd=` / `--exclude=`, which start with `--`. `dispatch.py` shlex-splits the template into argv, so without the `--` terminator `opencode run` parses `--no-console` as *its own* CLI flag (prints help, exits 1) and recon never runs — even when the quotes around the message are lost while you resolve the `[…|…]` choice. The `--` stops OpenCode's option parsing; everything after it is joined into the agent's `$ARGUMENTS` verbatim (empirically verified), so the flags reach `recon_inventory.py` intact whether or not the surrounding quotes survive.

**Placeholder discipline.** `dispatch.py --role-cmd-template` substitutes only `{…}`-form placeholders (`{project_root}`, `{review_root}`, `{core_root}` — the same ones the fan-out worker template uses), never `<…>` slots. Replace every `<…>` slot in the template string — `<HIGH_TIER>`, `<PROJECT_ROOT>`, `<REVIEW_ROOT>`, and the console/`<EXCLUDE_CSV>` choices — with its concrete value **before** invoking `dispatch.py`. An unsubstituted `<HIGH_TIER>` reaches `opencode run` verbatim (`-m <HIGH_TIER>`) and the recon process fails; the dispatcher will not expand it for you.

**`<HIGH_TIER>` — read it from the already-resolved model map; do NOT re-resolve.** `<REVIEW_ROOT>/.model_map.json` was written by the launcher (`frsr`) or the INSTALL "Resolve models" step and is the single source of the `high` / `fast` model ids; `<HIGH_TIER>` is its `high` value — read it directly (`python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["high"])' "<REVIEW_ROOT>/.model_map.json"`). When the map already exists, do **NOT** re-resolve or run `opencode models` discovery — that silently overrides an explicit `--models` pin (the map's `provenance` is then `cli`). **Only** if `<REVIEW_ROOT>/.model_map.json` is absent, create it once, non-interactively — `python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/model_resolver.py --discovery-cmd 'opencode models' --review-root "<REVIEW_ROOT>"` — then read it. Recon runs on the high tier. Recon is a single process — no fan-out — so `dispatch_role` launches one `opencode run` and treats the presence of `<REVIEW_ROOT>/CONTEXT.md` as success.

**In normal mode neither console flag is needed** — step 3b resolved a host runner (or proceeded with none) and the recon utility auto-decides. Pass `--no-console` on explicit sandbox requirement (hostile-repo audit, CI without credentials), or `--console-cmd=<tpl>` when step 3b picked a container/Makefile runner.

After the process returns — success means `<REVIEW_ROOT>/CONTEXT.md` was materialized and `opencode run` exited 0 (the dispatcher reports `output_present`). If CONTEXT.md is missing or the process failed — stop, print the error.

Then additionally run sanity-check with filesystem coverage:

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity --project-root "<PROJECT_ROOT>"
```

`--project-root` is required here — without it `validate_context.py` falls back to inferring from `parent(review_root)`, which fails for composite repos (parent has no `composer.json` / `package.json`) and prints `WARNING: project_root not specified and could not be inferred — sanity coverage skipped`. The fallback exists for legacy CLI callers; the orchestrator must always be explicit.

`--sanity` imports the recipe (per `recipe_used` from frontmatter), calls `recipe.sanity_probes()`, compares declared `file:` in sections against the actual filesystem. **Coverage threshold ladder** (rev v3):

- diff ≤ 5 % → ok, `recon_confidence: high`
- diff 5–20 % → warning, `recon_confidence: medium`, rationale in `frontmatter.warnings`
- diff > 20 % → error, `recon_confidence: low`, exit 1

If validation fails (ERROR exit 1) — stop, show errors to the user.

If only warnings (sanity diff 5–20 %) — OpenCode cannot prompt for a retry-vs-continue choice, so **do not auto-retry**: print the warning and continue with the available inventory at `recon_confidence: medium`. Workers will cover the declared entry points; the medium confidence and the rationale in `frontmatter.warnings` record the reduced coverage.

```
⚠️  Sanity-check: coverage in the warning range (5–20 %).
   Possibly some files are outside expected directories or follow non-standard naming.
   Continuing with the available inventory (recon_confidence: medium) — workers will cover the declared entry points.
   To improve coverage, re-run recon (drop --skip-recon) or widen the recipe's expected directories.
```

