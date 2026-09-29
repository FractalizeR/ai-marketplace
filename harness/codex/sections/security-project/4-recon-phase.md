### 4. Recon phase

Launch **one** recon process. Codex has no named agents and no in-process subagent — recon runs as a single external `codex exec` invocation that **reads and follows** the bundled recon agent file, driven through the shared role dispatcher (`shared/dispatch.py`, `dispatch_role`) so freshness, stdout capture, and gap classification match every other stage. The recon process picks the recipe itself (detect) and calls `recon_inventory.py`, which writes `<REVIEW_ROOT>/CONTEXT.md`. Forward the same inputs the in-process path forwarded — both paths **absolute** (Step 0.4 invariant), the console decision from step 3b (`CONSOLE_MODE`), and, if step 3a collected a non-empty exclude list, `EXCLUDE_CSV`:

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/dispatch.py \
  --role recon \
  --project-root "<PROJECT_ROOT>" \
  --review-root "<REVIEW_ROOT>" \
  --core-root "${FR_SECURITY_CORE_ROOT}" \
  --role-cmd-template 'codex exec -m <HIGH_TIER> -C <PROJECT_ROOT> <SANDBOX_FLAGS> --skip-git-repo-check -o <REVIEW_ROOT>/captures/recon.capture.txt "read and follow <FR_SECURITY_CORE_ROOT>/agents/security-recon.md then run recon: project_root=<PROJECT_ROOT> review_root=<REVIEW_ROOT> console_mode=<CONSOLE_MODE> exclude=<EXCLUDE_CSV>"'
```

**`<SANDBOX_FLAGS>` — choose by `CONSOLE_MODE` (this is the only worker whose sandbox varies):**

- **`CONSOLE_MODE` is `env` or a custom container/Makefile command** (the recon process must **execute the project console**) → `--dangerously-bypass-approvals-and-sandbox`. A `-s workspace-write` sandbox blocks the console command from reaching the Docker daemon socket / project services (`permission denied` → `console_runtime_failed`, ceiling clamped to medium), silently defeating the enrichment the operator explicitly asked for. Running the console is an explicit trust signal (the operator set `FR_SECURITY_CONSOLE_CMD` / `--console-cmd` on a project they own), so recon — a single process — runs unsandboxed here, exactly like the orchestrator. **The fan-out wave workers stay `-s workspace-write` + offline regardless** (they never execute the project; see step 8).
- **`CONSOLE_MODE` is `off` or `auto`** → `-s workspace-write --add-dir <REVIEW_ROOT>` (static, or a host `php` runner that needs no daemon). `--add-dir <REVIEW_ROOT>` grants the CONTEXT.md write when the review root lies outside `project_root` (composite repos); the bypass form above already has full access, so it does not need `--add-dir`.

**Author the inputs flag-free (`key=value`).** `codex exec` takes a single positional PROMPT, so the whole read-follow instruction is one quoted argument — never a leading-`--` flag that could collide with `codex exec`'s own options if the surrounding quotes are lost while resolving values. The recon agent maps `console_mode` (`off` | `auto` | `env` | a container/Makefile command) and `exclude` to the corresponding `recon_inventory.py` flags (`--no-console` / `--console-cmd=<tpl>` / neither, for `env`, since the utility reads `FR_SECURITY_CONSOLE_CMD` itself / `--exclude=<csv>`); the read-follow file is the single source of that mapping.

**Placeholder discipline.** `dispatch.py --role-cmd-template` substitutes only `{…}`-form placeholders (`{project_root}`, `{review_root}`, `{core_root}` — the same ones the fan-out worker template uses), never `<…>` slots. Replace every `<…>` slot in the template string — `<HIGH_TIER>`, `<PROJECT_ROOT>`, `<REVIEW_ROOT>`, `<FR_SECURITY_CORE_ROOT>`, `<SANDBOX_FLAGS>` (resolved just above from `CONSOLE_MODE`), `<CONSOLE_MODE>`, `<EXCLUDE_CSV>` — with its concrete value **before** invoking `dispatch.py`. An unsubstituted `<HIGH_TIER>` reaches `codex exec` verbatim (`-m <HIGH_TIER>`) and the recon process fails; the dispatcher will not expand it for you.

**`<HIGH_TIER>` — read it from the already-resolved model map; do NOT re-resolve.** `<REVIEW_ROOT>/.model_map.json` was written by the launcher (`frsr`) or the INSTALL "Resolve models" step and is the single source of the `high` / `fast` model ids; `<HIGH_TIER>` is its `high` value — read it directly (`python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["high"])' "<REVIEW_ROOT>/.model_map.json"`). When the map already exists, do **NOT** run model discovery, `model_resolver.py`, `codex models` / `codex debug models`, or read `~/.codex/config.toml` — that silently overrides an explicit `--models` pin (the map's `provenance` is then `cli`). **Only** if `<REVIEW_ROOT>/.model_map.json` is absent, create it once, non-interactively — `python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/model_resolver.py --discovery-cmd 'codex debug models' --review-root "<REVIEW_ROOT>"` — then read it. Recon runs on the high tier. `-C <PROJECT_ROOT>` sets the worker's cwd; in the `-s workspace-write` case `--add-dir <REVIEW_ROOT>` (part of `<SANDBOX_FLAGS>`) grants write access to the review root — in a composite repo it lies **outside** `project_root`, and the sandbox would otherwise deny the CONTEXT.md write silently (the `--dangerously-bypass-approvals-and-sandbox` case already has full access). `--skip-git-repo-check` lets `codex exec` run in a non-git subtree. Recon is a single process — no fan-out — so `dispatch_role` launches one `codex exec` and treats the presence of `<REVIEW_ROOT>/CONTEXT.md` as success.

After the process returns — success means `<REVIEW_ROOT>/CONTEXT.md` was materialized and `codex exec` exited 0 (the dispatcher reports `output_present`). If CONTEXT.md is missing, the captured last message (`-o …/recon.capture.txt`) is the partial safety net: read it and recover CONTEXT.md, otherwise stop and print the error.

Then run the sanity check with filesystem coverage and record the recon gaps:

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity --project-root "<PROJECT_ROOT>" --gaps-out "<REVIEW_ROOT>/recon_gaps.json"
```

`--project-root` is required here — without it `validate_context.py` falls back to inferring from `parent(review_root)`, which fails for composite repos (parent has no `composer.json` / `package.json`) and prints `WARNING: project_root not specified and could not be inferred — sanity coverage skipped`. The fallback exists for legacy CLI callers; the orchestrator must always be explicit.

`--sanity` imports the recipe (per `recipe_used` from frontmatter), calls `recipe.sanity_probes()`, and compares what the sections declare against the filesystem. It **never stops the run on a coverage problem** — which suits headless Codex, where there is no one to ask about a retry. Each gap is a `WARNING:` line on stderr, and all but the last kind below are also a record in `<REVIEW_ROOT>/recon_gaps.json`:

- files a probe found on disk that a section does not declare (an `ok` section with more than 5 % missing, or any `partial` / `unknown` one);
- a section whose extractor failed (`extractor_failed: …`);
- config the recipe found but could not interpret (`config_uninterpreted: …`), and list sections left in `pending_enrichment`;
- declared files that are not on disk (the recon process already had one attempt to fix these).

The gap records feed the WGAP wave in step 7: workers review those files directly, so a gap costs a follow-up pass instead of the run. `--gaps-out` rewrites the file on every call, with an empty `items` list when there are no gaps.

- exit 0 → print the `WARNING:` lines as they are and continue; do not re-run recon.
- exit 1 → CONTEXT.md is structurally invalid — stop and print the `ERROR:` lines.
- exit 2 → CONTEXT.md is missing — stop.
