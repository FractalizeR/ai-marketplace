### 3b. Resolve console runner (environment-aware)

Console enrichment (running the project's `bin/console` for routes / ceiling=high) is the only recon step that **executes the project**. Running it on the host when the project lives **inside a container** distorts the environment (wrong PHP version, services unreachable). This step decides HOW to run it. OpenCode has no interactive-prompt primitive, so resolution is **non-interactive**: it is driven entirely by flags plus the static probe, and when the choice is ambiguous it degrades to static-only with a loud, recorded coverage gap rather than guessing.

Skip this whole step (set `CONSOLE_CMD = none`, proceed to step 4) when **any** of these holds:

- `--no-console` was passed → forward `--no-console` to the recon worker (user's explicit static-only choice). Wins over everything below.
- `--console-cmd=<tpl>` was passed → forward `--console-cmd=<tpl>` verbatim (user already chose the runner). **Caveat on OpenCode:** a template with spaces (almost all container/Makefile commands) is truncated by the whitespace-split argument contract — prefer the environment variable below, which `frsr --console-cmd` sets for you.
- **`FR_SECURITY_CONSOLE_CMD` is set in the environment** — check `[ -n "$FR_SECURITY_CONSOLE_CMD" ]`. A launcher (`frsr --console-cmd "docker compose exec -T php bin/console"`) or CI exported the console command out-of-band so its spaces ride the environment intact. Set `CONSOLE_CMD = env` and forward exactly that token (`console_mode=env`) to the recon worker — **never** substitute or echo the variable's value into the prompt. `recon_inventory.py` reads `FR_SECURITY_CONSOLE_CMD` itself. This is the clean, space-safe way to enable container/Makefile console on OpenCode. (`--no-console` still wins; an explicit `--console-cmd=<tpl>` flag takes precedence when it survived intact.)
- `--skip-recon` path is taken (CONTEXT.md is reused, not regenerated).

Otherwise:

1. **Detect whether the stack even has console enrichment.** Run `python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect` and read `recipe`. Only **Symfony** has console enrichment today (Laravel/generic are fully static). If `recipe != symfony` → nothing to resolve, proceed to step 4 with no console flags.

2. **Probe the environment** (read-only; runs only host `php --version` + file reads — safe even for untrusted repos):

   ```bash
   python3 ${FR_SECURITY_CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
   ```

   This prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.

3. **If `containerized == false` AND `host_php_present == true`** → the host is a faithful runner. Proceed to step 4 with **no** console flags (the recon utility auto-selects the host runner).

4. **Otherwise (containerized, or no host php)** → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively** (the show-and-confirm trust model is impossible without a prompt). Proceed to step 4 with no console flag and **record the gap**: the recon utility detects the unresolved containerized console and writes a loud `console_gap` (ceiling=medium) into CONTEXT.md, which `dedupe_findings.py` surfaces as a `## Coverage Gaps` section in REPORT.md. Nothing is silently dropped — reduced coverage is visible. To get container/Makefile console enrichment on OpenCode, re-run with `frsr --console-cmd "docker compose exec -T <php-service> php bin/console"` (or a Makefile passthrough `frsr --console-cmd "make console CMD={args}"`) — this exports `FR_SECURITY_CONSOLE_CMD` so the space-containing template survives; to declare an explicit static-only run, pass `--no-console`.

5. Set `CONSOLE_CMD` to the resolved `--console-cmd=...`, `--no-console`, `env` (utility reads `FR_SECURITY_CONSOLE_CMD`), or none, and forward it to the recon worker in step 4.

> The choice is always deterministic on OpenCode. For a containerized project, `frsr --console-cmd "<template>"` (→ `FR_SECURITY_CONSOLE_CMD`, `CONSOLE_CMD = env`) is the space-safe way to enable console enrichment; with no console command set on a containerized project, the run proceeds static-only with a recorded `console_gap` (ceiling=medium) — the safe default, surfaced in REPORT.md so nothing is silently dropped.

