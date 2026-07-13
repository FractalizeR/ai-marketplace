### 4c. Resolve console runner (environment-aware)

Decide HOW to run the project console (the only recon step that **executes the project**). Running it on the host when the project lives inside a container distorts the environment (wrong PHP version, services unreachable). OpenCode has no interactive-prompt primitive, so resolution is **non-interactive**: flags plus the static probe only, degrading to static-only with a recorded coverage gap when ambiguous rather than guessing.

Skip this whole step (set `CONSOLE_CMD = none`) when **any** holds:

- `--no-console` was passed → forward `--no-console` to the recon worker (step 5). Wins over everything below.
- `--console-cmd=<tpl>` was passed → forward it verbatim. **Caveat on OpenCode:** a template with spaces is truncated by the whitespace-split argument contract — prefer the environment variable below.
- **`FR_SECURITY_CONSOLE_CMD` is set in the environment** (`[ -n "$FR_SECURITY_CONSOLE_CMD" ]`) — a launcher (`frsr --console-cmd "docker compose exec -T php bin/console"`) or CI exported the console command out-of-band → `CONSOLE_CMD = env`; forward `console_mode=env`, **not** the variable's space-containing value. `recon_inventory.py` reads `FR_SECURITY_CONSOLE_CMD` itself. The clean, space-safe container/Makefile console path on OpenCode.
- `--skip-recon` path is taken (CONTEXT.md is reused).

Otherwise:

1. Detect the recipe: `python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect`. Console enrichment applies to **Symfony** only — for other recipes proceed with no console flags.
2. Probe (read-only, safe even for untrusted repos):

   ```bash
   python3 ${FR_SECURITY_CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
   ```

   It prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.
3. If `containerized == false` AND `host_php_present == true` → the host is a faithful runner; proceed with no console flags (the recon utility auto-selects the host).
4. Otherwise (containerized, or no host php) → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively**. Proceed with no console flag; the recon utility records a loud `console_gap` (ceiling=medium) in CONTEXT.md, which `dedupe_findings.py` surfaces as a `## Coverage Gaps` section in REPORT.md. To enable container/Makefile enrichment on OpenCode, re-run with `frsr --console-cmd "docker compose exec -T <php-service> php bin/console"` (or a Makefile passthrough `frsr --console-cmd "make console CMD={args}"`) — it exports `FR_SECURITY_CONSOLE_CMD` so the space-containing template survives; for an explicit static-only run, pass `--no-console`.
5. Set `CONSOLE_CMD` (the resolved `--console-cmd=...`, `--no-console`, `env` → the utility reads `FR_SECURITY_CONSOLE_CMD`, or none) and forward it to the recon worker in step 5.

> The choice is always deterministic on OpenCode. For a containerized project, `frsr --console-cmd "<template>"` (→ `FR_SECURITY_CONSOLE_CMD`, `CONSOLE_CMD = env`) is the space-safe way to enable console enrichment; with no console command set, the run proceeds static-only with a recorded `console_gap` (ceiling=medium) — the safe default.

