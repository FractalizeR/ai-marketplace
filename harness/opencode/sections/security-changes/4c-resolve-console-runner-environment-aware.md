### 4c. Resolve console runner (environment-aware)

Decide HOW to run the project console (the only recon step that **executes the project**). Running it on the host when the project lives inside a container distorts the environment (wrong PHP version, services unreachable). OpenCode has no interactive-prompt primitive, so resolution is **non-interactive**: flags plus the static probe only, degrading to static-only with a recorded coverage gap when ambiguous rather than guessing.

Skip this whole step (set `CONSOLE_CMD = none`) when **any** holds:

- `--no-console` was passed → forward `--no-console` to the recon worker (step 5).
- `--console-cmd=<tpl>` was passed → forward it verbatim.
- `--skip-recon` path is taken (CONTEXT.md is reused).

Otherwise:

1. Detect the recipe: `python3 ${CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect`. Console enrichment applies to **Symfony** only — for other recipes proceed with no console flags.
2. Probe (read-only, safe even for untrusted repos):

   ```bash
   python3 ${CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
   ```

   It prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.
3. If `containerized == false` AND `host_php_present == true` → the host is a faithful runner; proceed with no console flags (the recon utility auto-selects the host).
4. Otherwise (containerized, or no host php) → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively**. Proceed with no console flag; the recon utility records a loud `console_gap` (ceiling=medium) in CONTEXT.md, which `dedupe_findings.py` surfaces as a `## Coverage Gaps` section in REPORT.md. To enable container/Makefile enrichment on OpenCode, re-run with an explicit `--console-cmd="docker compose exec -T <php-service> php bin/console"` (or a Makefile passthrough `--console-cmd="make console CMD={args}"`); for an explicit static-only run, pass `--no-console`.
5. Set `CONSOLE_CMD` (the resolved `--console-cmd=...` or `--no-console`, or none) and forward it to the recon worker in step 5.

> The choice is always deterministic on OpenCode: pass `--console-cmd`/`--no-console` to control it. With neither flag on a containerized project, the run proceeds static-only with a recorded `console_gap` (ceiling=medium) — the safe default.

