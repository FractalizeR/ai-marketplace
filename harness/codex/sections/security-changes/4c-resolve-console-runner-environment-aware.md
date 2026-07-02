### 4c. Resolve console runner (environment-aware)

Decide HOW to run the project console (the only recon step that **executes the project**), expressed as a `CONSOLE_MODE` value forwarded to recon in step 5. Running it on the host when the project lives inside a container distorts the environment (wrong PHP version, services unreachable). Codex runs headless (`codex exec`, approval `never`), so resolution is **non-interactive**: flags plus the static probe only, degrading to static-only with a recorded coverage gap when ambiguous rather than guessing.

Skip this whole step (set `CONSOLE_MODE = off`) when **any** holds:

- `--no-console` was passed → `CONSOLE_MODE = off` (static-only).
- `--console-cmd=<tpl>` was passed → `CONSOLE_MODE = <tpl>` verbatim.
- `--skip-recon` path is taken (CONTEXT.md is reused).

Otherwise:

1. Detect the recipe: `python3 ${CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect`. Console enrichment applies to **Symfony** only — for other recipes proceed with `CONSOLE_MODE = off`.
2. Probe (read-only, safe even for untrusted repos):

   ```bash
   python3 ${CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
   ```

   It prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.
3. If `containerized == false` AND `host_php_present == true` → the host is a faithful runner; set `CONSOLE_MODE = auto` (the recon utility auto-selects the host).
4. Otherwise (containerized, or no host php) → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively**. Set `CONSOLE_MODE = off`; the recon utility records a loud `console_gap` (ceiling=medium) in CONTEXT.md, which `dedupe_findings.py` surfaces as a `## Coverage Gaps` section in REPORT.md. To enable container/Makefile enrichment on Codex, re-run with an explicit `--console-cmd="docker compose exec -T <php-service> php bin/console"` (or a Makefile passthrough `--console-cmd="make console CMD={args}"`); for an explicit static-only run, pass `--no-console`.
5. Forward `CONSOLE_MODE` (`off` | `auto` | a container/Makefile command) to the recon worker in step 5.

> The choice is always deterministic on Codex: pass `--console-cmd`/`--no-console` to control it. With neither flag on a containerized project, the run proceeds static-only with a recorded `console_gap` (ceiling=medium) — the safe default.
