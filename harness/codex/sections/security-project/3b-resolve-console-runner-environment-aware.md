### 3b. Resolve console runner (environment-aware)

Console enrichment (running the project's `bin/console` for routes / ceiling=high) is the only recon step that **executes the project**. Running it on the host when the project lives **inside a container** distorts the environment (wrong PHP version, services unreachable). This step decides HOW to run it, expressed as a `CONSOLE_MODE` value forwarded to recon in step 4. Codex runs headless (`codex exec`, approval `never`), so resolution is **non-interactive**: it is driven entirely by flags plus the static probe, and when the choice is ambiguous it degrades to static-only with a loud, recorded coverage gap rather than guessing.

Skip this whole step (set `CONSOLE_MODE = off`, proceed to step 4) when **any** of these holds:

- `--no-console` was passed → `CONSOLE_MODE = off` (user's explicit static-only choice).
- `--console-cmd=<tpl>` was passed → `CONSOLE_MODE = <tpl>` verbatim (user already chose the runner).
- `--skip-recon` path is taken (CONTEXT.md is reused, not regenerated).

Otherwise:

1. **Detect whether the stack even has console enrichment.** Run `python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect` and read `recipe`. Only **Symfony** has console enrichment today (Laravel/generic are fully static). If `recipe != symfony` → nothing to resolve, proceed to step 4 with `CONSOLE_MODE = off`.

2. **Probe the environment** (read-only; runs only host `php --version` + file reads — safe even for untrusted repos):

   ```bash
   python3 ${FR_SECURITY_CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
   ```

   This prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.

3. **If `containerized == false` AND `host_php_present == true`** → the host is a faithful runner. Set `CONSOLE_MODE = auto` (the recon utility auto-selects the host runner) and proceed to step 4.

4. **Otherwise (containerized, or no host php)** → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively** (the show-and-confirm trust model is impossible without a prompt). Set `CONSOLE_MODE = off` and **record the gap**: the recon utility detects the unresolved containerized console and writes a loud `console_gap` (ceiling=medium) into CONTEXT.md, which `dedupe_findings.py` surfaces as a `## Coverage Gaps` section in REPORT.md. Nothing is silently dropped — reduced coverage is visible. To get container/Makefile console enrichment on Codex, re-run with an explicit `--console-cmd="docker compose exec -T <php-service> php bin/console"` (or a Makefile passthrough `--console-cmd="make console CMD={args}"`); to declare an explicit static-only run, pass `--no-console`.

5. Forward `CONSOLE_MODE` to the recon worker in step 4 (`off` | `auto` | a container/Makefile command).

> The choice is always deterministic on Codex: pass `--console-cmd`/`--no-console` to control it. With neither flag on a containerized project, the run proceeds static-only with a recorded `console_gap` (ceiling=medium) — the safe default, surfaced in REPORT.md so nothing is silently dropped.
