### 4c. Resolve console runner (environment-aware)

Decide HOW to run the project console (the only recon step that **executes the project**), then boot-test it before recon depends on it. Running it on the host when the project lives inside a container distorts the environment (wrong PHP version, services unreachable). OpenCode has no interactive-prompt primitive, so resolution is **non-interactive**: flags plus the static probe only, and a console that is applicable but does not boot **stops the run** rather than degrading silently.

Skip this whole step (set `CONSOLE_CMD = none`) when `--skip-recon` is taken (CONTEXT.md is reused).

Otherwise, resolve `CONSOLE_CMD`:

- `--no-console` was passed → forward `--no-console` to the recon worker (step 5). Wins over everything below.
- `--console-cmd=<tpl>` was passed → forward it verbatim. **Caveat on OpenCode:** a template with spaces is truncated by the whitespace-split argument contract — prefer the environment variable below.
- **`FR_SECURITY_CONSOLE_CMD` is set in the environment** (`[ -n "$FR_SECURITY_CONSOLE_CMD" ]`) — a launcher (`frsr --console-cmd "docker compose exec -T php bin/console"`) or CI exported the console command out-of-band → `CONSOLE_CMD = env`; forward `console_mode=env`, **not** the variable's space-containing value. `recon_inventory.py` reads `FR_SECURITY_CONSOLE_CMD` itself. The clean, space-safe container/Makefile console path on OpenCode.
- Neither of the above:
  1. Detect the recipe: `python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect`. Console enrichment applies to **Symfony** only — for other recipes `CONSOLE_CMD = none` (the boot-test below is a no-op for it).
  2. Probe (read-only, safe even for untrusted repos):

     ```bash
     python3 ${FR_SECURITY_CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
     ```

     It prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.
  3. If `containerized == false` AND `host_php_present == true` → the host is a faithful runner; `CONSOLE_CMD = none` (the recon utility auto-selects the host).
  4. Otherwise (containerized, or no host php) → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively**. `CONSOLE_CMD = none` — the boot-test below catches this as `ok=false` and stops the run with the fix-it flags, instead of silently filing a coverage gap.

5. **Boot-test the resolved runner:**

   ```bash
   python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --console-preflight [--console-cmd=<tpl> | --no-console]
   ```

   Pass the same flag you'd forward to recon in step 5; nothing extra for `env` or `none`. `applicable=false` / `ok=true` → forward `CONSOLE_CMD` to the recon worker in step 5. `ok=false` (exit 3) → **stop the run.** Print `reason` and `suggestions` verbatim, plus the fix-it flags: `--console-cmd "<template>"` (or `frsr --console-cmd "<template>"` → `FR_SECURITY_CONSOLE_CMD`) for a working runner, or `--no-console` for an explicit static-only run. OpenCode has no prompt to fall back on, so an unresolved console is a hard stop here, not a coverage gap.

> OpenCode never prompts, so the boot-test is the only gate: a working `--console-cmd` / `FR_SECURITY_CONSOLE_CMD`, or an explicit `--no-console`, makes the run proceed deterministically; a containerized project with no console command, or a command that fails to boot, stops the run with the flags above.

