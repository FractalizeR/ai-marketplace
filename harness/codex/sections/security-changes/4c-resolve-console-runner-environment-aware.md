### 4c. Resolve console runner (environment-aware)

Decide HOW to run the project console (the only recon step that **executes the project**), expressed as a `CONSOLE_MODE` value forwarded to recon in step 5, then boot-test it before recon depends on it. Running it on the host when the project lives inside a container distorts the environment (wrong PHP version, services unreachable). Codex runs headless (`codex exec`, approval `never`), so resolution is **non-interactive**: flags plus the static probe only, and a console that is applicable but does not boot **stops the run** rather than degrading silently.

Skip this whole step when `--skip-recon` is taken (CONTEXT.md is reused).

Otherwise, resolve `CONSOLE_MODE`:

- `--no-console` was passed → `CONSOLE_MODE = off` (static-only). Wins over everything below.
- `--console-cmd=<tpl>` was passed → `CONSOLE_MODE = <tpl>` verbatim. **Caveat on Codex:** a template with spaces is truncated by the whitespace-split argument contract — prefer the environment variable below.
- **`FR_SECURITY_CONSOLE_CMD` is set in the environment** (`[ -n "$FR_SECURITY_CONSOLE_CMD" ]`) — a launcher (`frsr --console-cmd "docker compose exec -T php bin/console"`) or CI exported the console command out-of-band → `CONSOLE_MODE = env`; forward that token, **not** the variable's space-containing value. `recon_inventory.py` reads `FR_SECURITY_CONSOLE_CMD` itself. The clean, space-safe container/Makefile console path on Codex.
- Neither of the above:
  1. Detect the recipe: `python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect`. Console enrichment applies to **Symfony** only — for other recipes `CONSOLE_MODE = auto` (the recipe declares no console entrypoint, so the utility records console enrichment as N/A rather than as a gap; the boot-test below is a no-op for it).
  2. Probe (read-only, safe even for untrusted repos):

     ```bash
     python3 ${FR_SECURITY_CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
     ```

     It prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.
  3. If `containerized == false` AND `host_php_present == true` → the host is a faithful runner; `CONSOLE_MODE = auto` (the recon utility auto-selects the host).
  4. Otherwise (containerized, or no host php) → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively**. `CONSOLE_MODE = auto` — the boot-test below catches this as `ok=false` and stops the run with the fix-it flags, instead of silently filing a coverage gap.

5. **Boot-test the resolved runner:**

   ```bash
   python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --console-preflight [--console-cmd=<tpl> | --no-console]
   ```

   Pass the same token you'd forward to recon in step 5; nothing extra for `env` or `auto`. `applicable=false` / `ok=true` → forward `CONSOLE_MODE` (`off` | `auto` | `env` | a container/Makefile command) to the recon worker in step 5. `ok=false` (exit 3) → **stop the run.** Print `reason` and `suggestions` verbatim, plus the fix-it flags: `--console-cmd "<template>"` (or `frsr --console-cmd "<template>"` → `FR_SECURITY_CONSOLE_CMD`) for a working runner, or `--no-console` for an explicit static-only run. Codex has no prompt to fall back on, so an unresolved console is a hard stop here, not a coverage gap.

> Codex never prompts, so the boot-test is the only gate: a working `--console-cmd` / `FR_SECURITY_CONSOLE_CMD`, or an explicit `--no-console`, makes the run proceed deterministically; a containerized project with no console command, or a command that fails to boot, stops the run with the flags above.
