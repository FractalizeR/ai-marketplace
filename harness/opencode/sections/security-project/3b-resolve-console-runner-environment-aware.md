### 3b. Resolve console runner (environment-aware)

Console enrichment (running the project's `bin/console` for routes / ceiling=high) is the only recon step that **executes the project**. Running it on the host when the project lives **inside a container** distorts the environment (wrong PHP version, services unreachable). This step decides HOW to run it, then boot-tests it before recon depends on it. OpenCode has no interactive-prompt primitive, so resolution is **non-interactive**: driven entirely by flags plus the static probe, and a console that is applicable but does not boot **stops the run** rather than degrading silently.

Skip this whole step (set `CONSOLE_CMD = none`, proceed to step 4) when `--skip-recon` is taken (CONTEXT.md is reused, not regenerated).

Otherwise, resolve `CONSOLE_CMD`:

- `--no-console` was passed → forward `--no-console` to the recon worker (user's explicit static-only choice). Wins over everything below.
- `--console-cmd=<tpl>` was passed → forward `--console-cmd=<tpl>` verbatim (user already chose the runner). **Caveat on OpenCode:** a template with spaces (almost all container/Makefile commands) is truncated by the whitespace-split argument contract — prefer the environment variable below, which `frsr --console-cmd` sets for you.
- **`FR_SECURITY_CONSOLE_CMD` is set in the environment** — check `[ -n "$FR_SECURITY_CONSOLE_CMD" ]`. A launcher (`frsr --console-cmd "docker compose exec -T php bin/console"`) or CI exported the console command out-of-band so its spaces ride the environment intact. Set `CONSOLE_CMD = env` and forward exactly that token (`console_mode=env`) to the recon worker and to the boot-test below — **never** substitute or echo the variable's value into the prompt. `recon_inventory.py` reads `FR_SECURITY_CONSOLE_CMD` itself. This is the clean, space-safe way to enable container/Makefile console on OpenCode. (`--no-console` still wins; an explicit `--console-cmd=<tpl>` flag takes precedence when it survived intact.)
- None of the above:
  1. **Detect whether the stack even has console enrichment.** Run `python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect` and read `recipe`. Only **Symfony** has console enrichment today (Laravel/generic are fully static). If `recipe != symfony` → `CONSOLE_CMD = none`, proceed to step 4 with no console flags (the boot-test below is a no-op for it).
  2. **Probe the environment** (read-only; runs only host `php --version` + file reads — safe even for untrusted repos):

     ```bash
     python3 ${FR_SECURITY_CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
     ```

     This prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.
  3. **If `containerized == false` AND `host_php_present == true`** → the host is a faithful runner. `CONSOLE_CMD = none` (the recon utility auto-selects the host runner).
  4. **Otherwise (containerized, or no host php)** → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively** (the show-and-confirm trust model is impossible without a prompt). `CONSOLE_CMD = none` — the boot-test below catches this as `ok=false` and stops the run with the fix-it flags, instead of silently filing a coverage gap.

5. **Boot-test the resolved runner.**

   ```bash
   python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --console-preflight [--console-cmd=<tpl> | --no-console]
   ```

   Pass the same flag you'd forward to recon in step 4; nothing extra for `env` or `none`. Read the JSON result:
   - `applicable=false` or `ok=true` → forward `CONSOLE_CMD` to the recon worker in step 4.
   - `ok=false` (exit 3) → **stop the run.** Print `reason` and `suggestions` verbatim, plus the fix-it flags: `--console-cmd "<template>"` (or `frsr --console-cmd "<template>"` → `FR_SECURITY_CONSOLE_CMD`, the space-safe path on OpenCode) for a working runner, or `--no-console` for an explicit static-only run. OpenCode has no prompt to fall back on, so an unresolved console is a hard stop here, not a coverage gap.

> OpenCode never prompts, so the boot-test is the only gate: a working `--console-cmd` / `FR_SECURITY_CONSOLE_CMD`, or an explicit `--no-console`, makes the run proceed deterministically; a containerized project with no console command, or a command that fails to boot, stops the run with the flags above.

