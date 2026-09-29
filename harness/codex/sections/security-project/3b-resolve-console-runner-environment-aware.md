<!-- source-sha256: 05b4302800a15405ce15f3671d573c3f04dbec5ace2bd8f61b4afbb4a09e43a9 -->
### 3b. Resolve console runner (environment-aware)

Console enrichment (running the project's `bin/console` for routes and the processed framework config / ceiling=high) is the only recon step that **executes the project**, and the only way recon interprets config. Running it on the host when the project lives **inside a container** distorts the environment (wrong PHP version, services unreachable). This step decides HOW to run it, expressed as a `CONSOLE_MODE` value forwarded to recon in step 4, then boot-tests it before recon depends on it. Codex runs headless (`codex exec`, approval `never`), so resolution is **non-interactive**: driven entirely by flags plus the static probe, and a console that is applicable but does not boot **stops the run** rather than degrading silently.

Resolve `CONSOLE_MODE`:

- `--no-console` was passed → `CONSOLE_MODE = off` (user's explicit static-only choice). Wins over everything below. Cost: ceiling=medium, and framework config is not interpreted — those sections come back `partial` (or `pending_enrichment` for `auth_layer`) with a `config_uninterpreted: <alias>: no_console` reason, and their files go to the focused waves (the security config to W1); the WGAP wave gets only gap files no other slice already carries.
- `--console-cmd=<tpl>` was passed → `CONSOLE_MODE = <tpl>` verbatim (user already chose the runner). **Caveat on Codex:** a template with spaces (almost all container/Makefile commands) is truncated by the whitespace-split argument contract — prefer the environment variable below, which `frsr --console-cmd` sets for you.
- **`FR_SECURITY_CONSOLE_CMD` is set in the environment** — check `[ -n "$FR_SECURITY_CONSOLE_CMD" ]`. A launcher (`frsr --console-cmd "docker compose exec -T php bin/console"`) or CI exported the console command out-of-band so its spaces ride the environment intact. `CONSOLE_MODE = env`; forward exactly that token to the recon worker and to the boot-test below — **never** substitute or echo the variable's value into the prompt (its spaces would be re-split). `recon_inventory.py` reads `FR_SECURITY_CONSOLE_CMD` itself. This is the clean, space-safe way to enable container/Makefile console on Codex. (`--no-console` still wins; an explicit `--console-cmd=<tpl>` flag takes precedence when it survived intact.)
- None of the above:
  1. **Detect whether the stack even has console enrichment.** Run `python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --detect` and read `recipe`. Only **Symfony** has console enrichment today (Laravel/generic are fully static). If `recipe != symfony` → `CONSOLE_MODE = auto` (the recipe declares no console entrypoint, so the utility records console enrichment as N/A rather than as a gap; the boot-test below is a no-op for it).
  2. **Probe the environment** (read-only; runs only host `php --version` + file reads — safe even for untrusted repos):

     ```bash
     python3 ${FR_SECURITY_CORE_ROOT}/bin/recon/environment.py "<PROJECT_ROOT>" --console-entrypoint "php bin/console"
     ```

     This prints JSON: `{containerized, container_signals, host_php_present, host_php_version, suggested_php_service, suggestions:[{mode, cmd_template, label, source, detail}], reason}`.
  3. **If `containerized == false` AND `host_php_present == true`** → the host is a faithful runner. `CONSOLE_MODE = auto` (the recon utility auto-selects the host runner).
  4. **Otherwise (containerized, or no host php)** → there is no flag to disambiguate and no way to prompt, so **do not run a repo-derived command speculatively** (the show-and-confirm trust model is impossible without a prompt). `CONSOLE_MODE = auto` — the boot-test below catches this as `ok=false` and stops the run with the fix-it flags, instead of silently filing a coverage gap.

5. **Boot-test the resolved runner.**

   ```bash
   python3 ${FR_SECURITY_CORE_ROOT}/bin/recon_inventory.py "<PROJECT_ROOT>" --console-preflight [--console-cmd=<tpl> | --no-console]
   ```

   Pass the same token you'd forward to recon in step 4; nothing extra for `env` or `auto`. Read the JSON result:
   - `applicable=false` or `ok=true` → forward `CONSOLE_MODE` to the recon worker in step 4 (`off` | `auto` | `env` | a container/Makefile command).
   - `ok=false` (exit 3) → **stop the run.** Print `reason` and `suggestions` verbatim, plus the fix-it flags: `--console-cmd "<template>"` (or `frsr --console-cmd "<template>"` → `FR_SECURITY_CONSOLE_CMD`, the space-safe path on Codex) for a working runner, or `--no-console` for an explicit static-only run. Codex has no prompt to fall back on, so an unresolved console is a hard stop here, not a coverage gap.

> Codex never prompts, so the boot-test is the only gate: a working `--console-cmd` / `FR_SECURITY_CONSOLE_CMD`, or an explicit `--no-console`, makes the run proceed deterministically; a containerized project with no console command, or a command that fails to boot, stops the run with the flags above.
