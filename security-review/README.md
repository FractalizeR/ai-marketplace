# fr-security-review

Framework-aware static-first security audit for Claude Code: recipe-driven recon, focused worker waves, deterministic deduplication.

Supported stacks: Symfony, Laravel, generic PHP. The GraphQL layer (lighthouse, rebing-laravel, api-platform, webonyx) is detected automatically in Symfony and Laravel.

## Quick start

After installing the plugin from the marketplace, use two slash commands:

| Command | Purpose |
| --- | --- |
| `/fr-security-review:security-project` | Security audit of the whole project |
| `/fr-security-review:security-changes` | Security audit of the current branch diff against master |

Minimum run:

```
/fr-security-review:security-project
```

Artifacts are written to `security-review-<label>/` in the current working directory. The folder is automatically added to a local `.gitignore` (`<review_root>/.gitignore` with the content `*`); the project-level `.gitignore` is not modified.

## Pipeline

1. **Recon.** A recipe (Symfony / Laravel / generic PHP) collects a structured inventory of the project without an LLM: routes, middleware, controllers, data models, voters, form classes, listeners, messenger handlers, etc. The result is `<review_root>/CONTEXT.md` (schema v2 with frontmatter and closed shape specs).
2. **Plan waves.** `plan_waves.py` slices the inventory into thematic waves (auth+disclosure, injection+data-access, output-render, serialization+crypto, ssrf+fileops, fintech, exploratory) and assigns each one its own set of checklists and target files.
3. **Workers.** Parallel workers, 6 per batch, balanced-profile models: opus for analysis of trust boundaries (W1/W2/W6), sonnet for mechanical data-flow (W3/W4/W5/W∞).
4. **Dedupe.** `dedupe_findings.py` stitches per-wave findings into a split report: `REPORT.md` (executive summary + index) + `REPORT/<root_cause_family>.md` (details).

### ⚠️ Token consumption

`/fr-security-review:security-project` launches several parallel Opus/Sonnet workers on each run (W1–W6 + W∞ + adversarial pass). Cost depends on the model and project size.

**Flags for CI / cost saving:**
- `--quick` — disables W∞ (cross-layer chain analysis).
- `--no-adversarial` — disables the refute pass.
- `--ci` — alias for `--quick --no-adversarial`.

For your own project, `bin/dedupe/cost.py estimate <review_root>` after the first run shows the actual tokens.

## Security model

**What the plugin reads and executes:**

- **Read-only.** The recipe and checklists only read the project source code; they never modify files outside `<review_root>/`.
- **Console smoke by default.** The recon utility may run `bin/console list` (Symfony) or `php artisan list` (Laravel) to enrich sections (available commands, registered services, etc.). Timeout 30 seconds, memory limits — but **the project's bootstrap code is executed in the process**.
- **PHP metadata extractor.** `bin/recon/extract_php_metadata.php` parses PHP files via `token_get_all` without require/include — it does not execute project code. Subprocess sandbox: `timeout=60s`, `memory_limit=256M`, path traversal protection via `Path.resolve() + is_relative_to(project_root)`.
- **Worker tools.** Workers use Read, Grep, Glob; no Write to project files, no git commands except safe read-only ones, no code execution.

**When isolation is needed:**

- Auditing an untrusted/hostile repository (composer post-install hooks, service constructors with side effects).
- CI/CD without runtime credentials.
- Sandbox mode inside corporate infrastructure.

**Two isolation options:**

### Option 1 — `--no-console` flag

Fully disables console smoke. Recon works only via static file parsing:

```
/fr-security-review:security-project --no-console
```

`recon_confidence.ceiling` is forcibly lowered to `medium` (some sections remain on static heuristics). This is intentional — so that workers do not draw conclusions from a full inventory that does not exist.

`--no-console` does not protect against a vulnerability in the PHP metadata extractor itself (even though it does not require the code), or against extended read-only utilities. If the repo is truly hostile, add a sandbox.

### Option 2 — sandbox via firejail (Linux)

The idea: run Claude Code in a sandbox without network access, with read-write access only to the project directory. Specific firejail flags depend on the version and distribution — a starting point:

```bash
firejail --private="/path/to/project" --net=none claude code
```

Adapt options to your environment (see `firejail --help` and `man firejail`). For strict scenarios, Docker is more predictable.

### Option 3 — sandbox via Docker

Minimal Dockerfile:

```dockerfile
FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git python3 php-cli && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code
WORKDIR /workspace
```

Run with a mounted review-root to persist artifacts and `--review-root` for an explicit path:

```bash
docker run --rm -it \
  -v "$(pwd):/workspace:ro" \
  -v "$(pwd)/security-review-docker:/review:rw" \
  -e ANTHROPIC_API_KEY \
  claude-sandbox \
  claude /fr-security-review:security-project --review-root=/review --no-console
```

`--review-root` is required to override the label-based path; inside the container the cwd is read-only, while review-root is read-write on the host.

## Composite repositories (monorepos with a PHP subproject)

If your repository's `composer.json` / framework configs sit in a subdirectory (typical monorepo layout: a top-level `CLAUDE.md` plus a PHP project in `api/`, `backend/`, `services/php-api/`, …), pass `--project-root=<path>` so recon, exclusions, and worker file resolution all target the correct root:

```bash
# Monorepo root contains CLAUDE.md; PHP code is in api/:
claude /fr-security-review:security-project --project-root=api
```

What `--project-root` affects:

- **Recon** scans the project at `<PROJECT_ROOT>` (composer.json detection, framework detection, file globs).
- **CLAUDE.md** is read from both `<cwd>/CLAUDE.md` and `<PROJECT_ROOT>/CLAUDE.md` (whichever exist). Paths in `## Code review exclusions` sections are interpreted as `PROJECT_ROOT`-relative — write `legacy/`, not `api/legacy/`, in either file.
- **Workers** receive `project_root` and resolve `target_files` against it (without the flag, they would read relative to cwd and miss files in monorepos).
- **`/security-changes`** runs `git -C "<PROJECT_ROOT>"` for all git operations.

`--review-root=<out-dir>` is **independent** — it specifies where the review writes its output (`CONTEXT.md`, `waves/`, `REPORT.md`). It does NOT specify what to scan. The orchestrator rejects `--review-root=src` (and other source-tree-looking names) with a clear error, since pointing it at your source tree would clobber `src/.gitignore`.

## Project-specific exclusions

In addition to the built-in safe defaults (`vendor/`, `var/cache/`, `var/log/`, `node_modules/`, `storage/framework/cache/`, `storage/logs/`, `bootstrap/cache/`, `public/build/`, `.git/`), which the PHP extractor skips *before* parsing, you can exclude additional directories:

- **`CLAUDE.md`** — the recommended way for recurring project-level conditions. Before running recon, the orchestrator reads CLAUDE.md from both `<cwd>` and `<PROJECT_ROOT>` (for composite repos these are different files) and automatically extracts path prefixes from the `## Code review exclusions` section (or its equivalent). It is not parsed by regex — Claude reads it naturally. **All paths are `PROJECT_ROOT`-relative**; entries that don't resolve inside `PROJECT_ROOT` are skipped with a warning. Recommended format:

  ```markdown
  ## Code review exclusions
  Do not analyze in security review:
  - legacy/                — legacy code, will be removed in Q4
  - src/ThirdParty/        — vendored code, not our contract
  - generated/             — autogenerated, no review needed
  ```

- **`--exclude=<csv>`** — command flag for one-off exclusions:

  ```
  /fr-security-review:security-project --exclude=legacy,src/ThirdParty
  ```

Both sources are merged with the built-in `DEFAULT_EXCLUDE` (they do not replace it). Before running recon, the orchestrator prints the resulting list — the user sees what will not be analyzed. Applied project-level excludes are recorded in `frontmatter.warnings` of the final `<review_root>/CONTEXT.md` as `exclude_paths_user: <list>` for audit.

**When to add an exclude:** auto-generated code, vendored mirrors, legacy code before removal, directories with test fixtures that knowingly contain "vulnerabilities" for testing. Do not add directories you want to analyze — this lowers the recall of the security review.

**Per-file size cap.** Files larger than 2 MiB (for example, `vimeo/psalm/dictionaries/CallMap_*.php`) are skipped by the extractor with a warning in stderr. This is an OOM safeguard, even if the file falls inside the analyzed subtree.

## Self-introspection and parallel runs

Without `--label`, commands perform self-introspection and pick a label from the dictionary: `claude | codex | gemini | deepseek | qwen | other-<short>`. Review-root becomes `security-review-<label>/` — parallel runs of different models on the same project do not conflict.

**Known limitation:** open-weight fine-tunes (Qwen/DeepSeek) may incorrectly identify themselves as Claude. For CI/Docker, pass `--label` explicitly.

## Version and compatibility

Current major version is 4.x. Full changelog — in [CHANGELOG.md](CHANGELOG.md).

- `schema_version: 2` for `<review_root>/CONTEXT.md`. Old v1 artifacts (`<project_root>/SECURITY_CONTEXT.md`) are not read — slash commands detect them and emit a warning.
- Multi-stack monorepos — out of scope. One primary stack per project.

## Principles

- **Never commit review artifacts.** The local `<review_root>/.gitignore` already ignores all content. You can commit explicitly via `git add -f`.
- **The recon agent is the single writer to CONTEXT.md.** No workers, slash commands, or MCP should overwrite it.
- **Worker failure ≠ abort of the whole review.** Continue with the remaining waves.

## License

Elastic License 2.0. Full text — in the repository root ([LICENSE](../LICENSE)).

In short: free use (including in commercial and proprietary projects) is permitted. Prohibited: providing the plugin to third parties as a hosted/managed service, circumventing license mechanisms, removing copyright/attribution.
