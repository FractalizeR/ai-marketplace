"""Subprocess sandbox helpers shared by recon_inventory utility + recipes.

Two concerns:

1. **`run_extractor`** — spawn `bin/recon/extract_php_metadata.php` with
   `--kind=<KIND>` against a target file or directory. Enforces timeout,
   memory_limit, and project-root containment. Returns `(parsed_json, warning)`.

2. **Console enrichment** — `try_console_smoke` quickly probes whether the
   project's framework console is runnable; `run_console_command` runs
   individual subcommands (with timeout). Both operate on a caller-supplied
   `ConsoleRunner` that describes HOW to invoke the console — directly on the
   host (`php bin/console`), inside a container (`docker compose exec -T php
   php bin/console`), via a custom wrapper / Makefile target, or `php artisan`
   for Laravel. The module is therefore stack-agnostic and path-agnostic: it
   no longer checks that `bin/console` exists on the host — that responsibility
   belongs to whoever constructs the `ConsoleRunner`.

The recipe receives `no_console: bool` — when True, it builds a
`disabled_runner(...)` and emits `console_disabled_by_flag` warning. When
False, the recipe is free to attempt `try_console_smoke`; failure → degrade to
static-only with warning.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from recon.types import PathOutsideProjectRoot, assert_inside_project


# ---------------------------------------------------------------------------
# Extractor sandbox.
# ---------------------------------------------------------------------------

EXTRACTOR_TIMEOUT_SECONDS = 60
# Bumped 256M → 512M after vimeo/psalm CallMap_*.php blew memory_limit on a
# real Symfony project. Extractor scans many files in one process — a single
# auto-generated giant can starve the rest. Combined with --max-file-size cap
# this is belt-and-suspenders, but bumping the floor is cheap.
EXTRACTOR_MEMORY_LIMIT = "512M"

# Default exclude prefixes (relative to project_root). Whole subtrees here are
# never descended into by extract_php_metadata.php's RecursiveDirectoryIterator,
# so vendor/, var/cache/, node_modules/ files never reach token_get_all().
# Keep aligned with extract_php_metadata.php:DEFAULT_EXCLUDE for parity when
# users invoke the extractor manually for debugging.
DEFAULT_EXCLUDE: tuple[str, ...] = (
    "vendor",
    "var/cache",
    "var/log",
    "node_modules",
    "storage/framework/cache",
    "storage/logs",
    "bootstrap/cache",
    "public/build",
    ".git",
)

# Default per-file size cap. Files larger than this are skipped by the
# extractor with a stderr warning. 2 MiB is enough for any hand-written PHP
# class; the cap targets auto-generated giants like vimeo/psalm CallMap.
DEFAULT_MAX_FILE_SIZE: int = 2 * 1024 * 1024


def _normalize_exclude(extra: Optional[tuple[str, ...]]) -> tuple[str, ...]:
    """Merge DEFAULT_EXCLUDE with caller-supplied extras; dedupe, preserve order.

    Each entry is a relative-to-project-root prefix (no leading slash).
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in (*DEFAULT_EXCLUDE, *(extra or ())):
        if not isinstance(raw, str):
            continue
        norm = raw.strip().strip("/")
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return tuple(out)


def run_extractor(
    plugin_root: Path,
    project_root: Path,
    kind: str,
    target: Path,
    timeout: int = EXTRACTOR_TIMEOUT_SECONDS,
    *,
    exclude: Optional[tuple[str, ...]] = None,
    max_file_size: Optional[int] = None,
) -> tuple[Optional[dict], Optional[str]]:
    """Run extract_php_metadata.php sandboxed; return (parsed_json, warning).

    Path-safety: target must resolve under project_root (raises if not).
    On timeout / non-zero exit / JSON-parse failure → (None, warning_string).
    The PHP extractor itself receives `--project-root=<project_root>` so it
    rejects any symlink that escapes the project tree.

    `exclude`        — extra path prefixes (relative to project_root) appended
                       to DEFAULT_EXCLUDE. None == defaults only.
    `max_file_size`  — per-file byte cap; oversize files are skipped with
                       a stderr warning. None == DEFAULT_MAX_FILE_SIZE.
    """
    extractor = plugin_root / "bin" / "recon" / "extract_php_metadata.php"
    if not extractor.is_file():
        return None, f"extract_php_metadata.php missing at {extractor}"
    try:
        target_safe = assert_inside_project(target, project_root)
    except PathOutsideProjectRoot as e:
        return None, f"path_outside_project_root: {e}"
    merged_exclude = _normalize_exclude(exclude)
    effective_max_size = DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size
    cmd = [
        "php", "-d", f"memory_limit={EXTRACTOR_MEMORY_LIMIT}",
        str(extractor),
        f"--kind={kind}",
        f"--project-root={project_root.resolve()}",
        f"--exclude={','.join(merged_exclude)}",
        f"--max-file-size={effective_max_size}",
        str(target_safe),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"extract_php_metadata --kind={kind} timed out after {timeout}s"
    except FileNotFoundError:
        return None, "php executable not found on PATH"
    if proc.returncode != 0:
        stderr = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
        return None, f"extract_php_metadata --kind={kind} exit={proc.returncode}: {stderr[:200]}"
    if not proc.stdout.strip():
        return None, f"extract_php_metadata --kind={kind} produced empty output"
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError as e:
        return None, f"extract_php_metadata --kind={kind} invalid JSON: {e}"


# ---------------------------------------------------------------------------
# Console enrichment.
# ---------------------------------------------------------------------------

# Mode-aware timeouts. Containers and custom wrappers are slower than a host
# invocation — a cold container start (image pull-less but service boot, PHP
# warmup, autoload priming) can eat tens of seconds before the console even
# begins executing. Host stays tight; container/custom get the larger budget.
CONSOLE_SMOKE_TIMEOUT_HOST = 30
CONSOLE_SMOKE_TIMEOUT_CONTAINER = 60
CONSOLE_COMMAND_TIMEOUT_HOST = 60
CONSOLE_COMMAND_TIMEOUT_CONTAINER = 120

# Backwards-compatible aliases for the pre-refactor constant names. Some other
# modules may still import these by name; they map to the HOST values.
CONSOLE_SMOKE_TIMEOUT_SECONDS = CONSOLE_SMOKE_TIMEOUT_HOST
CONSOLE_COMMAND_TIMEOUT_SECONDS = CONSOLE_COMMAND_TIMEOUT_HOST

# Default smoke probes: try `list` first (cheapest, enumerates all commands),
# fall back to `debug:router --format=json` (targeted, doesn't require every
# bundle's Kernel to boot cleanly). Success if ANY probe exits 0.
_DEFAULT_SMOKE_PROBES: tuple[tuple[str, ...], ...] = (
    ("list",),
    ("debug:router", "--format=json"),
)


@dataclass
class ConsoleRunner:
    """Describes HOW to invoke a project's framework console.

    `mode`            — one of "host" | "container" | "custom" | "disabled".
                        Drives default timeout selection (host vs container/
                        custom) and the early-return short-circuit when
                        "disabled".
    `cmd_template`    — the full command string up to AND including the
                        entrypoint, e.g. "php bin/console",
                        "docker compose exec -T php php bin/console",
                        "php artisan", or a Makefile target like
                        "make console CMD={args}". May contain the literal
                        substring "{args}" as a placeholder for the
                        shell-quoted subcommand args (see build_console_argv).
                        None iff mode == "disabled".
    `cwd`             — working directory for the subprocess.
    `disabled_reason` — when mode == "disabled", the warning string returned
                        by the run functions in lieu of executing anything.
    """

    mode: str
    cmd_template: Optional[str]
    cwd: Path
    disabled_reason: Optional[str] = None


def disabled_runner(reason: str, cwd: Path) -> ConsoleRunner:
    """Construct a no-op runner that never spawns a subprocess.

    The run functions short-circuit on mode == "disabled" and surface
    `reason` as their warning. Used when console enrichment is suppressed
    (e.g. `--no-console`) or no runnable console could be resolved.
    """
    return ConsoleRunner(mode="disabled", cmd_template=None, cwd=cwd, disabled_reason=reason)


def host_runner(cmd_template: str, cwd: Path) -> ConsoleRunner:
    """Construct a host-mode runner (direct invocation, e.g. `php bin/console`)."""
    return ConsoleRunner(mode="host", cmd_template=cmd_template, cwd=cwd)


def container_runner(cmd_template: str, cwd: Path) -> ConsoleRunner:
    """Construct a container-mode runner (e.g. `docker compose exec -T php ...`)."""
    return ConsoleRunner(mode="container", cmd_template=cmd_template, cwd=cwd)


def custom_runner(cmd_template: str, cwd: Path) -> ConsoleRunner:
    """Construct a custom-mode runner (user wrapper / Makefile target)."""
    return ConsoleRunner(mode="custom", cmd_template=cmd_template, cwd=cwd)


def build_console_argv(runner: ConsoleRunner, console_args: list[str]) -> list[str]:
    """Resolve a runner's cmd_template + subcommand args into an argv list.

    This rule is a shared contract with other modules — keep it precise:

    - If "{args}" is a literal substring of `cmd_template`: replace it with
      `shlex.quote(" ".join(console_args))` — i.e. quote the space-joined
      args as ONE shell token — then `shlex.split(...)` the whole resolved
      string and return that list. The point of "{args}" is a Makefile-style
      passthrough (`make console CMD={args}`) where the entire subcommand must
      collapse into a single make-variable value, so the args stay glued to
      whatever prefix they substitute into.
    - Otherwise: return `shlex.split(cmd_template) + list(console_args)`.

    `console_args` may be empty. `cmd_template` must not be None (callers
    short-circuit disabled runners before reaching here).

    Examples:
      host:      "php bin/console" + ["debug:router", "--format=json"]
                 -> ["php", "bin/console", "debug:router", "--format=json"]
      container: "docker compose exec -T php php bin/console" + ["list"]
                 -> ["docker", "compose", "exec", "-T", "php",
                     "php", "bin/console", "list"]
      makefile:  "make console CMD={args}" + ["debug:router", "--format=json"]
                 -> ["make", "console", "CMD=debug:router --format=json"]
                 (the space-joined args are quoted as ONE token, so the final
                 shlex.split keeps "CMD=debug:router --format=json" glued).
      empty:     "make console CMD={args}" + []
                 -> ["make", "console", "CMD="]
                 (shlex.quote("") == "''", so CMD= becomes a bare empty value).
    """
    template = runner.cmd_template
    if template is None:
        raise ValueError("build_console_argv called on a runner with no cmd_template")
    if "{args}" in template:
        resolved = template.replace("{args}", shlex.quote(" ".join(console_args)))
        return shlex.split(resolved)
    return shlex.split(template) + list(console_args)


def _smoke_timeout_for(runner: ConsoleRunner, timeout: Optional[int]) -> int:
    if timeout is not None:
        return timeout
    return CONSOLE_SMOKE_TIMEOUT_HOST if runner.mode == "host" else CONSOLE_SMOKE_TIMEOUT_CONTAINER


def _command_timeout_for(runner: ConsoleRunner, timeout: Optional[int]) -> int:
    if timeout is not None:
        return timeout
    return CONSOLE_COMMAND_TIMEOUT_HOST if runner.mode == "host" else CONSOLE_COMMAND_TIMEOUT_CONTAINER


def try_console_smoke(
    runner: ConsoleRunner,
    *,
    probes: Optional[list[list[str]]] = None,
    timeout: Optional[int] = None,
) -> tuple[bool, Optional[str]]:
    """Quick probe: can the runner's console execute SOME probe with rc=0?

    Multi-probe fallback (default probes: `list`, then
    `debug:router --format=json`). First probe returning rc=0 ⇒ (True, None).
    Each probe is executed via `build_console_argv(runner, probe)` and run with
    `cwd=runner.cwd`. `subprocess.TimeoutExpired`, `FileNotFoundError` and
    `OSError` are treated as a failed probe (the next probe is still tried).

    - mode == "disabled" ⇒ return (False, runner.disabled_reason or
      "console_disabled") WITHOUT spawning any subprocess.
    - All probes fail ⇒ (False, "console_smoke_failed: <short reason>") where
      <short reason> summarizes the last probe's error/stderr (capped ~200).

    `timeout` overrides the mode-derived default (host vs container/custom).

    SECURITY: this DOES execute project code (Kernel boot for Symfony).
    Recipes must NOT call this when console enrichment is disabled — they
    should build a `disabled_runner(...)` instead.
    """
    if runner.mode == "disabled":
        return False, runner.disabled_reason or "console_disabled"

    effective_timeout = _smoke_timeout_for(runner, timeout)
    probe_list = probes if probes is not None else [list(p) for p in _DEFAULT_SMOKE_PROBES]
    last_reason = "no probes attempted"
    for probe in probe_list:
        argv = build_console_argv(runner, probe)
        try:
            proc = subprocess.run(
                argv,
                cwd=runner.cwd,
                capture_output=True, text=True, timeout=effective_timeout,
            )
        except subprocess.TimeoutExpired:
            last_reason = f"timed out after {effective_timeout}s"
            continue
        except FileNotFoundError:
            last_reason = f"command not found ({argv[0] if argv else '?'})"
            continue
        except OSError as e:
            last_reason = f"os error: {e}"
            continue
        if proc.returncode == 0:
            return True, None
        if proc.stderr.strip():
            last_reason = proc.stderr.strip().splitlines()[-1]
        else:
            last_reason = f"rc={proc.returncode}"
    return False, f"console_smoke_failed: {last_reason[:200]}"


def run_console_command(
    runner: ConsoleRunner,
    args: list[str],
    *,
    timeout: Optional[int] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Run a single console subcommand via `runner`. Return (stdout, warning).

    - mode == "disabled" ⇒ (None, runner.disabled_reason or
      "console_disabled") WITHOUT spawning any subprocess.
    - rc 0 ⇒ (stdout, None).
    - nonzero ⇒ (None, "console_command_failed: <args>: <last stderr, capped>").
    - TimeoutExpired ⇒ (None, "console_command_failed: <args> timed out ...").
    - FileNotFoundError ⇒ (None, "console_command_failed: command not found (...)").

    `timeout` overrides the mode-derived default (host vs container/custom).
    Caller (recipe) treats any warning as a per-command failure: the section
    gets a `warnings` entry, static-collected items remain.
    """
    if runner.mode == "disabled":
        return None, runner.disabled_reason or "console_disabled"

    effective_timeout = _command_timeout_for(runner, timeout)
    argv = build_console_argv(runner, args)
    args_repr = " ".join(args)
    try:
        proc = subprocess.run(
            argv,
            cwd=runner.cwd,
            capture_output=True, text=True, timeout=effective_timeout,
        )
    except subprocess.TimeoutExpired:
        return None, f"console_command_failed: {args_repr} timed out after {effective_timeout}s"
    except FileNotFoundError:
        return None, f"console_command_failed: command not found ({argv[0] if argv else '?'})"
    if proc.returncode != 0:
        last = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"rc={proc.returncode}"
        return None, f"console_command_failed: {args_repr}: {last[:200]}"
    return proc.stdout, None
