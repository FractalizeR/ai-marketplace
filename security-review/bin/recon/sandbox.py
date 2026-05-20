"""Subprocess sandbox helpers shared by recon_inventory utility + recipes.

Two concerns:

1. **`run_extractor`** — spawn `bin/recon/extract_php_metadata.php` with
   `--kind=<KIND>` against a target file or directory. Enforces timeout,
   memory_limit, and project-root containment. Returns `(parsed_json, warning)`.

2. **Console enrichment** (Symfony-style) — `try_console_smoke` quickly probes
   `bin/console list`; `run_console_command` runs individual `debug:*`
   commands (with timeout). Both return `(stdout, warning)`. Recipes that
   want console enrichment call these from `build_inventory`.

The recipe receives `no_console: bool` — when True, it skips console probes
and emits `console_disabled_by_flag` warning. When False, the recipe is free
to attempt `try_console_smoke`; failure → degrade to static-only with warning.
"""

from __future__ import annotations

import json
import subprocess
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
# Console probes.
# ---------------------------------------------------------------------------

CONSOLE_SMOKE_TIMEOUT_SECONDS = 30
CONSOLE_COMMAND_TIMEOUT_SECONDS = 60


def _run_smoke_probe(
    bin_console: Path,
    project_root: Path,
    args: list[str],
    timeout: int,
) -> tuple[bool, Optional[str], bool]:
    """Run a single smoke probe; return (ok, short_error, infra_failure).

    `short_error` is None when ok=True; otherwise a compact reason string
    (already truncated to ~200 chars) suitable for embedding in a warning.

    `infra_failure=True` signals an environment-level failure that no
    retry of a different command will recover from (e.g. `php` missing
    from PATH). Timeout is intentionally NOT infra: the probe target may
    be flaky, and a lighter command (e.g. `debug:router`) might still
    succeed within budget.
    """
    try:
        proc = subprocess.run(
            ["php", str(bin_console), *args],
            cwd=project_root,
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s", False
    except FileNotFoundError:
        return False, "php not on PATH", True
    if proc.returncode != 0:
        last = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"rc={proc.returncode}"
        return False, last[:200], False
    return True, None, False


def try_console_smoke(
    project_root: Path,
    timeout: int = CONSOLE_SMOKE_TIMEOUT_SECONDS,
) -> tuple[bool, Optional[str]]:
    """Quick probe: does `php bin/console <cmd>` exit 0 within `timeout`?

    Two-step fallback:

    1. Try `bin/console list` first — cheapest, lists all commands.
    2. If `list` failed, try `bin/console debug:router --format=json` —
       targeted command that doesn't require a fully-booted Kernel for
       every bundle. Useful when an unrelated bundle blows up during
       `list` (autoload/env issues seen in real prod projects).

    First-success wins: any probe returning rc=0 ⇒ (True, None).
    Both fail ⇒ (False, "console_smoke_failed: list+debug:router both
    failed: <list_err> | <router_err>") — both errors embedded for
    diagnosability, each truncated to keep the warning compact.

    Note: `debug:router --format=json` may emit large stdout — we don't
    parse it, only check returncode. Symfony 4.x without `--format=json`
    will fail this probe too; that's acceptable (best-effort fallback).

    SECURITY: this DOES execute project PHP code (Kernel boot). Recipes must
    NOT call this when `no_console=True`. Plan rev 3.3 Security model.
    """
    bin_console = project_root / "bin" / "console"
    if not bin_console.is_file():
        return False, "console_smoke_failed: bin/console missing"
    ok, list_err, infra = _run_smoke_probe(bin_console, project_root, ["list"], timeout)
    if ok:
        return True, None
    if infra:
        return False, f"console_smoke_failed: {list_err}"
    ok2, router_err, _ = _run_smoke_probe(
        bin_console, project_root, ["debug:router", "--format=json"], timeout,
    )
    if ok2:
        return True, None
    return False, (
        f"console_smoke_failed: list+debug:router both failed: "
        f"{list_err} | {router_err}"
    )


def run_console_command(
    project_root: Path,
    args: list[str],
    timeout: int = CONSOLE_COMMAND_TIMEOUT_SECONDS,
) -> tuple[Optional[str], Optional[str]]:
    """Run `php bin/console <args>` with timeout. Return (stdout, warning).

    On timeout / non-zero exit → (None, warning_string). Caller (recipe)
    treats warning as per-command failure: section gets `warnings` entry,
    static-collected items remain. Plan rev 3.4 F-E.1.
    """
    bin_console = project_root / "bin" / "console"
    if not bin_console.is_file():
        return None, f"console_command_failed: bin/console missing for {' '.join(args)}"
    cmd = ["php", str(bin_console), *args]
    try:
        proc = subprocess.run(
            cmd, cwd=project_root, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, f"console_command_failed: {' '.join(args)} timed out after {timeout}s"
    except FileNotFoundError:
        return None, "console_command_failed: php not on PATH"
    if proc.returncode != 0:
        last = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"rc={proc.returncode}"
        return None, f"console_command_failed: {' '.join(args)}: {last[:200]}"
    return proc.stdout, None
