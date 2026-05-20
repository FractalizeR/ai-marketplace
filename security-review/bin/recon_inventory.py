#!/usr/bin/env python3
"""recon_inventory — single writer of <review_root>/CONTEXT.md (schema v2).

CLI:
  recon_inventory.py <project_root> --detect
      → JSON with detected stack and available recipes. Exit 0 on match,
        1 if no recipe matches (bare directory).

  recon_inventory.py <project_root> --recipe <name> --review-root <dir>
                                    [--diff-files=<file>] [--no-console]
                                    [--force-recipe]
      → Writes <dir>/CONTEXT.md (schema v2) + <dir>/.gitignore="*". Idempotent.
        --no-console (S1): currently always set; console enrichment is S2.

  recon_inventory.py --review-root <dir> --validate
      → Delegates to validate_context.py against <dir>/CONTEXT.md.

stdlib only. Imports siblings via sys.path manipulation.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Make sibling modules importable.
_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(_BIN))

import compute_fingerprint as fp  # noqa: E402
from recon import recipes as recipes_pkg  # noqa: E402
from recon import sandbox as _sandbox  # noqa: E402
from recon.recipes import (  # noqa: E402
    detect_best,
    load_recipe,
    available_recipes,
    STACK_DETECT_THRESHOLD,
)
from recon.types import (  # noqa: E402
    InventoryResult,
    SectionPayload,
    StackMatch,
    PathOutsideProjectRoot,
    assert_inside_project,
)
from recon.yaml_emit import dump_yaml_subset, dump_frontmatter  # noqa: E402


# Re-export sandbox helpers so existing callers (tests, recipes) keep working.
run_extractor = _sandbox.run_extractor
EXTRACTOR_TIMEOUT_SECONDS = _sandbox.EXTRACTOR_TIMEOUT_SECONDS
EXTRACTOR_MEMORY_LIMIT = _sandbox.EXTRACTOR_MEMORY_LIMIT


# ---------------------------------------------------------------------------
# Review-root + .gitignore management.
# ---------------------------------------------------------------------------

GITIGNORE_CONTENT = "*\n"


def ensure_review_root(review_root: Path) -> None:
    """Create review_root + .gitignore=`*` (idempotent: don't overwrite custom)."""
    review_root.mkdir(parents=True, exist_ok=True)
    gi = review_root / ".gitignore"
    if not gi.is_file():
        gi.write_text(GITIGNORE_CONTENT, encoding="utf-8")


def _resolve_review_root(project_root: Path, review_root_arg: Path) -> Path:
    if review_root_arg.is_absolute():
        return review_root_arg.resolve()
    return (project_root / review_root_arg).resolve()


# ---------------------------------------------------------------------------
# CONTEXT.md emission.
# ---------------------------------------------------------------------------


def _payload_to_dict(payload: SectionPayload) -> dict:
    """Drop None fields. M5: surface `data={}` as an explicit error rather than
    silently producing a status=ok scalar with no `data` key.
    """
    out: dict = {"status": payload.status}
    if payload.reason is not None:
        out["reason"] = payload.reason
    if payload.enrichment_hint is not None:
        out["enrichment_hint"] = payload.enrichment_hint
    if payload.items is not None:
        out["items"] = payload.items
    if payload.data is not None:
        if not payload.data:
            raise ValueError(
                f"Section payload has empty data={{}} (status={payload.status!r}); "
                "use status=unknown / pending_enrichment / data=None instead"
            )
        out["data"] = payload.data
    if payload.source_files is not None:
        out["source_files"] = payload.source_files
    if payload.warnings:
        out["warnings"] = payload.warnings
    return out


def _enrichment_marker(scope: str) -> str:
    """Stable, unique anchor token for Edit-only enrichment flow (plan section C).

    Format: `<scope>__pending__<sha8>`. Recon-agent matches the marker as part
    of `old_string`; on success it must rewrite `pending` → `done`, making the
    Edit naturally idempotent (retried Edit fails on `old_string not found`).
    """
    h = hashlib.sha256(scope.encode("utf-8")).hexdigest()[:8]
    return f"{scope}__pending__{h}"


def _section_md(section_id: str, payload: SectionPayload) -> str:
    """Emit `## Title` + anchor + (optional enrichment_marker) + fenced yaml."""
    title = section_id.replace("_", " ").title()
    yaml_text = dump_yaml_subset(_payload_to_dict(payload))
    marker = ""
    if payload.status == "pending_enrichment":
        marker = f"<!-- enrichment_marker: {_enrichment_marker(section_id)} -->\n"
    return (
        f"## {title}\n"
        f"<!-- section_id: {section_id} -->\n"
        f"{marker}\n"
        f"```yaml\n{yaml_text}```\n\n"
    )


def _framework_specific_md(framework: str, fs_payloads: dict[str, SectionPayload]) -> str:
    """Emit framework_specific bag as one section with `<framework>: { keys }` shape.

    Pending bag-keys carry their own enrichment_marker so recon-agent can Edit
    each independently.
    """
    if not fs_payloads:
        return ""
    markers = []
    nested: dict = {framework: {}}
    for k, payload in fs_payloads.items():
        nested[framework][k] = _payload_to_dict(payload)
        if payload.status == "pending_enrichment":
            scope = f"framework_specific.{framework}.{k}"
            markers.append(f"<!-- enrichment_marker: {_enrichment_marker(scope)} -->")
    yaml_text = dump_yaml_subset(nested)
    marker_block = ("\n".join(markers) + "\n") if markers else ""
    return (
        f"## Framework Specific\n"
        f"<!-- section_id: framework_specific -->\n"
        f"{marker_block}\n"
        f"```yaml\n{yaml_text}```\n\n"
    )


def _write_context_atomic(review_root: Path, frontmatter: dict, body: str) -> Path:
    """Atomically write `<review_root>/CONTEXT.md`.

    Uses a uniquely-named temp file in the same directory so that two
    concurrent runs into the same `--review-root` cannot clobber each
    other's `*.tmp` (prior implementation used a fixed `CONTEXT.md.tmp`,
    which would race on overlapping invocations).
    """
    import tempfile as _tempfile
    out = review_root / "CONTEXT.md"
    text = dump_frontmatter(frontmatter) + "\n" + body
    fd, tmp_path = _tempfile.mkstemp(prefix=".CONTEXT.md.", suffix=".tmp", dir=str(review_root))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_path, out)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return out


# ---------------------------------------------------------------------------
# Frontmatter helpers.
# ---------------------------------------------------------------------------


def _git_rev(project_root: Path) -> tuple[str, Optional[str]]:
    """Return (sha, warning). warning=None when git rev-parse succeeded."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root, capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            return proc.stdout.strip(), None
        msg = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"rc={proc.returncode}"
        return "unknown", f"git_rev_unavailable: {msg[:200]}"
    except FileNotFoundError:
        return "unknown", "git_rev_unavailable: git not on PATH"
    except (OSError, subprocess.TimeoutExpired) as e:
        return "unknown", f"git_rev_unavailable: {e}"


def _stack_block(recipe, project_root: Path) -> dict:
    match: Optional[StackMatch] = recipe.detect(project_root)
    framework = "none" if recipe.RECIPE_NAME == "generic_php" else recipe.RECIPE_NAME
    if match is None:
        return {
            "language": getattr(recipe, "LANGUAGE", "unknown"),
            "framework": "unknown",
            "framework_version": None,
            "detected_via": "none",
        }
    return {
        "language": getattr(recipe, "LANGUAGE", "unknown"),
        "framework": framework,
        "framework_version": match.version,
        "detected_via": ", ".join(match.evidence) if match.evidence else "heuristic",
    }


def _tool_versions(project_root: Path) -> dict:
    out: dict = {"mcp_phpstorm": "unavailable"}
    composer = project_root / "composer.json"
    if not composer.is_file():
        return out
    try:
        data = json.loads(composer.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    if not isinstance(data, dict):
        return out
    for dep_name, out_key in (
        ("symfony/framework-bundle", "symfony"),
        ("doctrine/orm", "doctrine"),
    ):
        for section in ("require", "require-dev"):
            deps = data.get(section)
            if isinstance(deps, dict) and dep_name in deps:
                ver = deps[dep_name]
                if isinstance(ver, str):
                    out[out_key] = ver
                break
    return out


def _confidence(result: InventoryResult, no_console: bool) -> dict:
    """Compute recon_confidence dict {level, ceiling}.

    Rev 3.3 ceiling policy: ceiling=medium whenever console enrichment did not
    actually run (M1). Source of truth — `result.sources_used`: if no entry
    starts with "console:", we did not enrich, regardless of CLI flag. This
    keeps S1 stubs (which never run console) at ceiling=medium even without
    --no-console.
    """
    if result.status == "ok":
        level = "high"
    elif result.status == "partial":
        level = "medium"
    else:
        level = "low"
    console_used = any(
        isinstance(s, str) and s.startswith("console:") for s in result.sources_used
    )
    ceiling = "high" if (console_used and not no_console) else "medium"
    if ceiling == "medium" and level == "high":
        level = "medium"
    return {"level": level, "ceiling": ceiling}


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------


def cmd_detect(project_root: Path) -> int:
    project_root = project_root.resolve()
    if not project_root.is_dir():
        print(f"error: not a directory: {project_root}", file=sys.stderr)
        return 2
    picked = detect_best(project_root)
    output = {
        "project_root": str(project_root),
        "available_recipes": available_recipes(),
        "stack_detect_threshold": STACK_DETECT_THRESHOLD,
    }
    if picked is None:
        output["stack"] = {"name": "unknown", "confidence": 0.0, "evidence": []}
        print(json.dumps(output, indent=2))
        return 1
    name, m = picked
    output["stack"] = {
        "name": name,
        "version": m.version,
        "confidence": m.confidence,
        "evidence": m.evidence,
    }
    output["recipe"] = name
    print(json.dumps(output, indent=2))
    return 0


def cmd_inventory(
    project_root: Path,
    recipe_name: str,
    review_root_arg: Path,
    diff_files: Optional[set[str]],
    no_console: bool,
    exclude: Optional[tuple[str, ...]] = None,
) -> int:
    project_root = project_root.resolve()
    if not project_root.is_dir():
        print(f"error: project root not a directory: {project_root}", file=sys.stderr)
        return 2

    try:
        recipe = load_recipe(recipe_name)
    except ModuleNotFoundError:
        print(
            f"error: unknown recipe: {recipe_name} "
            f"(available: {', '.join(available_recipes())})",
            file=sys.stderr,
        )
        return 2

    review_root = _resolve_review_root(project_root, review_root_arg)
    # L4: warn (not error) if review-root falls outside project_root. Plan
    # rev 3.7 explicitly allows absolute paths for Docker / firejail / read-only
    # mounts, so we don't reject — just surface the situation.
    try:
        review_root.resolve().relative_to(project_root.resolve())
    except ValueError:
        print(
            f"warning: --review-root {review_root} is outside project_root {project_root}; "
            "ensure your sandbox/CI permits writing there",
            file=sys.stderr,
        )

    plugin_root = _BIN.parent
    result: InventoryResult = recipe.build_inventory(
        project_root,
        diff_files=diff_files,
        plugin_root=plugin_root,
        no_console=no_console,
        exclude=exclude,
    )

    pf = fp.compute_project_fingerprint(project_root)
    cf = fp.compute_code_fingerprint(project_root)

    warnings = list(result.warnings)
    if no_console:
        warnings.append("console_disabled_by_flag")
    if exclude:
        # Surface user-supplied excludes in frontmatter for auditability — so
        # downstream consumers (worker, dedupe, REPORT) can see what was
        # intentionally skipped beyond DEFAULT_EXCLUDE.
        warnings.append(
            "exclude_paths_user: " + ", ".join(exclude)
        )

    git_rev, git_warning = _git_rev(project_root)
    if git_warning is not None:
        warnings.append(git_warning)

    # Dedupe while preserving order so a recipe that calls the extractor
    # multiple times (e.g. attack_surface + data_access + doctrine_listeners
    # all need --kind=class) does not produce a noisy frontmatter.
    sources_used_dedup: list[str] = []
    seen_sources: set[str] = set()
    for src in result.sources_used:
        if src in seen_sources:
            continue
        seen_sources.add(src)
        sources_used_dedup.append(src)
    warnings_dedup: list[str] = []
    seen_warnings: set[str] = set()
    for w in warnings:
        if w in seen_warnings:
            continue
        seen_warnings.add(w)
        warnings_dedup.append(w)

    frontmatter = {
        "schema_version": 2,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "git_rev": git_rev,
        "project_fingerprint": pf,
        "code_fingerprint": cf,
        "scope": "changes" if diff_files is not None else "project",
        "stack": _stack_block(recipe, project_root),
        "recipe_used": recipe.RECIPE_NAME,
        "tool_versions": _tool_versions(project_root),
        "sources_used": sources_used_dedup,
        "missing_sections": result.missing_sections,
        "recon_confidence": _confidence(result, no_console),
        "warnings": warnings_dedup,
        "errors": result.errors,
    }

    body_parts = []
    for sid, payload in result.core.items():
        body_parts.append(_section_md(sid, payload))
    body_parts.append(
        _framework_specific_md(recipe.RECIPE_NAME, result.framework_specific)
    )

    ensure_review_root(review_root)
    out = _write_context_atomic(review_root, frontmatter, "".join(body_parts))

    print(f"wrote {out}")
    if result.status == "failed":
        return 1
    return 0


def cmd_validate(review_root_arg: Path) -> int:
    review_root = review_root_arg.resolve()
    context_path = review_root / "CONTEXT.md"
    if not context_path.is_file():
        print(f"error: CONTEXT.md not found in {review_root}", file=sys.stderr)
        return 2
    import validate_context as vc
    res = vc.validate_context_file(context_path)
    for w in res.warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    for e in res.errors:
        print(f"ERROR: {e}", file=sys.stderr)
    return 0 if res.ok() else 1


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _parse_diff_files(arg: Optional[Path]) -> Optional[set[str]]:
    if arg is None:
        return None
    if not arg.is_file():
        print(f"error: --diff-files not found: {arg}", file=sys.stderr)
        sys.exit(2)
    return {ln.strip() for ln in arg.read_text(encoding="utf-8").splitlines() if ln.strip()}


def _parse_exclude(arg: Optional[str]) -> Optional[tuple[str, ...]]:
    """Parse `--exclude=a,b,c` into a tuple of normalized prefixes.

    None / empty → None (caller passes no extras, only DEFAULT_EXCLUDE applies).
    Each entry is stripped of whitespace and surrounding slashes; empty
    entries (e.g. trailing comma) are dropped.
    """
    if not arg:
        return None
    parts: list[str] = []
    for raw in arg.split(","):
        norm = raw.strip().strip("/")
        if norm:
            parts.append(norm)
    return tuple(parts) if parts else None


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Recon inventory writer (schema v2)")
    parser.add_argument("project_root", type=Path, nargs="?", help="Project root")
    parser.add_argument("--detect", action="store_true", help="Detect stack only")
    parser.add_argument("--recipe", help="Recipe name (e.g. symfony, generic_php)")
    parser.add_argument("--review-root", type=Path, help="Output directory for CONTEXT.md")
    parser.add_argument("--diff-files", type=Path, default=None, help="File listing changed files")
    parser.add_argument("--no-console", action="store_true",
                        help="Do not invoke bin/console (static-only inventory)")
    parser.add_argument("--exclude", default=None,
                        help="CSV of project-root-relative path prefixes to skip pre-parse "
                             "(appended to built-in DEFAULT_EXCLUDE: vendor, var/cache, "
                             "node_modules, etc). Used by orchestrator to forward "
                             "project-specific CLAUDE.md exclusions.")
    parser.add_argument("--validate", action="store_true",
                        help="Validate <review-root>/CONTEXT.md against schema")
    args = parser.parse_args(argv)

    if args.validate:
        if args.review_root is None:
            print("error: --validate requires --review-root", file=sys.stderr)
            return 2
        return cmd_validate(args.review_root)

    if args.project_root is None:
        print("error: project_root is required (or use --validate --review-root)", file=sys.stderr)
        return 2

    if args.detect:
        if args.recipe or args.review_root:
            print("error: --detect is mutually exclusive with --recipe/--review-root", file=sys.stderr)
            return 2
        return cmd_detect(args.project_root)

    if args.recipe is None:
        print("error: --recipe is required (or use --detect)", file=sys.stderr)
        return 2
    if args.review_root is None:
        print("error: --review-root is required with --recipe", file=sys.stderr)
        return 2

    diff_files = _parse_diff_files(args.diff_files)
    exclude = _parse_exclude(args.exclude)
    return cmd_inventory(
        args.project_root, args.recipe, args.review_root, diff_files, args.no_console,
        exclude,
    )


if __name__ == "__main__":
    sys.exit(main())
