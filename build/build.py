"""Build CLI: derive the Codex bundle from the authoritative Claude prose.

Each artifact (``commands/*.md``, ``agents/*.md``) is split into sections and
rendered by ``derive.derive_artifact`` (authored templates for the
harness-coupled sections, token substitution for the rest), then gated
(``gates.check_codex_output``).

  --mode=check  (default)  render in memory, run the structural gates, the
                           authored-config validation and a determinism re-render;
                           never write. exit 0 clean / 1 gate / 2 error.
  --mode=write             same gates, fail-closed, then build a self-hosted
                           marketplace bundle (default ``dist/codex/``, gitignored)
                           via a rename-aside atomic swap.
  --mode=refresh-hashes    rewrite each section template's ``source-sha256``
                           header to the current Claude section (run after
                           reviewing a template flagged stale); body untouched.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from derive import (
    ArtifactKind,
    derive_artifact,
    kind_for,
    load_templates,
    refreshed_templates,
)
from gates import check_codex_output
from bundle import (
    bundle_core,
    copy_codex_static_configs,
    place_codex_marketplace,
    validate_codex_configs,
    safe_plugin_name,
    BUNDLE_MARKER,
)

_PLUGIN_DIRNAME = "security-review"
_DEFAULT_PLUGIN_ROOT = Path(__file__).resolve().parent.parent / _PLUGIN_DIRNAME
_BUILD_DIR = Path(__file__).resolve().parent
_DIST_ROOT = _BUILD_DIR.parent / "dist"
_DIST_CODEX = _DIST_ROOT / "codex"
_HARNESS_CODEX = _BUILD_DIR.parent / "harness" / "codex"
_TEMPLATES = _HARNESS_CODEX / "sections"


def render_codex_artifact(path: Path) -> tuple[str, list[str]]:
    """Derive one artifact; returns ``(text, template problems)``."""
    source = path.read_bytes().decode("utf-8")
    return derive_artifact(source, kind=kind_for(path), name=path.stem,
                           templates=load_templates(path.stem, _TEMPLATES))


def _gate(rendered: dict[Path, str]) -> list[str]:
    out: list[str] = []
    for path, text in rendered.items():
        is_skill = kind_for(path) is ArtifactKind.COMMAND
        out += [f"{path.name}: {v}" for v in check_codex_output(text, is_skill=is_skill)]
    return out


def codex_out_path(path: Path, plugin_out: Path) -> Path:
    """Output topology under the plugin dir: orchestrators are Codex *skills*
    (``skills/<name>/SKILL.md``); workers are read-follow files under the shared
    core (``core/agents/<name>.md``), where the dispatch templates' absolute
    ``${FR_SECURITY_CORE_ROOT}/agents/<name>.md`` / ``{core_root}/agents/<name>.md`` resolve."""
    if path.parent.name == "commands":
        return plugin_out / "skills" / path.stem / "SKILL.md"
    return plugin_out / "core" / "agents" / f"{path.stem}.md"


def _guard_out(out: Path) -> None:
    """Refuse to overwrite ``out`` unless it is clearly ours to replace.

    A build writes by swapping a fresh bundle into ``out`` (moving any existing
    tree aside first). Guard that destructive step against an operator-supplied
    path that is neither the repo's own ``dist/`` nor a prior bundle — the class of
    the ``--review-root=src`` incident (clobbering a real source tree)."""
    if not out.exists():
        return
    if not out.is_dir():
        raise ValueError(f"--out target exists and is not a directory: {out}")
    resolved = out.resolve()
    # Never write over an authored source tree, even if a marker somehow appears there.
    for protected in (_HARNESS_CODEX, _DEFAULT_PLUGIN_ROOT, _BUILD_DIR):
        if resolved == protected.resolve():
            raise ValueError(f"refusing to overwrite the source tree at {out}")
    # Never write *at* the dist/ root itself: the swap would move the whole dist/
    # aside, and the "under dist/ is ours" branch below would wave it through.
    # --out must be a per-harness subdir (dist/codex).
    if resolved == _DIST_ROOT.resolve():
        raise ValueError(
            f"refusing to overwrite the dist/ root itself ({out}); "
            "point --out at a per-harness subdir (e.g. dist/codex)."
        )
    try:
        resolved.relative_to(_DIST_ROOT.resolve())
        return  # anything strictly under the repo's dist/ is ours
    except ValueError:
        pass
    if (out / BUNDLE_MARKER).is_file():
        return  # carries our dedicated sentinel → a prior build's output
    raise ValueError(
        f"refusing to overwrite {out}: it is not under the repo's dist/ and carries "
        f"no bundle marker ({BUNDLE_MARKER}). Point --out at a fresh dir or a prior bundle."
    )


def discover_artifacts(plugin_root: Path) -> list[Path]:
    """The Claude-discovered artifact set: commands/*.md + agents/*.md."""
    found = sorted(
        list((plugin_root / "commands").glob("*.md"))
        + list((plugin_root / "agents").glob("*.md"))
    )
    if not found:
        raise FileNotFoundError(f"no command/agent artifacts under {plugin_root}")
    return found


def _atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _run_codex(args) -> int:
    # A bundle must be complete: --artifact would emit only the listed artifacts
    # beside a full core/ + configs, i.e. a silently partial bundle.
    if args.mode == "write" and args.artifact:
        print("ERROR: --artifact is incompatible with --mode=write "
              "(a bundle must contain the full skill/agent set).", file=sys.stderr)
        return 2
    artifacts = args.artifact or discover_artifacts(args.plugin_root)
    rendered: dict[Path, str] = {}
    violations: list[str] = []
    for path in artifacts:
        rendered[path], problems = render_codex_artifact(path)
        violations += [f"{path.name}: {p}" for p in problems]
    plugin_name = safe_plugin_name(_HARNESS_CODEX)  # safe token or None (reported below)
    # Authored-config validation applies to BOTH modes: check vets the in-git files;
    # write is fail-closed on the same problems before emitting. It derives + validates
    # the plugin name itself, so a bad name is a structured gate problem (exit 1), not
    # an unhandled exception.
    violations = validate_codex_configs(_HARNESS_CODEX) + violations + _gate(rendered)

    if args.mode == "write":
        out = (args.out or _DIST_CODEX).resolve()
        if violations or plugin_name is None:
            for v in violations:
                print(f"GATE: {v}", file=sys.stderr)
            return 1
        _write_codex_bundle(out, rendered, plugin_root=args.plugin_root,
                            plugin_name=plugin_name)
        print(f"wrote: {out}")
        return 0

    for path in artifacts:
        if render_codex_artifact(path)[0] != rendered[path]:
            violations.append(f"{path.name}: non-deterministic render")
    if violations:
        for v in violations:
            print(f"GATE: {v}", file=sys.stderr)
        return 1
    print(f"codex: {len(artifacts)} artifacts pass structural gates")
    return 0


def _run_refresh(args) -> int:
    # The templates are always the repo's, so hashing a scratch --plugin-root copy
    # would silently bless prose that is not the authoritative one.
    if args.plugin_root.resolve() != _DEFAULT_PLUGIN_ROOT.resolve() or args.artifact:
        print("ERROR: --mode=refresh-hashes hashes the repo's own artifacts; "
              "--plugin-root/--artifact are not accepted.", file=sys.stderr)
        return 2
    problems: list[str] = []
    for path in discover_artifacts(args.plugin_root):
        source = path.read_bytes().decode("utf-8")
        updates, errs = refreshed_templates(
            source, name=path.stem, templates=load_templates(path.stem, _TEMPLATES))
        problems += [f"{path.name}: {e}" for e in errs]
        for tpl_path, text in updates.items():
            _atomic_write(tpl_path, text.encode("utf-8"))
            print(f"refreshed: {tpl_path}")
    for p in problems:
        print(f"GATE: {p}", file=sys.stderr)
    return 1 if problems else 0


def _codex_readfollow_refs(rendered: dict[Path, str]) -> set[str]:
    """The set of ``agents/<file>.md`` filenames the dispatch templates read.

    Role-agnostic (any ``agents/<name>.md``, not a hardcoded role list) so a typo'd
    or renamed ref to an agent file the bundle does NOT produce is caught by the
    write-path correspondence assertion — a narrow allowlist would fail *open* for a
    new/misspelled name (3B code review)."""
    refs: set[str] = set()
    for text in rendered.values():
        for m in re.finditer(r"agents/([\w.-]+\.md)", text):
            refs.add(m.group(1))
    return refs


def _write_codex_bundle(out: Path, rendered: dict[Path, str], *, plugin_root: Path,
                        plugin_name: str) -> None:
    """Materialize the full self-hosted marketplace bundle: build into a fresh
    staging dir beside the target, then rename-aside swap it into ``out`` (a
    crash leaves *either* the old or the new
    tree at ``out``, never partial). The bundle has two roots in one tree: the
    marketplace (``.agents/plugins/marketplace.json``) and the plugin
    (``plugins/<name>/``)."""
    _guard_out(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=str(out.parent), prefix=f".{out.name}.staging."))
    (staging / BUNDLE_MARKER).write_text(
        "fr-security-review Codex bundle (generated; do not edit)\n", encoding="utf-8")
    plugin_out = staging / "plugins" / plugin_name
    backup: Path | None = None
    try:
        # bundle_core appends `core/` itself → pass the plugin dir, not .../core.
        bundle_core(plugin_out, plugin_root=plugin_root)
        for path, text in rendered.items():
            dest = codex_out_path(path, plugin_out)
            dest.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(dest, text.encode("utf-8"))
        copy_codex_static_configs(plugin_out, harness_root=_HARNESS_CODEX)
        place_codex_marketplace(staging, harness_root=_HARNESS_CODEX)
        # Fail closed if a dispatch template reads an agent file we did not emit.
        produced = {p.name for p in (plugin_out / "core" / "agents").glob("*.md")}
        missing = _codex_readfollow_refs(rendered) - produced
        if missing:
            raise AssertionError(
                f"dispatch templates read agent files not in the bundle: {sorted(missing)}")
        if out.exists():
            backup = out.with_name(f".{out.name}.backup.{os.getpid()}")
            os.replace(out, backup)      # move the old bundle aside
        os.replace(staging, out)         # put the new one in place
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        if backup is not None and not out.exists():
            os.replace(backup, out)      # restore the old bundle on failure
        raise
    finally:
        if backup is not None and backup.exists():
            shutil.rmtree(backup, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Derive the Codex bundle from Claude prose.")
    parser.add_argument("--harness", choices=["codex"], default="codex")
    parser.add_argument("--mode", choices=["check", "write", "refresh-hashes"],
                        default="check")
    parser.add_argument("--plugin-root", type=Path, default=_DEFAULT_PLUGIN_ROOT)
    parser.add_argument("--artifact", type=Path, action="append", default=None,
                        help="Specific artifact(s); default = discovered set (check only).")
    parser.add_argument("--out", type=Path, default=None,
                        help="Bundle output root (--mode=write; defaults to dist/codex).")
    args = parser.parse_args(argv)
    try:
        if args.mode == "refresh-hashes":
            return _run_refresh(args)
        return _run_codex(args)
    except Exception as exc:  # noqa: BLE001 - CLI boundary: any failure is exit 2
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
