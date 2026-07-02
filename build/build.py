"""Build CLI: rebuild harness artifacts from the authoritative Claude prose.

``build(segments, adapter)`` is a pure fold. The CLI reads each artifact's
bytes, decodes utf-8 strictly, partitions via ``extract``, renders via the
chosen adapter, re-encodes, and compares **bytes-out == bytes-in**.

  --mode=check  (default)  compute output, diff vs on-disk, never write.
                           exit 0 identical / 1 drift / 2 parse-or-error.
  --mode=write             rewrite in place, only when bytes differ.

For ``--harness=claude`` the round-trip is byte-identical by construction; the
default ``--mode=check`` therefore doubles as a self-consistency gate that
protects the authoritative files. ``opencode`` (Phase 2B) and ``codex`` (Phase 3A)
walk the coarser *section* IR instead: they render coupled sections from authored
templates and token-fold the rest, then run structural gates (no byte oracle).
``--mode=write`` for both bundles into a gitignored ``dist/<harness>/`` tree via a
rename-aside atomic swap (opencode = commands/agents; codex = a self-hosted
marketplace root with ``.codex-plugin``/skills/read-follow agents under ``core/``).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from segments import Segment, assert_partition
from extract import ArtifactKind, extract, CAT_TASK
from adapters import get_adapter, RenderContext
from sections import (
    partition_sections,
    assert_section_partition,
    attach_segments,
    detect_coupling,
    assert_coupling_guards,
)
from prose_coupling import load_pins, pins_for
from gates import (
    check_opencode_output,
    check_dispatch_template,
    check_codex_output,
    check_codex_dispatch_template,
    DISPATCH_ANCHORS,
)
from bundle import (
    bundle_core,
    copy_static_configs,
    validate_static_configs,
    copy_codex_static_configs,
    place_codex_marketplace,
    validate_codex_configs,
    safe_plugin_name,
    BUNDLE_MARKER,
    CODEX_BUNDLE_MARKER,
)

_PLUGIN_DIRNAME = "security-review"
_DEFAULT_PLUGIN_ROOT = Path(__file__).resolve().parent.parent / _PLUGIN_DIRNAME
_BUILD_DIR = Path(__file__).resolve().parent
_REGISTER = _BUILD_DIR / "PROSE_COUPLING.md"
_DIST_ROOT = _BUILD_DIR.parent / "dist"
_DIST_OPENCODE = _DIST_ROOT / "opencode"
_DIST_CODEX = _DIST_ROOT / "codex"
_HARNESS_OPENCODE = _BUILD_DIR.parent / "harness" / "opencode"
_HARNESS_CODEX = _BUILD_DIR.parent / "harness" / "codex"
# Marker→harness map, so _guard_out can refuse an --out carrying the OTHER
# harness's sentinel even under dist/ (a codex write into dist/opencode, etc.).
_ALL_MARKERS = (BUNDLE_MARKER, CODEX_BUNDLE_MARKER)


def build(segments: list[Segment], adapter) -> str:
    """Pure fold: render each segment and concatenate, no injected separators."""
    return "".join(adapter.render_segment(s) for s in segments)


def build_sectioned(sections, adapter, ctx) -> str:
    """Pure fold over the section partition (non-Claude derivation)."""
    return "".join(adapter.render_section(s, ctx) for s in sections)


def render_opencode_artifact(path: Path, adapter, pins) -> str:
    """Full OpenCode derivation pipeline for one authoritative artifact."""
    source = path.read_bytes().decode("utf-8")
    kind = _kind_for(path)
    segments = extract(source, kind)
    assert_partition(segments, source)
    task_spans = [s.span for s in segments if s.category == CAT_TASK]
    sections = partition_sections(source, task_spans=task_spans)
    assert_section_partition(sections, source)
    sections = attach_segments(sections, segments)
    file_rel = f"{path.parent.name}/{path.name}"
    sections = detect_coupling(sections, [p.pinned for p in pins_for(pins, file_rel)])
    assert_coupling_guards(sections)
    ctx = RenderContext(path.stem)
    # Build-time guard: every dispatch template must wire `opencode run`.
    for sec in sections:
        if sec.is_coupled and sec.section_anchor in DISPATCH_ANCHORS:
            problems = check_dispatch_template(adapter.render_section(sec, ctx))
            if problems:
                raise AssertionError(
                    f"{file_rel} [{sec.section_anchor}]: {'; '.join(problems)}"
                )
    return build_sectioned(sections, adapter, ctx)


def render_codex_artifact(path: Path, adapter, pins) -> str:
    """Full Codex derivation pipeline for one authoritative artifact.

    Mirrors ``render_opencode_artifact`` over the SAME section IR + pins; only the
    adapter (token render), the coupled-section templates, and the dispatch guard
    (``check_codex_dispatch_template``: ``codex exec`` read-follow, not ``--agent``)
    diverge."""
    source = path.read_bytes().decode("utf-8")
    kind = _kind_for(path)
    segments = extract(source, kind)
    assert_partition(segments, source)
    task_spans = [s.span for s in segments if s.category == CAT_TASK]
    sections = partition_sections(source, task_spans=task_spans)
    assert_section_partition(sections, source)
    sections = attach_segments(sections, segments)
    file_rel = f"{path.parent.name}/{path.name}"
    sections = detect_coupling(sections, [p.pinned for p in pins_for(pins, file_rel)])
    assert_coupling_guards(sections)
    ctx = RenderContext(path.stem)
    # Build-time guard: every dispatch template must wire `codex exec` read-follow.
    for sec in sections:
        if sec.is_coupled and sec.section_anchor in DISPATCH_ANCHORS:
            problems = check_codex_dispatch_template(adapter.render_section(sec, ctx))
            if problems:
                raise AssertionError(
                    f"{file_rel} [{sec.section_anchor}]: {'; '.join(problems)}"
                )
    return build_sectioned(sections, adapter, ctx)


def opencode_out_path(path: Path, out_root: Path) -> Path:
    """Output topology under ``out_root``: orchestrators are OpenCode *commands*
    (flat ``commands/<name>.md``, invoked ``/name`` with ``$ARGUMENTS``); worker
    agents are ``agents/<name>.md`` (dispatched via ``opencode run --agent <name>``)."""
    if path.parent.name == "commands":
        return out_root / "commands" / f"{path.stem}.md"
    return out_root / "agents" / f"{path.stem}.md"


def codex_out_path(path: Path, plugin_out: Path) -> Path:
    """Output topology under the plugin dir: orchestrators are Codex *skills*
    (``skills/<name>/SKILL.md``); workers are read-follow files under the shared
    core (``core/agents/<name>.md``), where the dispatch templates' absolute
    ``${CORE_ROOT}/agents/<name>.md`` / ``{core_root}/agents/<name>.md`` resolve."""
    if path.parent.name == "commands":
        return plugin_out / "skills" / path.stem / "SKILL.md"
    return plugin_out / "core" / "agents" / f"{path.stem}.md"


def _carries_marker(out: Path, marker: str) -> bool:
    """True if ``out`` carries ``marker`` at its root or in an immediate child dir
    (a bundle's marker sits at its own root, so ``out=dist`` must still see
    ``dist/opencode/<marker>``). One level is enough for the dist-container case."""
    if (out / marker).is_file():
        return True
    try:
        children = [c for c in out.iterdir() if c.is_dir()]
    except OSError:
        return False
    return any((c / marker).is_file() for c in children)


def _guard_out(out: Path, *, marker: str = BUNDLE_MARKER) -> None:
    """Refuse to overwrite ``out`` unless it is clearly ours to replace.

    A build writes by swapping a fresh bundle into ``out`` (moving any existing
    tree aside first). Guard that destructive step against an operator-supplied
    path that is neither the repo's own ``dist/`` nor a prior bundle — the class of
    the ``--review-root=src`` incident (clobbering a real source tree). ``marker``
    defaults to the OpenCode sentinel so the existing caller is untouched; the codex
    write passes ``CODEX_BUNDLE_MARKER``."""
    if not out.exists():
        return
    if not out.is_dir():
        raise ValueError(f"--out target exists and is not a directory: {out}")
    resolved = out.resolve()
    # Never write over an authored source tree, even if a marker somehow appears there.
    for protected in (_HARNESS_OPENCODE, _HARNESS_CODEX, _DEFAULT_PLUGIN_ROOT, _BUILD_DIR):
        if resolved == protected.resolve():
            raise ValueError(f"refusing to overwrite the source tree at {out}")
    # Never write *at* the dist/ root itself: the swap would move the whole dist/
    # (every harness bundle) aside, and the "under dist/ is ours" branch below would
    # wave it through. --out must be a per-harness subdir (dist/codex, dist/opencode).
    if resolved == _DIST_ROOT.resolve():
        raise ValueError(
            f"refusing to overwrite the dist/ root itself ({out}); "
            "point --out at a per-harness subdir (e.g. dist/codex)."
        )
    # Refuse to clobber the OTHER harness's bundle even under dist/ (a codex write
    # into dist/opencode, or vice versa) — each harness only replaces its own. The
    # marker can sit at the swap root OR one level down (dist/<harness>/marker), so
    # scan both — a direct-children-only check misses dist/opencode/<marker>.
    for other in _ALL_MARKERS:
        if other != marker and _carries_marker(out, other):
            raise ValueError(
                f"refusing to overwrite {out}: it (or a bundle beneath it) carries "
                f"another harness's marker ({other}). Point --out at a fresh dir or "
                "this harness's bundle."
            )
    try:
        resolved.relative_to(_DIST_ROOT.resolve())
        return  # anything strictly under the repo's dist/ is ours
    except ValueError:
        pass
    if (out / marker).is_file():
        return  # carries our dedicated sentinel → a prior build's output
    raise ValueError(
        f"refusing to overwrite {out}: it is not under the repo's dist/ and carries "
        f"no bundle marker ({marker}). Point --out at a fresh dir or a prior bundle."
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


def _kind_for(path: Path) -> ArtifactKind:
    parent = path.parent.name
    if parent == "commands":
        return ArtifactKind.COMMAND
    if parent == "agents":
        return ArtifactKind.AGENT
    raise ValueError(f"artifact {path} is not under commands/ or agents/")


def _rebuild_bytes(path: Path, adapter) -> bytes:
    source = path.read_bytes().decode("utf-8")
    segments = extract(source, _kind_for(path))
    assert_partition(segments, source)  # cheap structural guard before any write
    return build(segments, adapter).encode("utf-8")


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


def _run_opencode(args) -> int:
    # A bundle must be complete: --artifact would emit only the listed commands/
    # agents beside a full core/ + configs, i.e. a silently partial bundle.
    if args.mode == "write" and args.artifact:
        print("ERROR: --artifact is incompatible with --harness=opencode --mode=write "
              "(a bundle must contain the full command/agent set).", file=sys.stderr)
        return 2
    adapter = get_adapter("opencode")
    pins = load_pins(_REGISTER)
    artifacts = args.artifact or discover_artifacts(args.plugin_root)
    rendered = {p: render_opencode_artifact(p, adapter, pins) for p in artifacts}
    # Authored-config validation applies to BOTH modes (AR5): check verifies the
    # in-git files; write is fail-closed on the same problems before emitting.
    config_problems = validate_static_configs(_HARNESS_OPENCODE)

    if args.mode == "write":
        out = (args.out or _DIST_OPENCODE).resolve()
        blocked = list(config_problems)
        for path, text in rendered.items():
            blocked += [f"{path.name}: {v}" for v in check_opencode_output(text)]
        if blocked:
            for v in blocked:
                print(f"GATE: {v}", file=sys.stderr)
            return 1
        _write_bundle(out, rendered, plugin_root=args.plugin_root)
        print(f"wrote: {out}")
        return 0

    # check: structural gates + determinism (render again, compare) + configs.
    violations: list[str] = list(config_problems)
    for path, text in rendered.items():
        violations += [f"{path.name}: {v}" for v in check_opencode_output(text)]
    for path in artifacts:
        if render_opencode_artifact(path, adapter, pins) != rendered[path]:
            violations.append(f"{path.name}: non-deterministic render")
    if violations:
        for v in violations:
            print(f"GATE: {v}", file=sys.stderr)
        return 1
    print(f"opencode: {len(artifacts)} artifacts pass structural gates")
    return 0


def _run_codex(args) -> int:
    # A bundle must be complete: --artifact would emit only the listed artifacts
    # beside a full core/ + configs, i.e. a silently partial bundle.
    if args.mode == "write" and args.artifact:
        print("ERROR: --artifact is incompatible with --harness=codex --mode=write "
              "(a bundle must contain the full skill/agent set).", file=sys.stderr)
        return 2
    adapter = get_adapter("codex")
    pins = load_pins(_REGISTER)
    artifacts = args.artifact or discover_artifacts(args.plugin_root)
    rendered = {p: render_codex_artifact(p, adapter, pins) for p in artifacts}
    plugin_name = safe_plugin_name(_HARNESS_CODEX)  # safe token or None (reported below)
    # Authored-config validation applies to BOTH modes: check vets the in-git files;
    # write is fail-closed on the same problems before emitting. It derives + validates
    # the plugin name itself, so a bad name is a structured gate problem (exit 1), not
    # an unhandled exception.
    config_problems = validate_codex_configs(_HARNESS_CODEX)

    if args.mode == "write":
        out = (args.out or _DIST_CODEX).resolve()
        blocked = list(config_problems)
        for path, text in rendered.items():
            is_skill = _kind_for(path) is ArtifactKind.COMMAND
            blocked += [f"{path.name}: {v}"
                        for v in check_codex_output(text, is_skill=is_skill)]
        if blocked or plugin_name is None:
            for v in blocked:
                print(f"GATE: {v}", file=sys.stderr)
            return 1
        _write_codex_bundle(out, rendered, plugin_root=args.plugin_root,
                            plugin_name=plugin_name)
        print(f"wrote: {out}")
        return 0

    # check: structural gates + configs + determinism (render again, compare).
    violations: list[str] = list(config_problems)
    for path, text in rendered.items():
        is_skill = _kind_for(path) is ArtifactKind.COMMAND
        violations += [f"{path.name}: {v}"
                       for v in check_codex_output(text, is_skill=is_skill)]
    for path in artifacts:
        if render_codex_artifact(path, adapter, pins) != rendered[path]:
            violations.append(f"{path.name}: non-deterministic render")
    if violations:
        for v in violations:
            print(f"GATE: {v}", file=sys.stderr)
        return 1
    print(f"codex: {len(artifacts)} artifacts pass structural gates")
    return 0


def _codex_readfollow_refs(rendered: dict[Path, str]) -> set[str]:
    """The set of ``agents/<file>.md`` filenames the dispatch templates read.

    Role-agnostic (any ``agents/<name>.md``, not a hardcoded role list) so a typo'd
    or renamed ref to an agent file the bundle does NOT produce is caught by the
    write-path correspondence assertion — a narrow allowlist would fail *open* for a
    new/misspelled name (3B code review)."""
    import re
    refs: set[str] = set()
    for text in rendered.values():
        for m in re.finditer(r"agents/([\w.-]+\.md)", text):
            refs.add(m.group(1))
    return refs


def _write_codex_bundle(out: Path, rendered: dict[Path, str], *, plugin_root: Path,
                        plugin_name: str) -> None:
    """Materialize the full self-hosted marketplace bundle: build into a fresh
    staging dir beside the target, then rename-aside swap it into ``out`` (same
    crash-safety as the OpenCode path — a crash leaves *either* the old or the new
    tree at ``out``, never partial). The bundle has two roots in one tree: the
    marketplace (``.agents/plugins/marketplace.json``) and the plugin
    (``plugins/<name>/``)."""
    _guard_out(out, marker=CODEX_BUNDLE_MARKER)
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=str(out.parent), prefix=f".{out.name}.staging."))
    (staging / CODEX_BUNDLE_MARKER).write_text(
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


def _write_bundle(out: Path, rendered: dict[Path, str], *, plugin_root: Path) -> None:
    """Materialize the full bundle: build into a fresh staging dir beside the
    target, then swap it in by moving any existing bundle aside first
    (rename-aside), so a crash always leaves *either* the old or the new tree at
    ``out`` — never a partial one. Staging and backup share ``out``'s parent, so
    every ``os.replace`` is a same-filesystem rename (no EXDEV)."""
    _guard_out(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=str(out.parent), prefix=f".{out.name}.staging."))
    (staging / BUNDLE_MARKER).write_text(
        "fr-security-review OpenCode bundle (generated; do not edit)\n", encoding="utf-8")
    backup: Path | None = None
    try:
        bundle_core(staging, plugin_root=plugin_root)
        copy_static_configs(staging, harness_root=_HARNESS_OPENCODE)
        for path, text in rendered.items():
            dest = opencode_out_path(path, staging)
            dest.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(dest, text.encode("utf-8"))
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
    parser = argparse.ArgumentParser(description="Rebuild harness artifacts from Claude prose.")
    parser.add_argument("--harness", choices=["claude", "codex", "opencode"], default="claude")
    parser.add_argument("--mode", choices=["check", "write"], default="check")
    parser.add_argument("--plugin-root", type=Path, default=_DEFAULT_PLUGIN_ROOT)
    parser.add_argument("--artifact", type=Path, action="append", default=None,
                        help="Specific artifact(s); default = discovered set.")
    parser.add_argument("--out", type=Path, default=None,
                        help="Bundle output root (codex/opencode --mode=write only; "
                             "defaults per harness under dist/; no-op for claude, "
                             "which writes back to source).")
    args = parser.parse_args(argv)

    if args.harness == "claude" and args.out is not None:
        print("note: --out is ignored for --harness=claude (writes in place).",
              file=sys.stderr)

    try:
        if args.harness == "opencode":
            return _run_opencode(args)
        if args.harness == "codex":
            return _run_codex(args)
        adapter = get_adapter(args.harness)
        artifacts = args.artifact or discover_artifacts(args.plugin_root)
        # Two-phase: rebuild everything (each with assert_partition) before
        # touching disk, so a mid-run failure never leaves a partial rewrite.
        rebuilt = {path: _rebuild_bytes(path, adapter) for path in artifacts}
        drift = False
        for path, data in rebuilt.items():
            if data == path.read_bytes():
                continue
            if args.mode == "check":
                drift = True
                print(f"DRIFT: {path}", file=sys.stderr)
            else:
                _atomic_write(path, data)
                print(f"wrote: {path}")
    except NotImplementedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary: any failure is exit 2
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.mode == "check" and drift:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
