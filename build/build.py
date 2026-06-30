"""Build CLI: rebuild harness artifacts from the authoritative Claude prose.

``build(segments, adapter)`` is a pure fold. The CLI reads each artifact's
bytes, decodes utf-8 strictly, partitions via ``extract``, renders via the
chosen adapter, re-encodes, and compares **bytes-out == bytes-in**.

  --mode=check  (default)  compute output, diff vs on-disk, never write.
                           exit 0 identical / 1 drift / 2 parse-or-error.
  --mode=write             rewrite in place, only when bytes differ.

For ``--harness=claude`` the round-trip is byte-identical by construction; the
default ``--mode=check`` therefore doubles as a self-consistency gate that
protects the authoritative files. ``codex`` / ``opencode`` adapters are stubs
(Phase 2/3) and raise on any tagged segment → exit 2.
"""

from __future__ import annotations

import argparse
import os
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
from gates import check_opencode_output, check_dispatch_template, DISPATCH_ANCHORS

_PLUGIN_DIRNAME = "security-review"
_DEFAULT_PLUGIN_ROOT = Path(__file__).resolve().parent.parent / _PLUGIN_DIRNAME
_BUILD_DIR = Path(__file__).resolve().parent
_REGISTER = _BUILD_DIR / "PROSE_COUPLING.md"
_DIST_OPENCODE = _BUILD_DIR.parent / "dist" / "opencode"


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


def opencode_out_path(path: Path) -> Path:
    """Provisional 2B-core output topology (finalized in 2B-pkg)."""
    if path.parent.name == "commands":
        return _DIST_OPENCODE / "skills" / path.stem / "SKILL.md"
    return _DIST_OPENCODE / "agents" / f"{path.stem}.md"


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
    adapter = get_adapter("opencode")
    pins = load_pins(_REGISTER)
    artifacts = args.artifact or discover_artifacts(args.plugin_root)
    rendered = {p: render_opencode_artifact(p, adapter, pins) for p in artifacts}

    if args.mode == "write":
        # Never materialize a leaky artifact: gate before writing.
        blocked = []
        for path, text in rendered.items():
            blocked += [f"{path.name}: {v}" for v in check_opencode_output(text)]
        if blocked:
            for v in blocked:
                print(f"GATE: {v}", file=sys.stderr)
            return 1
        for path, text in rendered.items():
            out = opencode_out_path(path)
            out.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(out, text.encode("utf-8"))
            print(f"wrote: {out}")
        return 0

    # check: structural gates + determinism (render again, compare).
    violations: list[str] = []
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rebuild harness artifacts from Claude prose.")
    parser.add_argument("--harness", choices=["claude", "codex", "opencode"], default="claude")
    parser.add_argument("--mode", choices=["check", "write"], default="check")
    parser.add_argument("--plugin-root", type=Path, default=_DEFAULT_PLUGIN_ROOT)
    parser.add_argument("--artifact", type=Path, action="append", default=None,
                        help="Specific artifact(s); default = discovered set.")
    args = parser.parse_args(argv)

    try:
        if args.harness == "opencode":
            return _run_opencode(args)
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
