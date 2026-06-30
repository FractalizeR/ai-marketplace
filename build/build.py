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
from extract import ArtifactKind, extract
from adapters import get_adapter

_PLUGIN_DIRNAME = "security-review"
_DEFAULT_PLUGIN_ROOT = Path(__file__).resolve().parent.parent / _PLUGIN_DIRNAME


def build(segments: list[Segment], adapter) -> str:
    """Pure fold: render each segment and concatenate, no injected separators."""
    return "".join(adapter.render_segment(s) for s in segments)


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rebuild harness artifacts from Claude prose.")
    parser.add_argument("--harness", choices=["claude", "codex", "opencode"], default="claude")
    parser.add_argument("--mode", choices=["check", "write"], default="check")
    parser.add_argument("--plugin-root", type=Path, default=_DEFAULT_PLUGIN_ROOT)
    parser.add_argument("--artifact", type=Path, action="append", default=None,
                        help="Specific artifact(s); default = discovered set.")
    args = parser.parse_args(argv)

    try:
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
