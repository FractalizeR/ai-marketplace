"""Shared test fixtures: put build/ on sys.path and resolve the 5 artifacts.

Importing this module is the (intentional) side effect that makes the flat
engine modules (``extract``, ``segments``, ``build`` …) importable from the
``build/tests`` discovery root — mirroring the ``sys.path.insert`` convention
used by ``security-review/bin/tests``.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build"
PLUGIN_ROOT = REPO_ROOT / "security-review"

sys.path.insert(0, str(BUILD_DIR))

from extract import ArtifactKind  # noqa: E402  (after sys.path mutation)

ARTIFACTS = {
    PLUGIN_ROOT / "commands" / "security-project.md": ArtifactKind.COMMAND,
    PLUGIN_ROOT / "commands" / "security-changes.md": ArtifactKind.COMMAND,
    PLUGIN_ROOT / "agents" / "security.md": ArtifactKind.AGENT,
    PLUGIN_ROOT / "agents" / "security-recon.md": ArtifactKind.AGENT,
    PLUGIN_ROOT / "agents" / "security-refute.md": ArtifactKind.AGENT,
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")
