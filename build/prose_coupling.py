"""Loader for the prose-coupling register (`PROSE_COUPLING.md`).

Parsed by the same naive regex the tripwire test (`tests/test_prose_coupling.py`)
uses — stdlib-only, no YAML dependency. The register lives in a ```yaml fenced
block; each entry is a sequence of ``- id:`` / ``file:`` / ``pinned:`` lines (plus
informational fields the loader ignores). A ``pinned`` value is a *verbatim*
substring that locates the coupled section inside its ``file``.

Because the value is extracted by a greedy ``"(.*)"`` capture (not a YAML parser),
inner double quotes in a pin are written raw (e.g. ``"subagent_type="security""``)
and captured up to the last quote on the line — matching the tripwire exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.DOTALL)
_RE_ID = re.compile(r"\s*- id:\s*(\S+)")
_RE_FILE = re.compile(r"\s*file:\s*(\S+)")
_RE_PIN = re.compile(r'\s*pinned:\s*"(.*)"\s*$')


@dataclass(frozen=True)
class Pin:
    """One coupling anchor: ``pinned`` must appear verbatim inside ``file``."""

    id: str
    file: str          # plugin-root-relative, e.g. "commands/security-project.md"
    pinned: str

    @property
    def artifact_basename(self) -> str:
        """File stem used as the template namespace, e.g. ``security-project``."""
        return Path(self.file).stem


def load_pins(register_path: Path) -> list[Pin]:
    text = register_path.read_text(encoding="utf-8")
    block = _YAML_BLOCK.search(text)
    if not block:
        raise ValueError(f"{register_path} has no ```yaml register block")
    pins: list[Pin] = []
    cur: dict[str, str] = {}
    for line in block.group(1).splitlines():
        m_id = _RE_ID.match(line)
        m_file = _RE_FILE.match(line)
        m_pin = _RE_PIN.match(line)
        if m_id:
            cur = {"id": m_id.group(1)}
        elif m_file and cur:
            cur["file"] = m_file.group(1)
        elif m_pin and cur.get("id") and cur.get("file"):
            pins.append(Pin(cur["id"], cur["file"], m_pin.group(1)))
            cur = {}
    return pins


def pins_for(pins: list[Pin], file_rel: str) -> list[Pin]:
    """Pins whose ``file`` matches the plugin-root-relative artifact path."""
    return [p for p in pins if p.file == file_rel]
