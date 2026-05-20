"""Contract: prompt-side enum lists in markdown stay byte-aligned with the
Python single source of truth `models.SINK_KIND_TO_FAMILY`.

Files involved:
  - vr/code-review/bin/dedupe/models.py (authoritative)
  - vr/code-review/agents/security.md (operator-visible enum line)
  - vr/code-review/checklists/_meta.md (enum line + mapping table)

If a future PR adds a sink_kind to one place but forgets the others, these
tests fail with a diff that points at the divergent file.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dedupe.models import SINK_KIND_TO_FAMILY  # noqa: E402

# Plugin root: tests/ → bin/ → code-review/.
_PLUGIN_ROOT = Path(__file__).resolve().parents[2]
_SECURITY_MD = _PLUGIN_ROOT / "agents" / "security.md"
_META_MD = _PLUGIN_ROOT / "checklists" / "_meta.md"

# Identifiers in lowercase_underscore form. Used to extract every backticked
# token from a single markdown line.
_IDENT_RE = re.compile(r"`([a-z][a-z0-9_]*)`")

# Mapping table row: `<a>`, `<b>` | `family` (we accept comma-separated kinds
# in the left column to allow future grouping).
_MAPPING_ROW_RE = re.compile(
    r"^\|\s*((?:`[a-z][a-z0-9_]*`(?:\s*,\s*)?)+)\s*\|\s*`([a-z_]+)`\s*\|\s*$",
    re.MULTILINE,
)


def _kinds_from_enum_line(text: str, header: str) -> set[str]:
    """Extract sink_kind identifiers from the line after a header.

    Header lookup is fuzzy: we find a heading that mentions `sink_kind` and
    grab the next paragraph (single physical line). We then collect every
    backticked identifier from that paragraph.
    """
    # Find the closest heading containing `sink_kind` and `enum`.
    heading_re = re.compile(rf"^#{{2,4}}\s+{re.escape(header)}.*$", re.MULTILINE)
    m = heading_re.search(text)
    if not m:
        raise AssertionError(
            f"Heading {header!r} not found in markdown. Sections may have been renamed."
        )
    # Take the body until the next blank-line+heading pair.
    rest = text[m.end():]
    # Strip leading blank lines.
    rest = rest.lstrip("\n")
    # First non-blank "paragraph" — until the next blank line.
    paragraph = rest.split("\n\n", 1)[0]
    return set(_IDENT_RE.findall(paragraph))


class EnumConsistencyContract(unittest.TestCase):
    """Markdown lists of sink_kind must equal the Python enum exactly."""

    def test_security_md_lists_all_kinds_from_python(self):
        text = _SECURITY_MD.read_text(encoding="utf-8")
        kinds = _kinds_from_enum_line(text, "Закрытый enum `sink_kind`")
        py_kinds = set(SINK_KIND_TO_FAMILY.keys())
        missing = py_kinds - kinds
        extra = kinds - py_kinds
        self.assertFalse(
            missing or extra,
            f"agents/security.md sink_kind enum out of sync.\n"
            f"  In Python but missing in security.md: {sorted(missing)}\n"
            f"  In security.md but missing in Python: {sorted(extra)}",
        )

    def test_meta_md_lists_all_kinds_from_python(self):
        text = _META_MD.read_text(encoding="utf-8")
        # The meta file has an enum block introduced by "Значения enum `sink_kind`:"
        # — capture the next paragraph after that line.
        marker_re = re.compile(r"Значения enum `sink_kind`:\s*\n", re.MULTILINE)
        m = marker_re.search(text)
        self.assertIsNotNone(
            m, "checklists/_meta.md does not contain the enum marker line"
        )
        rest = text[m.end():]
        paragraph = rest.split("\n\n", 1)[0]
        kinds = set(_IDENT_RE.findall(paragraph))
        py_kinds = set(SINK_KIND_TO_FAMILY.keys())
        missing = py_kinds - kinds
        extra = kinds - py_kinds
        self.assertFalse(
            missing or extra,
            f"checklists/_meta.md sink_kind enum out of sync.\n"
            f"  In Python but missing in _meta.md: {sorted(missing)}\n"
            f"  In _meta.md but missing in Python: {sorted(extra)}",
        )

    def test_meta_md_mapping_matches_python(self):
        """The `sink_kind | root_cause_family` table in _meta.md must reproduce
        every (kind, family) pair from `SINK_KIND_TO_FAMILY`."""
        text = _META_MD.read_text(encoding="utf-8")
        markdown_pairs: dict[str, str] = {}
        for row in _MAPPING_ROW_RE.finditer(text):
            kinds_chunk, family = row.group(1), row.group(2)
            for k in _IDENT_RE.findall(kinds_chunk):
                markdown_pairs[k] = family
        # Compare the dicts directly.
        self.assertEqual(
            markdown_pairs,
            SINK_KIND_TO_FAMILY,
            "Mapping table in checklists/_meta.md does not match SINK_KIND_TO_FAMILY.\n"
            f"  Markdown: {sorted(markdown_pairs.items())}\n"
            f"  Python:   {sorted(SINK_KIND_TO_FAMILY.items())}",
        )


if __name__ == "__main__":
    unittest.main()
