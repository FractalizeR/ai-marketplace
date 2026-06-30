"""Tripwire: every pinned literal in PROSE_COUPLING.md still exists in its file."""

import re
import unittest

import _common
from _common import BUILD_DIR, PLUGIN_ROOT, read

_YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.DOTALL)


def _entries():
    text = read(BUILD_DIR / "PROSE_COUPLING.md")
    block = _YAML_BLOCK.search(text)
    assert block, "PROSE_COUPLING.md has no ```yaml register block"
    entries, cur = [], None
    for line in block.group(1).splitlines():
        m_id = re.match(r"\s*- id:\s*(\S+)", line)
        m_file = re.match(r'\s*file:\s*(\S+)', line)
        m_pin = re.match(r'\s*pinned:\s*"(.*)"\s*$', line)
        if m_id:
            cur = {"id": m_id.group(1)}
            entries.append(cur)
        elif m_file and cur is not None:
            cur["file"] = m_file.group(1)
        elif m_pin and cur is not None:
            cur["pinned"] = m_pin.group(1)
    return entries


class ProseCouplingAnchorTests(unittest.TestCase):
    def test_register_has_entries(self):
        entries = _entries()
        self.assertGreaterEqual(len(entries), 7)
        # Guard against the hand-rolled parser silently dropping entries on a
        # format drift: parsed count must equal the number of `- id:` lines.
        block = _YAML_BLOCK.search(read(BUILD_DIR / "PROSE_COUPLING.md")).group(1)
        self.assertEqual(len(entries), len(re.findall(r"(?m)^\s*- id:", block)))
        for e in entries:
            self.assertIn("file", e, f"entry {e['id']} missing file")
            self.assertIn("pinned", e, f"entry {e['id']} missing pinned")

    def test_pinned_literals_present_in_artifacts(self):
        for e in _entries():
            with self.subTest(id=e["id"]):
                artifact = read(PLUGIN_ROOT / e["file"])
                self.assertIn(
                    e["pinned"], artifact,
                    f"prose drift: {e['id']!r} pinned literal not found in {e['file']}",
                )


if __name__ == "__main__":
    unittest.main()
