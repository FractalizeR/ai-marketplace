"""Round-trip identity, divergence (de-tautology), encoding, count-from-grep."""

import unittest

import _common
from _common import ARTIFACTS, read

from extract import extract
from segments import assert_partition
from build import build
from adapters import ClaudeAdapter, FakeAdapter


class RoundTripTests(unittest.TestCase):
    def test_byte_identical_rebuild_all_artifacts(self):
        adapter = ClaudeAdapter()
        for path, kind in ARTIFACTS.items():
            with self.subTest(path=path.name):
                source = path.read_bytes()
                segments = extract(source.decode("utf-8"), kind)
                assert_partition(segments, source.decode("utf-8"))
                rebuilt = build(segments, adapter).encode("utf-8")
                self.assertEqual(rebuilt, source)

    def test_fake_adapter_diverges_only_at_core_root(self):
        # The real proof the IR has a seam: FakeAdapter differs from Claude
        # exactly at CORE_ROOT spans and nowhere else.
        for path, kind in ARTIFACTS.items():
            with self.subTest(path=path.name):
                segments = extract(read(path), kind)
                changed = [
                    s for s in segments
                    if ClaudeAdapter().render_segment(s) != FakeAdapter().render_segment(s)
                ]
                self.assertTrue(
                    all(s.category == "CORE_ROOT" for s in changed),
                    "FakeAdapter changed a non-CORE_ROOT segment",
                )
                # And it does change every CORE_ROOT (marker != original).
                core = [s for s in segments if s.category == "CORE_ROOT"]
                self.assertEqual(len(changed), len(core))

    def test_trailing_newline_and_emoji_survive(self):
        adapter = ClaudeAdapter()
        for path, kind in ARTIFACTS.items():
            source = read(path)
            rebuilt = build(extract(source, kind), adapter)
            with self.subTest(path=path.name):
                self.assertTrue(source.endswith("\n"))
                self.assertEqual(rebuilt.endswith("\n"), source.endswith("\n"))
                if "⚠️" in source:  # ⚠️ multi-codepoint grapheme
                    self.assertEqual(
                        rebuilt.count("⚠️"), source.count("⚠️")
                    )

    def test_core_root_count_from_grep(self):
        # Derive expectations from a raw scan, never a hardcoded literal; assert
        # the 21 body / 4 frontmatter / 25 total split + no false positives.
        total = body = fm = 0
        for path, kind in ARTIFACTS.items():
            source = read(path)
            total += source.count("${CLAUDE_PLUGIN_ROOT}")
            segments = extract(source, kind)
            core = [s for s in segments if s.category == "CORE_ROOT"]
            body += len(core)
            for s in core:
                self.assertEqual(s.original_text, "${CLAUDE_PLUGIN_ROOT}")  # no false positive
            for s in segments:
                if s.category == "cmd_frontmatter":
                    fm += s.attrs["core_root_globs"]
        self.assertEqual(total, 25)
        self.assertEqual(body, 21)
        self.assertEqual(fm, 4)
        self.assertEqual(body + fm, total)


if __name__ == "__main__":
    unittest.main()
