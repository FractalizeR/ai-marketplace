"""Tests for the dedupe `--dispatch-gaps` delta (Phase 2A S5)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedupe_findings as dff  # noqa: E402


def _mk_finding_md() -> str:
    return (
        "# Vulnerability 1: [sql_injection]: `src/Repo.php:42`\n\n"
        "* **Severity**: High\n"
        "* **Confidence**: 9/10\n"
        "* **Category**: sql_injection\n"
        "* **sink_kind**: dql_concat\n"
        "* **root_cause_family**: injection\n"
        "* **enclosing_symbol**: Repo::find\n"
        "* **sink_snippet**: |\n"
        "    $dql = 'SELECT u ' . $sort;\n"
        "* **Description**: test\n"
        "* **Data path**: X -> Y -> src/Repo.php:42\n"
        "* **Exploitation scenario**: p\n"
        "* **Impact**: i\n"
        "* **Recommendation**: r\n"
        "* **Discovered via**: checklist:auth.md\n\n"
    )


def _write_gaps(path: Path, entries: list) -> None:
    path.write_text(json.dumps(entries), encoding="utf-8")


class ReadDispatchGapsUnitTests(unittest.TestCase):
    def test_none_returns_empty(self):
        self.assertEqual(dff.read_dispatch_gaps(None), [])

    def test_missing_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(dff.read_dispatch_gaps(Path(d) / "nope.json"), [])

    def test_corrupt_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "g.json"
            p.write_text("{not json", encoding="utf-8")
            self.assertEqual(dff.read_dispatch_gaps(p), [])

    def test_non_list_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "g.json"
            p.write_text('{"slice_id": "X"}', encoding="utf-8")
            self.assertEqual(dff.read_dispatch_gaps(p), [])

    def test_valid_list_renders_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "g.json"
            _write_gaps(p, [
                {"slice_id": "W1_PART1", "reason": "timeout", "returncode": None},
                {"slice_id": "W2_PART1", "reason": "crash", "returncode": 1},
            ])
            lines = dff.read_dispatch_gaps(p)
            self.assertEqual(len(lines), 2)
            self.assertIn("W1_PART1", lines[0])
            self.assertIn("timeout", lines[0])
            self.assertIn("INCOMPLETE", lines[0])


class MainIntegrationTests(unittest.TestCase):
    def _run(self, args):
        return dff.main(args)

    def test_dispatch_gap_renders_and_marks_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            waves = review / "waves"
            waves.mkdir()
            (waves / "W1_PART1.md").write_text(_mk_finding_md(), encoding="utf-8")
            _write_gaps(review / "dispatch_gaps.json", [
                {"slice_id": "W2_PART1", "reason": "crash", "returncode": 1},
            ])
            out = review / "REPORT.md"
            rc = self._run([
                "--input-glob", str(waves / "*.md"),
                "--output", str(out),
                "--no-state",
            ])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertIn("INCOMPLETE AUDIT", text)
            self.assertIn("## Coverage Gaps", text)
            self.assertIn("W2_PART1", text)
            # marker is prominent — appears before the Coverage Gaps section.
            self.assertLess(text.index("INCOMPLETE AUDIT"), text.index("## Coverage Gaps"))

    def test_no_dispatch_gaps_no_marker(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            waves = review / "waves"
            waves.mkdir()
            (waves / "W1_PART1.md").write_text(_mk_finding_md(), encoding="utf-8")
            out = review / "REPORT.md"
            rc = self._run([
                "--input-glob", str(waves / "*.md"),
                "--output", str(out),
                "--no-state",
            ])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertNotIn("INCOMPLETE AUDIT", text)

    def test_all_waves_failed_renders_incomplete_not_exit2(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            (review / "waves").mkdir()
            _write_gaps(review / "dispatch_gaps.json", [
                {"slice_id": "W1_PART1", "reason": "crash", "returncode": 1},
                {"slice_id": "W2_PART1", "reason": "timeout", "returncode": None},
            ])
            out = review / "REPORT.md"
            rc = self._run([
                "--input-glob", str(review / "waves" / "*.md"),
                "--output", str(out),
                "--no-state",
            ])
            self.assertEqual(rc, 0)  # NOT exit 2
            text = out.read_text()
            self.assertIn("INCOMPLETE AUDIT", text)
            self.assertIn("W1_PART1", text)
            self.assertIn("W2_PART1", text)

    def test_zero_input_no_gaps_still_exit2(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            (review / "waves").mkdir()
            out = review / "REPORT.md"
            rc = self._run([
                "--input-glob", str(review / "waves" / "*.md"),
                "--output", str(out),
                "--no-state",
            ])
            self.assertEqual(rc, 2)

    def test_explicit_dispatch_gaps_path(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            waves = review / "waves"
            waves.mkdir()
            (waves / "W1_PART1.md").write_text(_mk_finding_md(), encoding="utf-8")
            gaps_p = review / "custom_gaps.json"
            _write_gaps(gaps_p, [{"slice_id": "WX", "reason": "missing_write", "returncode": 0}])
            out = review / "REPORT.md"
            rc = self._run([
                "--input-glob", str(waves / "*.md"),
                "--output", str(out),
                "--dispatch-gaps", str(gaps_p),
                "--no-state",
            ])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertIn("WX", text)
            self.assertIn("INCOMPLETE AUDIT", text)

    def test_missing_dispatch_gaps_no_crash(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            waves = review / "waves"
            waves.mkdir()
            (waves / "W1_PART1.md").write_text(_mk_finding_md(), encoding="utf-8")
            out = review / "REPORT.md"
            # default dispatch_gaps path does not exist → no-op.
            rc = self._run([
                "--input-glob", str(waves / "*.md"),
                "--output", str(out),
                "--no-state",
            ])
            self.assertEqual(rc, 0)
            self.assertNotIn("INCOMPLETE AUDIT", out.read_text())

    def test_idempotent_rewrite(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            waves = review / "waves"
            waves.mkdir()
            (waves / "W1_PART1.md").write_text(_mk_finding_md(), encoding="utf-8")
            _write_gaps(review / "dispatch_gaps.json", [
                {"slice_id": "W2_PART1", "reason": "crash", "returncode": 1},
            ])
            out = review / "REPORT.md"
            args = [
                "--input-glob", str(waves / "*.md"),
                "--output", str(out),
                "--no-state",
            ]
            self._run(args)
            first = out.read_text()
            self._run(args)
            second = out.read_text()
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
