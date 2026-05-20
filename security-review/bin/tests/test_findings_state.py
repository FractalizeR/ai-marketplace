"""Cross-run findings-state diff: save/load round-trip + compute_diff."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
sys.path.insert(0, str(BIN_DIR))

from dedupe.models import Finding, MergedFinding  # noqa: E402
from dedupe.state import (  # noqa: E402
    FindingSnapshot,
    STATE_FILENAME,
    STATE_SCHEMA_VERSION,
    compute_diff,
    load_state,
    save_state,
    snapshots_from,
)


def _f(sink_kind: str, file: str, line: int, snippet: str, severity="High",
       title="Finding") -> Finding:
    return Finding(
        title_line=title,
        sink_file=file,
        sink_line=line,
        severity=severity,
        sink_kind=sink_kind,
        sink_snippet=snippet,
    )


def _mf(*findings) -> MergedFinding:
    return MergedFinding(primary=findings[0], merged_from=list(findings[1:]))


class StateRoundtrip(unittest.TestCase):
    def test_save_load_roundtrip(self):
        snapshots = [
            FindingSnapshot("abcd1234", "src/A.php", 10, "idor_lookup", "High", "Test A"),
            FindingSnapshot("efgh5678", "src/B.php", 20, "dql_concat", "Critical", "Test B"),
        ]
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            target = save_state(snapshots, review_root)
            self.assertTrue(target.is_file())
            self.assertEqual(target.name, STATE_FILENAME)
            loaded = load_state(review_root)
            self.assertEqual(loaded, snapshots)

    def test_save_writes_schema_version(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state([], review_root)
            payload = json.loads((review_root / STATE_FILENAME).read_text())
            self.assertEqual(payload["schema_version"], STATE_SCHEMA_VERSION)

    def test_load_returns_none_when_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(load_state(Path(td)))

    def test_load_returns_none_on_corrupt_json(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text("{not json")
            self.assertIsNone(load_state(review_root))

    def test_load_returns_none_on_wrong_schema_version(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text(
                json.dumps({"schema_version": 99, "findings": []})
            )
            self.assertIsNone(load_state(review_root))

    def test_load_skips_malformed_finding_entries(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text(json.dumps({
                "schema_version": STATE_SCHEMA_VERSION,
                "findings": [
                    {"sink_hash": "ok123456", "sink_file": "a.php", "sink_line": 1,
                     "sink_kind": "k", "severity": "High", "title": "ok"},
                    "garbage_string",
                    {"sink_hash": "bad12345", "sink_line": "not-an-int"},
                ],
            }))
            loaded = load_state(review_root)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].sink_hash, "ok123456")


class SnapshotsFromMerged(unittest.TestCase):
    def test_snapshots_pull_primary_fields_and_merged_severity(self):
        a = _f("idor_lookup", "src/A.php", 10, "$repo->find($id)", severity="High",
               title="# A finding")
        b = _f("idor_lookup", "src/A.php", 10, "$repo->find($id)", severity="Critical")
        mf = _mf(a, b)
        snaps = snapshots_from([mf], [])
        self.assertEqual(len(snaps), 1)
        s = snaps[0]
        self.assertEqual(s.sink_hash, a.sink_hash)
        self.assertEqual(s.sink_file, "src/A.php")
        self.assertEqual(s.severity, "Critical")  # max across merged_from
        self.assertEqual(s.title, "# A finding")

    def test_snapshots_include_manual_collection(self):
        a = _f("custom:weird", "src/M.php", 5, "$x")
        snaps = snapshots_from([], [_mf(a)])
        self.assertEqual(len(snaps), 1)


class DiffSemantics(unittest.TestCase):
    def test_no_previous_returns_none(self):
        self.assertIsNone(compute_diff(None, []))

    def test_first_run_with_empty_state_marks_all_as_new(self):
        # Edge case: someone passes `previous=[]` explicitly. That's not the
        # same as None; everything in `current` should be classified as new.
        current = [
            FindingSnapshot("aaaaaaaa", "a.php", 1, "k", "High", "t"),
            FindingSnapshot("bbbbbbbb", "b.php", 2, "k", "High", "t"),
        ]
        diff = compute_diff([], current)
        self.assertEqual([s.sink_hash for s in diff.new], ["aaaaaaaa", "bbbbbbbb"])
        self.assertEqual(diff.recurring, [])
        self.assertEqual(diff.closed, [])

    def test_recurring_classified_when_hash_present_in_both(self):
        prev = [FindingSnapshot("h1", "a.php", 1, "k", "High", "t")]
        curr = [FindingSnapshot("h1", "a.php", 1, "k", "High", "t")]
        diff = compute_diff(prev, curr)
        self.assertEqual(len(diff.recurring), 1)
        self.assertEqual(diff.new, [])
        self.assertEqual(diff.closed, [])

    def test_closed_classified_when_hash_only_in_previous(self):
        prev = [FindingSnapshot("h1", "a.php", 1, "k", "High", "t"),
                FindingSnapshot("h2", "b.php", 2, "k", "High", "t")]
        curr = [FindingSnapshot("h1", "a.php", 1, "k", "High", "t")]
        diff = compute_diff(prev, curr)
        self.assertEqual([s.sink_hash for s in diff.closed], ["h2"])

    def test_nohash00_excluded_from_classification(self):
        # The nohash00 sentinel is what `Finding.sink_hash` returns when there
        # is no usable snippet. Letting those through pollutes diffs (every run
        # produces a "new" nohash00 and a "closed" nohash00).
        prev = [FindingSnapshot("nohash00", "a.php", 1, "k", "High", "t")]
        curr = [FindingSnapshot("nohash00", "b.php", 2, "k", "High", "t")]
        diff = compute_diff(prev, curr)
        self.assertEqual(diff.new, [])
        self.assertEqual(diff.recurring, [])
        self.assertEqual(diff.closed, [])

    def test_has_changes_property(self):
        prev = [FindingSnapshot("h1", "a.php", 1, "k", "High", "t")]
        curr = [FindingSnapshot("h2", "a.php", 1, "k", "High", "t")]
        diff = compute_diff(prev, curr)
        self.assertTrue(diff.has_changes)

        recurring_only = compute_diff(prev, prev)
        self.assertFalse(recurring_only.has_changes)


if __name__ == "__main__":
    unittest.main()
