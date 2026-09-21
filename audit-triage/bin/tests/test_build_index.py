"""Tests for build_index.py -- emit_index / emit_verdicts, and the CLI that
wires them to a triage run's .work/ artifacts.

Sidecar fixtures follow agents/triage-verify.md's OUTPUT CONTRACT exactly
(the `.work/verify/<unit_id>.json` shape a Phase 4 worker writes):

    {
      "unit_id": "...",
      "severity_before": "...", "severity_after": "...",
      "severity_change_rationale": "...",
      "locations": [
        {"sink_hash": "...", "sink_file": "...", "sink_line": 0,
         "status": "confirmed|changed|false_positive|manual_review",
         "note": "...", "condition_keys": [...],
         "verdict_candidate": "rejected|reaffirmed|null"}
      ],
      "fix_pattern_note": "..."
    }
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_index as bi  # noqa: E402
import parse_findings as pf  # noqa: E402
import fixtures_lib  # noqa: E402


def _sidecar(unit_id, *, severity_before="High", severity_after="High", rationale="", locations=(), fix_pattern_note=""):
    return {
        "unit_id": unit_id,
        "severity_before": severity_before,
        "severity_after": severity_after,
        "severity_change_rationale": rationale,
        "locations": list(locations),
        "fix_pattern_note": fix_pattern_note,
    }


def _location(sink_hash, *, status="confirmed", note="", condition_keys=(), verdict_candidate=None, **extra):
    loc = {
        "sink_hash": sink_hash,
        "sink_file": "src/X.php",
        "sink_line": 1,
        "status": status,
        "note": note,
        "condition_keys": list(condition_keys),
        "verdict_candidate": verdict_candidate,
    }
    loc.update(extra)
    return loc


class EmitVerdictsTests(unittest.TestCase):
    def test_reaffirmed_and_rejected_basic(self):
        sidecars = {
            "u1": _sidecar(
                "u1",
                locations=[
                    _location("aaaaaaaa", status="confirmed", verdict_candidate="reaffirmed"),
                    _location("bbbbbbbb", status="false_positive", verdict_candidate="rejected"),
                ],
            )
        }
        result = bi.emit_verdicts(sidecars)
        by_hash = {e["sink_hash"]: e for e in result["verdicts"]}
        self.assertEqual(by_hash["aaaaaaaa"]["verdict"], "reaffirmed")
        self.assertEqual(by_hash["aaaaaaaa"]["source"], "audit-triage")
        self.assertEqual(by_hash["bbbbbbbb"]["verdict"], "rejected")
        self.assertEqual(result["conflicts"], [])

    def test_changed_and_manual_review_emit_nothing(self):
        sidecars = {
            "u1": _sidecar(
                "u1",
                locations=[
                    _location("aaaaaaaa", status="changed", verdict_candidate=None),
                    _location("bbbbbbbb", status="manual_review", verdict_candidate=None),
                ],
            )
        }
        result = bi.emit_verdicts(sidecars)
        self.assertEqual(result["verdicts"], [])

    def test_nohash00_never_emitted(self):
        sidecars = {"u1": _sidecar("u1", locations=[_location("nohash00", verdict_candidate="reaffirmed")])}
        result = bi.emit_verdicts(sidecars)
        self.assertEqual(result["verdicts"], [])

    def test_unknown_condition_key_dropped_known_kept(self):
        sidecars = {
            "u1": _sidecar(
                "u1",
                locations=[
                    _location(
                        "aaaaaaaa",
                        verdict_candidate="rejected",
                        condition_keys=["admin_only", "not_a_real_key"],
                    )
                ],
            )
        }
        result = bi.emit_verdicts(sidecars)
        entry = result["verdicts"][0]
        self.assertEqual(entry["condition_keys"], ["admin_only"])

    def test_refute_file_and_line_only_together_and_only_for_rejected(self):
        # refute_line without refute_file -> dropped (not a pair)
        sidecars = {
            "u1": _sidecar(
                "u1",
                locations=[
                    _location("aaaaaaaa", verdict_candidate="rejected", refute_line=42),
                    _location("bbbbbbbb", verdict_candidate="rejected", refute_file="src/Y.php", refute_line=42),
                    _location("cccccccc", verdict_candidate="reaffirmed", refute_file="src/Z.php", refute_line=1),
                ],
            )
        }
        result = bi.emit_verdicts(sidecars)
        by_hash = {e["sink_hash"]: e for e in result["verdicts"]}
        self.assertNotIn("refute_file", by_hash["aaaaaaaa"])
        self.assertEqual(by_hash["bbbbbbbb"]["refute_file"], "src/Y.php")
        self.assertEqual(by_hash["bbbbbbbb"]["refute_line"], 42)
        # reaffirmed never carries refute_file/refute_line even if present in the sidecar
        self.assertNotIn("refute_file", by_hash["cccccccc"])

    def test_conflicting_candidates_across_units_are_dropped_and_reported(self):
        sidecars = {
            "u1": _sidecar("u1", locations=[_location("aaaaaaaa", verdict_candidate="rejected")]),
            "u2": _sidecar("u2", locations=[_location("aaaaaaaa", verdict_candidate="reaffirmed")]),
        }
        result = bi.emit_verdicts(sidecars)
        self.assertEqual(result["verdicts"], [])
        self.assertEqual(result["conflicts"], ["aaaaaaaa"])

    def test_identical_candidate_across_two_units_collapses_silently(self):
        sidecars = {
            "u1": _sidecar("u1", locations=[_location("aaaaaaaa", verdict_candidate="reaffirmed")]),
            "u2": _sidecar("u2", locations=[_location("aaaaaaaa", verdict_candidate="reaffirmed")]),
        }
        result = bi.emit_verdicts(sidecars)
        self.assertEqual(len(result["verdicts"]), 1)
        self.assertEqual(result["conflicts"], [])

    def test_output_is_sorted_by_sink_hash(self):
        sidecars = {
            "u1": _sidecar(
                "u1",
                locations=[
                    _location("zzzzzzzz", verdict_candidate="reaffirmed"),
                    _location("aaaaaaaa", verdict_candidate="reaffirmed"),
                ],
            )
        }
        result = bi.emit_verdicts(sidecars)
        self.assertEqual([e["sink_hash"] for e in result["verdicts"]], ["aaaaaaaa", "zzzzzzzz"])


class EmitIndexTests(unittest.TestCase):
    """DoD: every sink_hash from findings.json's confirmed list must appear
    literally in INDEX.md -- verified here against the REAL fixture."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = fixtures_lib.build_review_root(Path(cls.tmp.name) / "review")
        cls.records = pf.load(cls.review_root)
        cls.grouping = fixtures_lib.FULL_GROUPING
        cls.sidecars = {
            "u1-injection": _sidecar(
                "u1-injection",
                severity_before="Critical",
                severity_after="Medium",
                rationale="internal-network-only per trust model",
                locations=[
                    _location("b55e8630", status="confirmed", verdict_candidate="reaffirmed", condition_keys=["internal_network_only"]),
                    _location("809bd41e", status="confirmed", verdict_candidate="reaffirmed"),
                ],
            ),
            "u2-crypto": _sidecar(
                "u2-crypto",
                severity_before="High",
                severity_after="High",
                locations=[
                    _location("116a9474", status="false_positive", verdict_candidate="rejected", refute_file="src/Token.php", refute_line=50),
                    _location("33c924c1", status="changed"),
                ],
            ),
            # triage-manual and triage-leads deliberately left without a sidecar.
        }

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_sink_hash_appears_in_index(self):
        text = bi.emit_index(self.records, self.grouping, self.sidecars)
        for r in self.records:
            self.assertIn(r.sink_hash, text, msg=f"{r.sink_hash} ({r.record_id}) missing from INDEX.md")

    def test_units_table_lists_every_unit(self):
        text = bi.emit_index(self.records, self.grouping, self.sidecars)
        for unit_id in self.grouping:
            self.assertIn(f"`{unit_id}`", text)

    def test_verified_unit_shows_downgraded_severity(self):
        text = bi.emit_index(self.records, self.grouping, self.sidecars)
        lines = [l for l in text.splitlines() if l.startswith("| `u1-injection`")]
        self.assertEqual(len(lines), 1)
        self.assertIn("Medium", lines[0])

    def test_unit_without_sidecar_is_pending(self):
        text = bi.emit_index(self.records, self.grouping, self.sidecars)
        lines = [l for l in text.splitlines() if l.startswith("| `triage-leads`")]
        self.assertEqual(len(lines), 1)
        self.assertIn("pending verification", lines[0])

    def test_false_positive_rejected_location_surfaces_status(self):
        text = bi.emit_index(self.records, self.grouping, self.sidecars)
        lines = [l for l in text.splitlines() if l.startswith("| `116a9474`")]
        self.assertEqual(len(lines), 1)
        self.assertIn("false_positive", lines[0])

    def test_prior_resolution_section_present_when_marked(self):
        # No prior resolutions in this fixture run (fresh .findings_state.json) --
        # section must simply be absent, not error.
        text = bi.emit_index(self.records, self.grouping, self.sidecars)
        if not any(r.prior_resolution for r in self.records):
            self.assertNotIn("## Prior-run resolutions", text)


class BuildIndexCliTests(unittest.TestCase):
    def test_full_cli_chain(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            review_root = fixtures_lib.build_review_root(td_path / "review")
            tickets_root = td_path / "tickets"

            with contextlib.redirect_stdout(io.StringIO()):
                rc = pf.main([str(review_root), "--tickets-root", str(tickets_root)])
            self.assertEqual(rc, 0)

            grouping_path = tickets_root / ".work" / "grouping.json"
            grouping_path.write_text(json.dumps(fixtures_lib.FULL_GROUPING), encoding="utf-8")

            verify_dir = tickets_root / ".work" / "verify"
            verify_dir.mkdir(parents=True)
            (verify_dir / "u1-injection.json").write_text(
                json.dumps(
                    _sidecar(
                        "u1-injection",
                        locations=[_location("b55e8630", verdict_candidate="reaffirmed")],
                    )
                ),
                encoding="utf-8",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                rc2 = bi.main([str(tickets_root)])
            self.assertEqual(rc2, 0)

            index_path = tickets_root / "INDEX.md"
            self.assertTrue(index_path.is_file())
            index_text = index_path.read_text(encoding="utf-8")
            self.assertIn("b55e8630", index_text)

            verdicts_path = tickets_root / ".work" / "verdicts.json"
            self.assertTrue(verdicts_path.is_file())
            verdicts_payload = json.loads(verdicts_path.read_text(encoding="utf-8"))
            self.assertEqual(verdicts_payload["schema_version"], 1)
            self.assertEqual(
                verdicts_payload["findings_json_sha256"],
                pf.findings_json_sha256(review_root),
            )
            self.assertEqual(len(verdicts_payload["verdicts"]), 1)
            self.assertEqual(verdicts_payload["verdicts"][0]["sink_hash"], "b55e8630")

    def test_missing_parsed_json_fails_loudly(self):
        with tempfile.TemporaryDirectory() as td:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = bi.main([str(Path(td) / "tickets")])
            self.assertEqual(rc, 2)

    def test_missing_grouping_fails_loudly(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            review_root = fixtures_lib.build_review_root(td_path / "review")
            tickets_root = td_path / "tickets"
            with contextlib.redirect_stdout(io.StringIO()):
                pf.main([str(review_root), "--tickets-root", str(tickets_root)])
            with contextlib.redirect_stdout(io.StringIO()):
                rc = bi.main([str(tickets_root)])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
