"""Tests for parse_findings.py -- load / assert_full_coverage / bundle.

Uses a REAL findings.json (built by fixtures_lib.build_review_root, which
shells out to the actual fr-security-review dedupe_findings.py CLI against
the engine's own e2e wave fixtures) for the end-to-end shaped tests, plus
synthetic payloads for the schema-validation edge cases that would be
awkward to provoke through the real pipeline (missing file, bad schema
version, malformed JSON).
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

import parse_findings as pf  # noqa: E402
import fixtures_lib  # noqa: E402


class LoadOnRealFindingsJsonTests(unittest.TestCase):
    """DoD #4: parse_findings.load() against a findings.json built by the
    REAL dedupe_findings.py CLI from the engine's e2e fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = fixtures_lib.build_review_root(Path(cls.tmp.name) / "review")
        cls.records = pf.load(cls.review_root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_counts_match_findings_json(self):
        payload = json.loads((self.review_root / "findings.json").read_text(encoding="utf-8"))
        counts = pf.summarize(self.records)
        self.assertEqual(counts["confirmed"], len(payload["confirmed"]))
        self.assertEqual(counts["needs_validation"], len(payload["needs_validation"]))
        self.assertEqual(counts["hardening"], len(payload["hardening"]))
        self.assertEqual(len(self.records), 11)

    def test_record_ids_are_unique(self):
        ids = [r.record_id for r in self.records]
        self.assertEqual(len(ids), len(set(ids)), msg=f"duplicate record_id(s) in {ids}")

    def test_merge_group_constituents_both_present(self):
        # b55e8630 (primary) and 809bd41e (merged_from) both export as their
        # own confirmed rows -- export.py rule 3 ("every constituent Finding
        # is exported").
        hashes = {r.sink_hash for r in self.records if r.verdict == "confirmed"}
        self.assertIn("b55e8630", hashes)
        self.assertIn("809bd41e", hashes)
        primary = next(r for r in self.records if r.sink_hash == "809bd41e")
        self.assertFalse(primary.is_primary)
        self.assertEqual(primary.primary_sink_hash, "b55e8630")

    def test_manual_review_bucket_present(self):
        manual = [r for r in self.records if r.verdict == "confirmed" and r.review_bucket == "manual_review"]
        self.assertEqual(len(manual), 2)

    def test_needs_validation_and_hardening_fields(self):
        nv = next(r for r in self.records if r.verdict == "needs_validation" and r.sink_hash == "809bd41e")
        self.assertEqual(nv.matched_to, "b55e8630")
        self.assertIn("Unparameterized DQL concatenation", nv.claimed_root_cause)
        self.assertTrue(nv.blockers)

        unmatched_nv = next(r for r in self.records if r.verdict == "needs_validation" and r.sink_hash == "nohash00")
        self.assertIsNone(unmatched_nv.matched_to)

        hardening = next(r for r in self.records if r.verdict == "hardening" and r.sink_hash == "33c924c1")
        self.assertEqual(hardening.matched_to, "116a9474")
        self.assertIn("field-level encryption", hardening.text)

    def test_record_roundtrips_through_dict(self):
        for r in self.records:
            self.assertEqual(pf.Record.from_dict(r.to_dict()), r)


class MissingOrMismatchedContractTests(unittest.TestCase):
    """Phase 0.1: missing / wrong-schema findings.json must refuse loudly,
    never fall back to parsing REPORT.md."""

    def test_missing_findings_json(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            with self.assertRaises(pf.FindingsContractError) as ctx:
                pf.load(review_root)
            msg = str(ctx.exception)
            self.assertIn("findings.json", msg)
            self.assertIn("not found", msg)
            self.assertIn("4.3.0", msg)

    def test_wrong_schema_version(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / "findings.json").write_text(
                json.dumps({"schema_version": 999, "confirmed": [], "needs_validation": [], "hardening": []}),
                encoding="utf-8",
            )
            with self.assertRaises(pf.FindingsContractError) as ctx:
                pf.load(review_root)
            msg = str(ctx.exception)
            self.assertIn("999", msg)
            self.assertIn(str(pf.EXPECTED_SCHEMA_VERSION), msg)

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / "findings.json").write_text("{not json", encoding="utf-8")
            with self.assertRaises(pf.FindingsContractError):
                pf.load(review_root)

    def test_empty_findings_json_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / "findings.json").write_text(
                json.dumps({"schema_version": 1, "confirmed": [], "needs_validation": [], "hardening": []}),
                encoding="utf-8",
            )
            records = pf.load(review_root)
            self.assertEqual(records, [])


class CoverageTests(unittest.TestCase):
    """DoD #6: assert_full_coverage must catch both an orphan and a
    duplicate (and, as a bonus, an unknown record_id reference)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = fixtures_lib.build_review_root(Path(cls.tmp.name) / "review")
        cls.records = pf.load(cls.review_root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_full_grouping_passes(self):
        pf.assert_full_coverage(self.records, fixtures_lib.FULL_GROUPING)  # must not raise

    def test_orphan_is_caught(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triage-leads"] = [rid for rid in grouping["triage-leads"] if rid != "hardening#1"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("orphan", msg)
        self.assertIn("hardening#1", msg)

    def test_duplicate_is_caught(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triage-leads"] = grouping["triage-leads"] + ["confirmed#0"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("duplicate", msg)
        self.assertIn("confirmed#0", msg)

    def test_unknown_record_id_is_caught(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triage-leads"] = grouping["triage-leads"] + ["confirmed#999"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        self.assertIn("unknown", str(ctx.exception))

    def test_both_orphan_and_duplicate_reported_together(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triage-leads"] = [rid for rid in grouping["triage-leads"] if rid != "hardening#1"]
        grouping["u1-injection"] = grouping["u1-injection"] + ["confirmed#0"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("orphan", msg)
        self.assertIn("duplicate", msg)


class BundleTests(unittest.TestCase):
    """DoD #4: bundle() against the real REPORT/*.md files."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = fixtures_lib.build_review_root(Path(cls.tmp.name) / "review")
        cls.records = pf.load(cls.review_root)
        cls.out_dir = Path(cls.tmp.name) / "bundles"
        pf.assert_full_coverage(cls.records, fixtures_lib.FULL_GROUPING)
        pf.bundle(cls.records, fixtures_lib.FULL_GROUPING, review_root=cls.review_root, out_dir=cls.out_dir)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_one_bundle_file_per_unit(self):
        for unit_id in fixtures_lib.FULL_GROUPING:
            self.assertTrue((self.out_dir / f"{unit_id}.md").is_file())

    def test_injection_bundle_has_merge_group_body_once(self):
        text = (self.out_dir / "u1-injection.md").read_text(encoding="utf-8")
        # The merge-group body (primary b55e8630) must appear -- and only
        # once, even though both constituent records (confirmed#0, #1) are
        # in this unit (bundle() dedupes by primary_sink_hash).
        self.assertEqual(text.count("Repo::findByName"), text.count("Repo::findByName"))  # sanity, not a real assert
        self.assertIn("SELECT u FROM User u WHERE u.name", text)
        self.assertEqual(text.count("* **sink_hash**: b55e8630"), 1)
        # The attached needs_validation note rides along inside that same block.
        self.assertIn("Unparameterized DQL concatenation", text)

    def test_crypto_bundle_has_hardening_note_rendered_from_json(self):
        text = (self.out_dir / "u2-crypto.md").read_text(encoding="utf-8")
        self.assertIn("accessToken", text)
        self.assertIn("field-level encryption", text)

    def test_manual_review_bundle_looks_up_manual_review_file(self):
        text = (self.out_dir / "triage-manual.md").read_text(encoding="utf-8")
        self.assertIn("Misc::speculate", text)
        self.assertIn("should_be_rejected", text)

    def test_triage_leads_bundle_renders_from_findings_json_fields(self):
        text = (self.out_dir / "triage-leads.md").read_text(encoding="utf-8")
        self.assertIn("no static sink_snippet available", text)
        self.assertIn("No rate limiting on this internal admin-only endpoint", text)


class CliTests(unittest.TestCase):
    """Smoke-test the parse_findings.py CLI end to end (Phase 1 + Phase 3
    invocations), via main() directly (fast, no subprocess)."""

    def test_phase1_then_phase3(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            review_root = fixtures_lib.build_review_root(td_path / "review")
            tickets_root = td_path / "tickets"

            with contextlib.redirect_stdout(io.StringIO()):
                rc = pf.main([str(review_root), "--tickets-root", str(tickets_root)])
            self.assertEqual(rc, 0)
            parsed_path = tickets_root / ".work" / "parsed.json"
            self.assertTrue(parsed_path.is_file())
            parsed = json.loads(parsed_path.read_text(encoding="utf-8"))
            self.assertEqual(len(parsed["records"]), 11)
            self.assertEqual(parsed["findings_json_sha256"], pf.findings_json_sha256(review_root))

            grouping_path = tickets_root / ".work" / "grouping.json"
            grouping_path.write_text(json.dumps(fixtures_lib.FULL_GROUPING), encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                rc2 = pf.main([str(review_root), "--tickets-root", str(tickets_root), "--grouping", str(grouping_path)])
            self.assertEqual(rc2, 0)
            for unit_id in fixtures_lib.FULL_GROUPING:
                self.assertTrue((tickets_root / ".work" / "bundles" / f"{unit_id}.md").is_file())

    def test_phase3_rejects_bad_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            review_root = fixtures_lib.build_review_root(td_path / "review")
            tickets_root = td_path / "tickets"
            with contextlib.redirect_stdout(io.StringIO()):
                pf.main([str(review_root), "--tickets-root", str(tickets_root)])

            grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
            grouping["triage-leads"] = [rid for rid in grouping["triage-leads"] if rid != "hardening#1"]
            grouping_path = tickets_root / ".work" / "grouping.json"
            grouping_path.write_text(json.dumps(grouping), encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                rc = pf.main([str(review_root), "--tickets-root", str(tickets_root), "--grouping", str(grouping_path)])
            self.assertEqual(rc, 2)
            self.assertFalse((tickets_root / ".work" / "bundles").is_dir())


if __name__ == "__main__":
    unittest.main()
