"""Tests for parse_findings.py -- load / assert_full_coverage / bundle /
the TICKETS_ROOT guard / PROJECT_ROOT resolution / the CLI.

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
import shutil
import subprocess
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
        grouping["triageleads"] = [rid for rid in grouping["triageleads"] if rid != "hardening#1"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("orphan", msg)
        self.assertIn("hardening#1", msg)

    def test_duplicate_is_caught(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triageleads"] = grouping["triageleads"] + ["confirmed#0"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("duplicate", msg)
        self.assertIn("confirmed#0", msg)

    def test_unknown_record_id_is_caught(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triageleads"] = grouping["triageleads"] + ["confirmed#999"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        self.assertIn("unknown", str(ctx.exception))

    def test_unit_id_form_is_enforced(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["bad-leads"] = grouping.pop("triageleads")
        grouping["U2Crypto"] = grouping.pop("u2crypto")
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("[a-z0-9]+", msg)
        self.assertIn("bad-leads", msg)
        self.assertIn("U2Crypto", msg)
        self.assertNotIn("orphan", msg)

    def test_both_orphan_and_duplicate_reported_together(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triageleads"] = [rid for rid in grouping["triageleads"] if rid != "hardening#1"]
        grouping["u1injection"] = grouping["u1injection"] + ["confirmed#0"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("orphan", msg)
        self.assertIn("duplicate", msg)

    def test_malformed_grouping_shape_reported_in_one_coverage_error(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["u1injection"] = "confirmed#0"  # a str is iterable -- must not be read char by char
        grouping["u2crypto"] = grouping["u2crypto"] + [{"record_id": "confirmed#0"}, 7]
        grouping["emptied"] = []
        grouping["triageleads"] = [rid for rid in grouping["triageleads"] if rid != "hardening#1"]
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("not a list", msg)
        self.assertIn("u1injection (str)", msg)
        self.assertIn("empty unit", msg)
        self.assertIn("emptied", msg)
        self.assertIn("non-string record_id", msg)
        self.assertIn("u2crypto: {'record_id': 'confirmed#0'}", msg)
        self.assertIn("u2crypto: 7", msg)
        self.assertIn("hardening#1", msg)  # the orphan, reported alongside
        self.assertNotIn("unknown", msg)

    def test_non_list_value_types_are_named(self):
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["extra"] = {"confirmed#0": True}
        grouping["other"] = None
        with self.assertRaises(pf.CoverageError) as ctx:
            pf.assert_full_coverage(self.records, grouping)
        msg = str(ctx.exception)
        self.assertIn("extra (dict)", msg)
        self.assertIn("other (NoneType)", msg)


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
        text = (self.out_dir / "u1injection.md").read_text(encoding="utf-8")
        # The merge-group body (primary b55e8630) must appear -- and only
        # once, even though both constituent records (confirmed#0, #1) are
        # in this unit (one block per merge group, anchored on its primary).
        self.assertEqual(text.count("# Vulnerability "), 1)
        self.assertEqual(text.count("* **enclosing_symbol**: Repo::findByName"), 1)
        self.assertIn("SELECT u FROM User u WHERE u.name", text)
        self.assertEqual(text.count("* **sink_hash**: b55e8630"), 1)
        # The attached needs_validation note rides along inside that same block.
        self.assertIn("Unparameterized DQL concatenation", text)

    def _manifest_rows(self, unit_id: str) -> dict[str, list[str]]:
        text = (self.out_dir / f"{unit_id}.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("## Manifest\n"), msg=text[:200])
        manifest = text.split("\n\n---\n\n", 1)[0]
        rows = {}
        for line in manifest.splitlines()[4:]:
            cells = [c.strip() for c in line.strip("|").split(" | ")]
            rows[cells[0]] = cells
        return rows

    def test_manifest_lists_every_record_of_every_unit(self):
        for unit_id, record_ids in fixtures_lib.FULL_GROUPING.items():
            self.assertEqual(list(self._manifest_rows(unit_id)), record_ids)

    def test_manifest_includes_collapsed_constituent(self):
        rows = self._manifest_rows("u1injection")
        self.assertEqual(rows["confirmed#1"][:4], ["confirmed#1", "confirmed", "809bd41e", "src/Repo.php:42"])
        self.assertIn("[MERGED_DESPITE_HASH_MISMATCH]", rows["confirmed#1"][5])
        self.assertEqual(rows["needs_validation#0"][6], "b55e8630")

    def test_manifest_marks_missing_location(self):
        rows = self._manifest_rows("triagemanual")
        self.assertEqual(rows["confirmed#5"][3], "(no location)")

    def test_collapsed_block_names_the_records_it_covers(self):
        text = (self.out_dir / "u1injection.md").read_text(encoding="utf-8")
        self.assertIn("covers: confirmed#0, confirmed#1\n", text)
        self.assertIn("covers: needs_validation#0\n", text)

    def test_crypto_bundle_has_hardening_note_rendered_from_json(self):
        text = (self.out_dir / "u2crypto.md").read_text(encoding="utf-8")
        self.assertIn("accessToken", text)
        self.assertIn("field-level encryption", text)

    def test_manual_review_bundle_looks_up_manual_review_file(self):
        text = (self.out_dir / "triagemanual.md").read_text(encoding="utf-8")
        self.assertIn("Misc::speculate", text)
        self.assertIn("should_be_rejected", text)

    def test_triage_leads_bundle_renders_from_findings_json_fields(self):
        text = (self.out_dir / "triageleads.md").read_text(encoding="utf-8")
        self.assertIn("no static sink_snippet available", text)
        self.assertIn("No rate limiting on this internal admin-only endpoint", text)


SHARED_HASH = "5a5a5a5a"


def _confirmed_row(sink_hash, *, file, line, is_primary, primary=SHARED_HASH, symbol="Svc::run"):
    return {
        "verdict": "confirmed",
        "sink_hash": sink_hash,
        "primary_sink_hash": primary,
        "is_primary": is_primary,
        "review_bucket": "main",
        "sink_file": file,
        "sink_line": line,
        "sink_kind": "dql_concat",
        "root_cause_family": "injection",
        "enclosing_symbol": symbol,
        "severity": "High",
        "confidence": 8,
        "category": "sql_injection",
        "condition_keys": [],
        "discovered_via": "checklist:injection.md",
        "source_file": "W1.md",
        "slice_id": "W1",
        "flags": [],
    }


def _vuln_block(n: int, loc: str, sink_hash: str, marker: str) -> str:
    return (
        f"# Vulnerability {n}: [sql_injection]: `{loc}`\n\n"
        f"* **Severity**: High\n"
        f"* **Description**: {marker}\n"
        f"* **sink_hash**: {sink_hash}\n"
    )


class SharedHashBundleTests(unittest.TestCase):
    """Two independent confirmed groups whose primaries share a
    primary_sink_hash (same snippet, different file) -- synthetic
    findings.json + REPORT, placeholder paths."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.review_root = Path(self.tmp.name) / "review"
        (self.review_root / "REPORT").mkdir(parents=True)
        payload = {
            "schema_version": 1,
            "confirmed": [
                _confirmed_row(SHARED_HASH, file="src/Alpha.php", line=10, is_primary=True),
                # Location matches neither primary: its group is ambiguous.
                _confirmed_row("6b6b6b6b", file="src/Gamma.php", line=5, is_primary=False),
                _confirmed_row(SHARED_HASH, file="src/Beta.php", line=20, is_primary=True),
                # Same file:line as the Beta primary: pinned to that group.
                _confirmed_row("7c7c7c7c", file="src/Beta.php", line=20, is_primary=False),
            ],
            "needs_validation": [],
            "hardening": [],
        }
        (self.review_root / "findings.json").write_text(json.dumps(payload), encoding="utf-8")
        (self.review_root / "REPORT" / "injection.md").write_text(
            "# SECURITY_REVIEW_RESULTS -- injection\n\n"
            + _vuln_block(1, "src/Alpha.php:10", SHARED_HASH, "Synthetic marker ALPHA body.")
            + "\n"
            + _vuln_block(2, "src/Beta.php:20", SHARED_HASH, "Synthetic marker BETA body."),
            encoding="utf-8",
        )
        self.records = pf.load(self.review_root)
        self.out_dir = Path(self.tmp.name) / "bundles"

    def tearDown(self):
        self.tmp.cleanup()

    def _bundle(self, grouping: dict) -> dict[str, str]:
        pf.bundle(self.records, grouping, review_root=self.review_root, out_dir=self.out_dir)
        return {u: (self.out_dir / f"{u}.md").read_text(encoding="utf-8") for u in grouping}

    def test_each_independent_group_gets_its_own_body(self):
        text = self._bundle({"u1shared": ["confirmed#0", "confirmed#1", "confirmed#2", "confirmed#3"]})["u1shared"]
        self.assertEqual(text.count("Synthetic marker ALPHA body."), 1)
        self.assertEqual(text.count("Synthetic marker BETA body."), 1)

    def test_ambiguous_constituent_is_listed_under_every_candidate_block(self):
        text = self._bundle({"u1shared": ["confirmed#0", "confirmed#1", "confirmed#2", "confirmed#3"]})["u1shared"]
        self.assertIn("covers: confirmed#0, confirmed#1\n\n# Vulnerability 1:", text)
        self.assertIn("covers: confirmed#1, confirmed#2, confirmed#3\n\n# Vulnerability 2:", text)

    def test_constituent_pinned_by_location_follows_that_primary_only(self):
        text = self._bundle({"u1all": ["confirmed#0", "confirmed#2", "confirmed#3"]})["u1all"]
        self.assertIn("covers: confirmed#0\n\n# Vulnerability 1:", text)
        self.assertIn("covers: confirmed#2, confirmed#3\n\n# Vulnerability 2:", text)

    def test_constituent_split_from_its_pinned_primary_gets_that_body(self):
        text = self._bundle({"u1prim": ["confirmed#0", "confirmed#1", "confirmed#2"], "u2lone": ["confirmed#3"]})["u2lone"]
        self.assertIn("covers: confirmed#3\n", text)
        self.assertIn("Synthetic marker BETA body.", text)
        self.assertNotIn("ALPHA", text)

    def test_ambiguous_constituent_split_from_its_primaries_gets_every_candidate_body(self):
        # Neither REPORT title carries the constituent's location, so a
        # lookup by hash + its own location could only guess the first block.
        text = self._bundle({"u1prim": ["confirmed#0", "confirmed#2", "confirmed#3"], "u2lone": ["confirmed#1"]})["u2lone"]
        self.assertIn("covers: confirmed#1\n\n# Vulnerability 1:", text)
        self.assertIn("covers: confirmed#1\n\n# Vulnerability 2:", text)
        self.assertIn("Synthetic marker ALPHA body.", text)
        self.assertIn("Synthetic marker BETA body.", text)


def _fixture_sink_files(records) -> list[str]:
    return sorted({r.sink_file for r in records if r.sink_file})


def _run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = pf.main(argv)
    return rc, out.getvalue(), err.getvalue()


def _tree_snapshot(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))


class CheckTicketsRootTests(unittest.TestCase):
    """The TICKETS_ROOT guard's four verdicts, on synthetic directories."""

    SHA = "a" * 64

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.audit_root = (self.base / "audit").resolve()
        self.audit_root.mkdir()
        self.tickets = self.base / "tickets"

    def tearDown(self):
        self.tmp.cleanup()

    def _write_parsed(self, *, audit_root=None, sha=None, project_root=None):
        work = self.tickets / ".work"
        work.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "audit_root": str(audit_root or self.audit_root),
            "findings_json_sha256": sha or self.SHA,
            "records": [],
        }
        if project_root is not None:
            payload["project_root"] = project_root
        (work / "parsed.json").write_text(json.dumps(payload), encoding="utf-8")

    def _check(self):
        return pf.check_tickets_root(self.tickets, self.audit_root, self.SHA)

    def test_missing_dir_is_ok(self):
        self.assertEqual(self._check().kind, "ok")

    def test_state_after_phase_0_3_is_ok(self):
        # Exactly what Phase 0.3 leaves behind before Phase 1 runs.
        (self.tickets / ".work").mkdir(parents=True)
        (self.tickets / ".gitignore").write_text("*\n", encoding="utf-8")
        verdict = self._check()
        self.assertEqual(verdict.kind, "ok")
        self.assertEqual(verdict.found, ())

    def test_nested_empty_dirs_are_ok(self):
        (self.tickets / ".work" / "bundles").mkdir(parents=True)
        (self.tickets / "sub" / "deeper").mkdir(parents=True)
        self.assertEqual(self._check().kind, "ok")

    def test_nested_gitignore_is_content(self):
        (self.tickets / ".work").mkdir(parents=True)
        (self.tickets / ".work" / ".gitignore").write_text("*\n", encoding="utf-8")
        verdict = self._check()
        self.assertEqual(verdict.kind, "foreign")
        self.assertEqual(verdict.found, (".work/.gitignore",))

    def test_archives_do_not_count_as_content(self):
        prev = self.tickets / ".work" / "prev-1" / ".work"
        prev.mkdir(parents=True)
        (prev / "parsed.json").write_text("{}", encoding="utf-8")
        (self.tickets / ".work" / "prev-1" / "high-u1x-placeholder.md").write_text("x", encoding="utf-8")
        self.assertEqual(self._check().kind, "ok")

    def test_same_audit_same_sha_is_resume(self):
        self._write_parsed(project_root="/placeholder/project")
        (self.tickets / "high-u1x-placeholder.md").write_text("x", encoding="utf-8")
        verdict = self._check()
        self.assertEqual(verdict.kind, "resume")
        self.assertEqual(verdict.existing_parsed["project_root"], "/placeholder/project")

    def test_same_audit_other_sha_is_stale(self):
        self._write_parsed(sha="b" * 64)
        verdict = self._check()
        self.assertEqual(verdict.kind, "stale")
        self.assertIn(".work/parsed.json", verdict.found)

    def test_non_empty_without_parsed_is_foreign_and_lists_files(self):
        self.tickets.mkdir()
        (self.tickets / "README.md").write_text("someone else's", encoding="utf-8")
        (self.tickets / ".gitignore").write_text("*\n", encoding="utf-8")
        verdict = self._check()
        self.assertEqual(verdict.kind, "foreign")
        self.assertEqual(verdict.found, ("README.md",))

    def test_parsed_for_other_audit_is_foreign(self):
        self._write_parsed(audit_root=self.base / "other-audit")
        self.assertEqual(self._check().kind, "foreign")

    def test_corrupt_parsed_is_foreign(self):
        (self.tickets / ".work").mkdir(parents=True)
        (self.tickets / ".work" / "parsed.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(self._check().kind, "foreign")

    def test_tickets_root_is_a_file_is_foreign(self):
        self.tickets.write_text("x", encoding="utf-8")
        self.assertEqual(self._check().kind, "foreign")

    def _outside_work_with_matching_parsed(self) -> Path:
        # A matching parsed.json behind the link: without the symlink check
        # this would read as "resume" (or as empty if the dir were empty).
        outside = self.base / "outside"
        outside.mkdir()
        payload = {"schema_version": 1, "audit_root": str(self.audit_root), "findings_json_sha256": self.SHA, "records": []}
        (outside / "parsed.json").write_text(json.dumps(payload), encoding="utf-8")
        return outside

    def test_symlinked_work_is_foreign_even_with_matching_parsed(self):
        outside = self._outside_work_with_matching_parsed()
        self.tickets.mkdir()
        (self.tickets / ".work").symlink_to(outside, target_is_directory=True)
        verdict = self._check()
        self.assertEqual(verdict.kind, "foreign")
        self.assertEqual(verdict.symlinks, (".work",))
        self.assertIn("(symlink)", verdict.found[0])

    def test_symlinked_empty_work_is_foreign_not_ok(self):
        outside = self.base / "outside"
        outside.mkdir()
        self.tickets.mkdir()
        (self.tickets / ".work").symlink_to(outside, target_is_directory=True)
        self.assertEqual(self._check().kind, "foreign")

    def test_symlink_named_like_an_archive_or_gitignore_is_foreign(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.tickets / ".work").mkdir(parents=True)
        (self.tickets / ".work" / "prev-1").symlink_to(outside, target_is_directory=True)
        (self.tickets / ".gitignore").symlink_to(outside / "gitignore")
        verdict = self._check()
        self.assertEqual(verdict.kind, "foreign")
        self.assertEqual(verdict.symlinks, (".gitignore", ".work/prev-1"))

    def test_tickets_root_itself_a_symlink_is_foreign(self):
        real = self.base / "real-tickets"
        real.mkdir()
        self.tickets.symlink_to(real, target_is_directory=True)
        verdict = self._check()
        self.assertEqual(verdict.kind, "foreign")
        self.assertEqual(verdict.symlinks, (".",))


class ArchivePreviousTests(unittest.TestCase):
    def test_moves_everything_but_gitignore_and_prior_archives(self):
        with tempfile.TemporaryDirectory() as td:
            tickets = Path(td) / "tickets"
            (tickets / ".work" / "verify").mkdir(parents=True)
            (tickets / ".work" / "prev-1").mkdir()
            (tickets / ".work" / "prev-1" / "old.md").write_text("old", encoding="utf-8")
            (tickets / ".gitignore").write_text("*\n", encoding="utf-8")
            (tickets / "INDEX.md").write_text("index", encoding="utf-8")
            (tickets / "high-u1x-placeholder.md").write_text("unit", encoding="utf-8")
            (tickets / ".work" / "parsed.json").write_text("{}", encoding="utf-8")
            (tickets / ".work" / "verify" / "u1x.json").write_text("{}", encoding="utf-8")

            dest = pf.archive_previous(tickets)

            self.assertEqual(dest, tickets / ".work" / "prev-2")
            self.assertEqual(
                _tree_snapshot(tickets),
                [
                    ".gitignore",
                    ".work",
                    ".work/prev-1",
                    ".work/prev-1/old.md",
                    ".work/prev-2",
                    ".work/prev-2/.work",
                    ".work/prev-2/.work/parsed.json",
                    ".work/prev-2/.work/verify",
                    ".work/prev-2/.work/verify/u1x.json",
                    ".work/prev-2/INDEX.md",
                    ".work/prev-2/high-u1x-placeholder.md",
                ],
            )
            self.assertEqual(pf.check_tickets_root(tickets, Path(td) / "audit", "a" * 64).kind, "ok")

    def test_refuses_symlinked_work_and_moves_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            tickets = Path(td) / "tickets"
            outside = Path(td) / "outside"
            outside.mkdir()
            (outside / "parsed.json").write_text("{}", encoding="utf-8")
            tickets.mkdir()
            (tickets / "INDEX.md").write_text("index", encoding="utf-8")
            (tickets / ".work").symlink_to(outside, target_is_directory=True)
            before_outside, before_tickets = _tree_snapshot(outside), _tree_snapshot(tickets)
            with self.assertRaises(pf.TicketsRootError):
                pf.archive_previous(tickets)
            self.assertEqual(_tree_snapshot(outside), before_outside)
            self.assertEqual(_tree_snapshot(tickets), before_tickets)

    def test_nothing_to_move_creates_no_archive(self):
        with tempfile.TemporaryDirectory() as td:
            tickets = Path(td) / "tickets"
            (tickets / ".work").mkdir(parents=True)
            (tickets / ".gitignore").write_text("*\n", encoding="utf-8")
            self.assertIsNone(pf.archive_previous(tickets))
            self.assertEqual(_tree_snapshot(tickets), [".gitignore", ".work"])


class ResolveProjectRootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (Path(self.tmp.name) / "saved").resolve()
        self.other = (Path(self.tmp.name) / "other").resolve()
        self.saved.mkdir()
        self.other.mkdir()
        self.parsed = {"project_root": str(self.saved)}

    def tearDown(self):
        self.tmp.cleanup()

    def test_resume_uses_saved_root(self):
        self.assertEqual(pf.resolve_project_root(None, "resume", self.parsed), self.saved)

    def test_resume_accepts_matching_explicit_root(self):
        self.assertEqual(pf.resolve_project_root(self.saved, "resume", self.parsed), self.saved)

    def test_resume_rejects_contradicting_explicit_root(self):
        with self.assertRaises(pf.ProjectRootError):
            pf.resolve_project_root(self.other, "resume", self.parsed)

    def test_ok_prefers_explicit_root(self):
        self.assertEqual(pf.resolve_project_root(self.other, "ok", self.parsed), self.other)

    def test_ok_defaults_to_cwd(self):
        self.assertEqual(pf.resolve_project_root(None, "ok", None), Path.cwd().resolve())

    def test_resume_without_saved_root_falls_back(self):
        self.assertEqual(pf.resolve_project_root(self.other, "resume", {}), self.other)


class CheckProjectRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = fixtures_lib.build_review_root(Path(cls.tmp.name) / "review")
        cls.records = pf.load(cls.review_root)
        cls.sink_files = _fixture_sink_files(cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_fixture_has_an_empty_sink_file_and_five_unique_ones(self):
        self.assertTrue(any(not r.sink_file for r in self.records))
        self.assertEqual(len(self.sink_files), 5)

    def test_all_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            root = fixtures_lib.build_project_tree(Path(td), self.sink_files)
            self.assertEqual(pf.check_project_root(self.records, root), (5, 5))

    def test_some_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            root = fixtures_lib.build_project_tree(Path(td), self.sink_files[:2])
            self.assertEqual(pf.check_project_root(self.records, root), (2, 5))

    def test_none_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(pf.check_project_root(self.records, Path(td)), (0, 5))

    def test_no_sink_files_at_all(self):
        self.assertEqual(pf.check_project_root([], Path(".")), (0, 0))


class CliTests(unittest.TestCase):
    """The parse_findings.py CLI end to end (Phase 0.3 guard, Phase 1,
    Phase 3), via main() directly (fast, no subprocess)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.review_root = fixtures_lib.build_review_root(self.base / "review")
        self.sink_files = _fixture_sink_files(pf.load(self.review_root))
        self.project = fixtures_lib.build_project_tree(self.base / "project", self.sink_files)
        self.tickets = self.base / "tickets"
        self.parsed_path = self.tickets / ".work" / "parsed.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _phase1(self, *extra: str, project: Path | None = None) -> tuple[int, str, str]:
        argv = [str(self.review_root), "--tickets-root", str(self.tickets), *extra]
        if project is not None:
            argv += ["--project-root", str(project)]
        return _run_main(argv)

    def _parsed(self) -> dict:
        return json.loads(self.parsed_path.read_text(encoding="utf-8"))

    def _write_grouping(self, grouping: dict) -> Path:
        path = self.tickets / ".work" / "grouping.json"
        path.write_text(json.dumps(grouping), encoding="utf-8")
        return path

    def test_phase1_then_phase3(self):
        rc, out, _ = self._phase1(project=self.project)
        self.assertEqual(rc, 0)
        parsed = self._parsed()
        self.assertEqual(len(parsed["records"]), 11)
        self.assertEqual(parsed["findings_json_sha256"], pf.findings_json_sha256(self.review_root))
        self.assertEqual(parsed["project_root"], str(self.project.resolve()))
        self.assertEqual(parsed["project_root_resolved"], [5, 5])
        self.assertEqual(json.loads(out)["tickets_root_verdict"], "ok")

        grouping_path = self._write_grouping(fixtures_lib.FULL_GROUPING)
        rc2, _, _ = self._phase1("--grouping", str(grouping_path))
        self.assertEqual(rc2, 0)
        for unit_id in fixtures_lib.FULL_GROUPING:
            self.assertTrue((self.tickets / ".work" / "bundles" / f"{unit_id}.md").is_file())

    def test_phase1_after_phase_0_3_setup_is_ok(self):
        (self.tickets / ".work").mkdir(parents=True)
        (self.tickets / ".gitignore").write_text("*\n", encoding="utf-8")
        rc, out, _ = self._phase1(project=self.project)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["tickets_root_verdict"], "ok")

    def test_phase3_rejects_bad_coverage(self):
        self._phase1(project=self.project)
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["triageleads"] = [rid for rid in grouping["triageleads"] if rid != "hardening#1"]
        rc, _, _ = self._phase1("--grouping", str(self._write_grouping(grouping)))
        self.assertEqual(rc, 2)
        self.assertFalse((self.tickets / ".work" / "bundles").is_dir())

    def test_phase3_rejects_dashed_unit_id_before_bundling(self):
        self._phase1(project=self.project)
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["bad-leads"] = grouping.pop("triageleads")
        rc, _, err = self._phase1("--grouping", str(self._write_grouping(grouping)))
        self.assertEqual(rc, 2)
        self.assertIn("bad-leads", err)
        self.assertFalse((self.tickets / ".work" / "bundles").is_dir())

    def test_phase3_malformed_grouping_fails_before_touching_parsed_json(self):
        self._phase1(project=self.project)
        parsed = self._parsed()
        parsed["marker"] = "untouched"  # a rewrite by this run would drop it
        self.parsed_path.write_text(json.dumps(parsed), encoding="utf-8")
        grouping = {k: list(v) for k, v in fixtures_lib.FULL_GROUPING.items()}
        grouping["u1injection"] = grouping["u1injection"] + [{"record_id": "confirmed#0"}]
        grouping["emptied"] = []
        rc, _, err = self._phase1("--grouping", str(self._write_grouping(grouping)))
        self.assertEqual(rc, 2)
        self.assertIn("non-string record_id", err)
        self.assertIn("emptied", err)
        self.assertEqual(self._parsed().get("marker"), "untouched")
        self.assertFalse((self.tickets / ".work" / "bundles").is_dir())

    def test_phase3_malformed_grouping_with_archive_previous_archives_nothing(self):
        self._phase1(project=self.project)
        grouping_path = self.base / "grouping.json"
        grouping_path.write_text(json.dumps({"u1x": "confirmed#0"}), encoding="utf-8")
        before = _tree_snapshot(self.tickets)
        rc, _, _ = self._phase1("--archive-previous", "--grouping", str(grouping_path), project=self.project)
        self.assertEqual(rc, 2)
        self.assertEqual(_tree_snapshot(self.tickets), before)

    def _link_work_outside(self) -> Path:
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("not triage output", encoding="utf-8")
        self.tickets.mkdir()
        (self.tickets / ".work").symlink_to(outside, target_is_directory=True)
        return outside

    def test_symlinked_work_blocks_phase1_and_writes_nothing_outside(self):
        outside = self._link_work_outside()
        rc, _, err = self._phase1(project=self.project)
        self.assertEqual(rc, 2)
        self.assertIn("symlink", err)
        self.assertEqual(_tree_snapshot(outside), ["keep.txt"])

    def test_symlinked_work_refuses_archive_previous(self):
        outside = self._link_work_outside()
        rc, _, err = self._phase1("--archive-previous", project=self.project)
        self.assertEqual(rc, 2)
        self.assertIn("refusing --archive-previous", err)
        self.assertEqual(_tree_snapshot(outside), ["keep.txt"])
        self.assertEqual(_tree_snapshot(self.tickets), [".work"])

    def test_symlinked_tickets_root_is_refused(self):
        real = self.base / "real-tickets"
        real.mkdir()
        self.tickets.symlink_to(real, target_is_directory=True)
        rc, out, _ = self._phase1("--check-only")
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out)["verdict"], "foreign")
        for extra in ((), ("--archive-previous",)):
            rc, _, _ = self._phase1(*extra, project=self.project)
            self.assertEqual(rc, 2)
        self.assertEqual(_tree_snapshot(real), [])

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_archive_previous_refuses_git_tracked_tickets_root(self):
        self.tickets.mkdir()
        subprocess.run(["git", "init", "-q", str(self.tickets)], check=True)
        (self.tickets / "Controller.php").write_text("<?php\n// synthetic placeholder\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.tickets), "add", "Controller.php"], check=True)
        rc, _, err = self._phase1("--archive-previous", project=self.project)
        self.assertEqual(rc, 2)
        self.assertIn("tracked by git", err)
        self.assertIn("Controller.php", err)
        self.assertTrue((self.tickets / "Controller.php").is_file())
        self.assertFalse((self.tickets / ".work").exists())

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_archive_previous_allows_untracked_content_inside_a_repo(self):
        repo = self.base / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "tracked.txt").write_text("x", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        tickets = repo / "security-tickets"
        tickets.mkdir()
        (tickets / "notes.md").write_text("x", encoding="utf-8")
        rc, _, _ = _run_main(
            [str(self.review_root), "--tickets-root", str(tickets), "--project-root", str(self.project), "--archive-previous"]
        )
        self.assertEqual(rc, 0)
        self.assertTrue((tickets / ".work" / "prev-1" / "notes.md").is_file())

    def test_archive_previous_refuses_when_git_times_out(self):
        self.tickets.mkdir()
        (self.tickets / "notes.md").write_text("x", encoding="utf-8")
        real_run = pf.subprocess.run

        def hanging_git(cmd, *args, **kwargs):
            if cmd[:1] == ["git"]:
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
            return real_run(cmd, *args, **kwargs)

        pf.subprocess.run = hanging_git
        try:
            rc, _, err = self._phase1("--archive-previous", project=self.project)
        finally:
            pf.subprocess.run = real_run
        self.assertEqual(rc, 2)
        self.assertIn("did not answer", err)
        self.assertEqual(_tree_snapshot(self.tickets), ["notes.md"])

    def test_git_tracked_files_is_none_outside_a_repo(self):
        # tempfile paths are not inside a git work tree on a normal machine.
        probe = subprocess.run(["git", "-C", str(self.base), "rev-parse"], capture_output=True) if shutil.which("git") else None
        if probe is not None and probe.returncode == 0:
            self.skipTest("temp dir unexpectedly inside a git work tree")
        self.assertIsNone(pf.git_tracked_files(self.base))

    def test_check_only_on_foreign_dir_writes_nothing(self):
        self.tickets.mkdir()
        (self.tickets / "notes.md").write_text("private skill output", encoding="utf-8")
        before = _tree_snapshot(self.tickets)
        rc, out, err = self._phase1("--check-only", project=self.project)
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out)["verdict"], "foreign")
        self.assertIn("notes.md", err)
        self.assertEqual(_tree_snapshot(self.tickets), before)

    def test_check_only_on_missing_dir_creates_nothing(self):
        rc, out, _ = self._phase1("--check-only")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["verdict"], "ok")
        self.assertFalse(self.tickets.exists())

    def test_check_only_reports_resume(self):
        self._phase1(project=self.project)
        rc, out, _ = self._phase1("--check-only")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["verdict"], "resume")

    def test_check_only_refuses_archive_previous(self):
        self.tickets.mkdir()
        (self.tickets / "notes.md").write_text("x", encoding="utf-8")
        rc, _, _ = self._phase1("--check-only", "--archive-previous")
        self.assertEqual(rc, 2)
        self.assertEqual(_tree_snapshot(self.tickets), ["notes.md"])

    def test_foreign_dir_blocks_phase1(self):
        self.tickets.mkdir()
        (self.tickets / "notes.md").write_text("x", encoding="utf-8")
        rc, _, err = self._phase1(project=self.project)
        self.assertEqual(rc, 2)
        self.assertIn("notes.md", err)
        self.assertEqual(_tree_snapshot(self.tickets), ["notes.md"])

    def test_foreign_dir_with_archive_previous(self):
        self.tickets.mkdir()
        (self.tickets / "notes.md").write_text("x", encoding="utf-8")
        rc, out, _ = self._phase1("--archive-previous", project=self.project)
        self.assertEqual(rc, 0)
        self.assertTrue((self.tickets / ".work" / "prev-1" / "notes.md").is_file())
        self.assertFalse((self.tickets / "notes.md").exists())
        self.assertEqual(json.loads(out)["archived_previous_to"], str(self.tickets.resolve() / ".work" / "prev-1"))

    def test_stale_blocks_then_archive_previous_starts_fresh(self):
        self._phase1(project=self.project)
        (self.tickets / "high-u1x-placeholder.md").write_text("unit", encoding="utf-8")
        findings = self.review_root / "findings.json"
        findings.write_text(json.dumps(json.loads(findings.read_text(encoding="utf-8")), indent=4), encoding="utf-8")

        rc, _, err = self._phase1()
        self.assertEqual(rc, 2)
        self.assertIn("stale", err)

        rc2, _, _ = self._phase1("--archive-previous", project=self.project)
        self.assertEqual(rc2, 0)
        prev = self.tickets / ".work" / "prev-1"
        self.assertTrue((prev / "high-u1x-placeholder.md").is_file())
        self.assertTrue((prev / ".work" / "parsed.json").is_file())
        self.assertEqual(self._parsed()["findings_json_sha256"], pf.findings_json_sha256(self.review_root))

    def test_resume_with_archive_previous_restarts_same_audit(self):
        self._phase1(project=self.project)
        (self.tickets / "INDEX.md").write_text("index", encoding="utf-8")
        other = fixtures_lib.build_project_tree(self.base / "other", self.sink_files)
        rc, out, _ = self._phase1("--archive-previous", project=other)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["tickets_root_verdict"], "ok")
        self.assertTrue((self.tickets / ".work" / "prev-1" / "INDEX.md").is_file())
        self.assertEqual(self._parsed()["project_root"], str(other.resolve()))

    def test_archive_previous_refuses_when_audit_root_is_inside(self):
        tickets = self.base
        rc, _, err = _run_main(
            [str(self.review_root), "--tickets-root", str(tickets), "--project-root", str(self.project), "--archive-previous"]
        )
        self.assertEqual(rc, 2)
        self.assertIn("AUDIT_ROOT", err)
        self.assertTrue((self.review_root / "findings.json").is_file())

    def test_project_root_is_sticky_on_resume(self):
        self._phase1(project=self.project)
        rc, out, _ = self._phase1()
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["tickets_root_verdict"], "resume")
        self.assertEqual(self._parsed()["project_root"], str(self.project.resolve()))

    def test_resume_rejects_different_project_root(self):
        self._phase1(project=self.project)
        other = fixtures_lib.build_project_tree(self.base / "other", self.sink_files)
        rc, _, err = self._phase1(project=other)
        self.assertEqual(rc, 2)
        self.assertIn("contradicts", err)
        self.assertEqual(self._parsed()["project_root"], str(self.project.resolve()))

    def test_zero_resolved_writes_nothing_and_retry_is_ok(self):
        wrong = self.base / "wrong"
        wrong.mkdir()
        rc, _, err = self._phase1(project=wrong)
        self.assertEqual(rc, 2)
        self.assertIn("0", err)
        self.assertFalse(self.tickets.exists())

        rc2, out, _ = self._phase1(project=self.project)
        self.assertEqual(rc2, 0)
        self.assertEqual(json.loads(out)["tickets_root_verdict"], "ok")
        self.assertEqual(self._parsed()["project_root"], str(self.project.resolve()))

    def test_zero_resolved_after_archive_retry_is_ok_without_archiving_again(self):
        self.tickets.mkdir()
        (self.tickets / "notes.md").write_text("x", encoding="utf-8")
        wrong = self.base / "wrong"
        wrong.mkdir()
        rc, _, _ = self._phase1("--archive-previous", project=wrong)
        self.assertEqual(rc, 2)
        self.assertFalse(self.parsed_path.exists())

        rc2, out, _ = self._phase1(project=self.project)
        self.assertEqual(rc2, 0)
        self.assertEqual(json.loads(out)["tickets_root_verdict"], "ok")

    def test_partial_resolution_is_a_warning_not_an_error(self):
        partial = fixtures_lib.build_project_tree(self.base / "partial", self.sink_files[:3])
        rc, out, _ = self._phase1(project=partial)
        self.assertEqual(rc, 0)
        summary = json.loads(out)
        self.assertEqual(summary["project_root_resolved"], [3, 5])
        self.assertIn("project_root_warning", summary)
        self.assertEqual(self._parsed()["project_root_resolved"], [3, 5])


if __name__ == "__main__":
    unittest.main()
