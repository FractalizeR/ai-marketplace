"""Tests for `dedupe/export.py` (P2.4 — `findings.json` public contract) and
its wiring into `dedupe_findings.py`'s CLI (wave_format=2 verdict buckets:
`parse_wave` per file, `attach_side_records(merged + manual, ...)`, unmatched
records reaching the renderer, `findings.json` written every run)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedupe as df  # noqa: E402
from dedupe import pipeline  # noqa: E402
from dedupe.export import (  # noqa: E402
    FINDINGS_JSON_NAME,
    SCHEMA_VERSION,
    build_findings_export,
)
from dedupe.refute import RefuteRecord, apply_refute_records  # noqa: E402

_CLI_SCRIPT = str(Path(__file__).resolve().parent.parent / "dedupe_findings.py")

WAVE_FORMAT_MARKER = "<!-- wave_format: 2 -->\n"


# ---------------------------------------------------------------------------
# Fixture builders — self-contained (no cross-import from
# test_dedupe_findings.py; kept deliberately minimal for this file's needs).
# ---------------------------------------------------------------------------


def _vuln_block(
    n: int, sink_file: str, sink_line: int, sink_kind: str, root_cause_family: str,
    enclosing_symbol: str, sink_snippet: str, *,
    severity: str = "High", confidence: int = 9, category: str = "sql_injection",
) -> str:
    return (
        f"# Vulnerability {n}: [{category}]: `{sink_file}:{sink_line}`\n\n"
        f"* **Severity**: {severity}\n"
        f"* **Confidence**: {confidence}/10\n"
        f"* **Category**: {category}\n"
        f"* **sink_kind**: {sink_kind}\n"
        f"* **root_cause_family**: {root_cause_family}\n"
        f"* **enclosing_symbol**: {enclosing_symbol}\n"
        f"* **sink_snippet**: {sink_snippet}\n"
        f"* **Description**: test desc\n"
        f"* **Data path**: X -> {sink_file}:{sink_line}\n"
        f"* **Exploitation scenario**: test payload\n"
        f"* **Impact**: test impact\n"
        f"* **Recommendation**: test fix\n"
        f"* **Discovered via**: checklist:test.md\n\n"
    )


def _nv_block(
    n: int, sink_file: str, sink_line: int, sink_kind: str, root_cause_family: str,
    enclosing_symbol: str, sink_snippet: str, *, claimed_root_cause: str = "unclear",
) -> str:
    return (
        f"# Needs validation {n}: [{sink_kind}]: `{sink_file}:{sink_line}`\n\n"
        f"* **sink_kind**: {sink_kind}\n"
        f"* **root_cause_family**: {root_cause_family}\n"
        f"* **enclosing_symbol**: {enclosing_symbol}\n"
        f"* **sink_snippet**: {sink_snippet}\n"
        f"* **claimed_root_cause**: {claimed_root_cause}\n"
        f"* **trace**: some -> trace\n"
        f"* **blockers**: a fact outside the repo\n"
        f"* **validation_plan_deployment**: check deployment config\n\n"
    )


def _hardening_block(
    n: int, sink_file: str, sink_line: int, sink_kind: str, root_cause_family: str,
    enclosing_symbol: str, sink_snippet: str, *, text: str = "hardening observation",
) -> str:
    return (
        f"# Hardening {n}: [{sink_kind}]: `{sink_file}:{sink_line}`\n\n"
        f"* **sink_kind**: {sink_kind}\n"
        f"* **root_cause_family**: {root_cause_family}\n"
        f"* **enclosing_symbol**: {enclosing_symbol}\n"
        f"* **sink_snippet**: {sink_snippet}\n"
        f"* **text**: {text}\n\n"
    )


def _write(tmpdir: Path, filename: str, *blocks: str) -> Path:
    path = tmpdir / filename
    path.write_text(WAVE_FORMAT_MARKER + "\n".join(blocks), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# export.py — unit-level contract tests.
# ---------------------------------------------------------------------------


class ExportSchemaTests(unittest.TestCase):
    def _confirmed(self, snippet, **kw):
        base = dict(
            title_line="h", sink_file="src/Repo.php", sink_line=42,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find", sink_snippet=snippet,
            severity="High", confidence=9,
        )
        base.update(kw)
        return df.Finding(**base)

    def test_schema_version_present(self):
        payload = build_findings_export([], [], [], [])
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertIsInstance(payload["schema_version"], int)

    def test_empty_input_yields_empty_lists_not_missing_keys(self):
        payload = build_findings_export([], [], [], [])
        self.assertEqual(payload["confirmed"], [])
        self.assertEqual(payload["needs_validation"], [])
        self.assertEqual(payload["hardening"], [])

    def test_no_run_varying_fields(self):
        """No key anywhere in the payload should be a run id / timestamp /
        wall-clock-derived value — the payload must be reproducible byte for
        byte from the same input objects, called twice."""
        f = self._confirmed("$q = $em->createQuery($s);")
        merged, manual = df.dedupe([f])
        p1 = build_findings_export(merged, manual, [], [])
        p2 = build_findings_export(merged, manual, [], [])
        self.assertEqual(json.dumps(p1, sort_keys=True), json.dumps(p2, sort_keys=True))
        # Defensive: scan every key at every level for the usual run-varying
        # names -- a future field addition on the wrong axis fails loudly.
        forbidden_substrings = ("timestamp", "run_id", "run_seq", "generated_at", "created_at")
        text = json.dumps(p1).lower()
        for token in forbidden_substrings:
            self.assertNotIn(token, text, f"payload contains a run-varying-looking key: {token!r}")

    def test_merged_from_is_exported_not_just_primary(self):
        """[MERGED_DESPITE_HASH_MISMATCH] absorbs a losing snippet with a
        DIFFERENT sink_hash into `merged_from` -- the plan's core requirement
        is that the LOSER's sink_hash still appears in findings.json, or the
        live-validation sink_hash-set metric silently shrinks whenever the
        primary-selection coin toss changes winner across runs."""
        f_low = self._confirmed("$q = $em->createQuery($a);", confidence=8, raw_body="short")
        f_high = self._confirmed(
            "$q = $em->createQuery($b);", confidence=10,
            raw_body="much longer body wins as primary",
        )
        merged, manual = df.dedupe([f_low, f_high])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].merged_from), 1)
        loser_hash = merged[0].merged_from[0].sink_hash
        winner_hash = merged[0].primary.sink_hash
        self.assertNotEqual(loser_hash, winner_hash)

        payload = build_findings_export(merged, manual, [], [])
        exported_hashes = {e["sink_hash"] for e in payload["confirmed"]}
        self.assertIn(winner_hash, exported_hashes)
        self.assertIn(loser_hash, exported_hashes,
                       "merged_from finding's sink_hash must be exported too")
        self.assertEqual(len(payload["confirmed"]), 2)
        primaries = [e for e in payload["confirmed"] if e["is_primary"]]
        losers = [e for e in payload["confirmed"] if not e["is_primary"]]
        self.assertEqual(len(primaries), 1)
        self.assertEqual(len(losers), 1)
        # Both constituents share the same group key so a consumer can join.
        self.assertEqual(primaries[0]["primary_sink_hash"], winner_hash)
        self.assertEqual(losers[0]["primary_sink_hash"], winner_hash)

    def test_matched_needs_validation_carries_matched_to(self):
        snippet = "$q = $em->createQuery($s);"
        merged, manual = df.dedupe([self._confirmed(snippet)])
        nv = df.NeedsValidation(
            sink_file="src/Repo.php", sink_line=42, sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="Repo::find",
            sink_snippet=snippet,
        )
        pipeline.attach_side_records(merged, [nv], [])

        payload = build_findings_export(merged, manual, [], [])
        self.assertEqual(len(payload["needs_validation"]), 1)
        entry = payload["needs_validation"][0]
        self.assertEqual(entry["matched_to"], merged[0].primary.sink_hash)
        self.assertEqual(entry["sink_hash"], nv.sink_hash)

    def test_unmatched_records_carry_null_matched_to(self):
        nv = df.NeedsValidation(
            sink_file="src/Other.php", sink_line=7, sink_kind="weak_random",
            root_cause_family="crypto", enclosing_symbol="Rand::gen",
            sink_snippet="mt_rand();",
        )
        hn = df.HardeningNote(
            sink_file="src/Other.php", sink_line=8, sink_kind="csrf_missing",
            root_cause_family="authz", enclosing_symbol="Rand::gen",
            sink_snippet="doIt();", text="note",
        )
        payload = build_findings_export([], [], [nv], [hn])
        self.assertEqual(len(payload["needs_validation"]), 1)
        self.assertEqual(len(payload["hardening"]), 1)
        self.assertIsNone(payload["needs_validation"][0]["matched_to"])
        self.assertIsNone(payload["hardening"][0]["matched_to"])

    def test_manual_review_bucket_is_tagged(self):
        """A finding that lands in `manual` (custom sink, not auto-promoted)
        must still be exported, tagged so a consumer can tell it apart."""
        custom = self._confirmed(
            "doCustomThing();", sink_kind="other:not_mapped_anywhere",
            root_cause_family="other:not_mapped_anywhere",
            severity="Medium", confidence=5,
        )
        merged, manual = df.dedupe([custom])
        self.assertEqual(merged, [])
        self.assertEqual(len(manual), 1)

        payload = build_findings_export(merged, manual, [], [])
        self.assertEqual(len(payload["confirmed"]), 1)
        self.assertEqual(payload["confirmed"][0]["review_bucket"], "manual_review")


# ---------------------------------------------------------------------------
# Order regression: attach_side_records happens BEFORE refute; the plan's
# probe found `apply_refute_records` never reconstructs a MergedFinding, so
# an attached annotation must survive a subsequent refute pass unchanged.
# ---------------------------------------------------------------------------


class AttachBeforeRefuteOrderTests(unittest.TestCase):
    def test_attached_needs_validation_survives_refute_pass(self):
        f = df.Finding(
            title_line="h", sink_file="src/Auth/Guard.php", sink_line=3,
            sink_kind="csrf_missing", root_cause_family="authz",
            enclosing_symbol="Guard::check", sink_snippet="hash_equals($a,$b);",
            severity="High", confidence=9,
        )
        merged, manual = df.dedupe([f])
        nv = df.NeedsValidation(
            sink_file="src/Auth/Guard.php", sink_line=3, sink_kind="csrf_missing",
            root_cause_family="authz", enclosing_symbol="Guard::check",
            sink_snippet="hash_equals($a,$b);",
        )
        # Step 1 (as in dedupe_findings.main): attach BEFORE refute.
        pipeline.attach_side_records(merged, [nv], [])
        self.assertEqual(merged[0].needs_validation, [nv])

        primary = merged[0].primary
        finding_key = f"{primary.sink_hash}:{primary.sink_file}:{primary.sink_line}:{primary.sink_kind}"
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / "src" / "Auth").mkdir(parents=True)
            (td_path / "src" / "Auth" / "Guard.php").write_text(
                "<?php\nfunction checkState() {\n    hash_equals($a, $b);\n}\n",
                encoding="utf-8",
            )
            rec = RefuteRecord(
                finding_key=finding_key, refute_file="src/Auth/Guard.php",
                refute_line=3, rationale="hash_equals present", confidence=9,
            )
            # Step 2: refute pass runs AFTER attach.
            merged_after, invalid = apply_refute_records(merged, [rec], td_path)

        self.assertEqual(invalid, [])
        self.assertIn(df.FLAG_REFUTE_CLAIMED, merged_after[0].flags)
        self.assertEqual(
            merged_after[0].needs_validation, [nv],
            "attached needs_validation annotation must survive the refute pass",
        )


# ---------------------------------------------------------------------------
# CLI wiring — end to end via subprocess, matching the DoD's literal command
# expectations (parse_wave per file, union attach, findings.json every run).
# ---------------------------------------------------------------------------


class CliWiringTests(unittest.TestCase):
    def _run_cli(self, tmpdir: Path, extra_args: list[str] | None = None) -> subprocess.CompletedProcess:
        args = [
            sys.executable, _CLI_SCRIPT,
            "--input-glob", str(tmpdir / "*.md"),
            "--output", str(tmpdir / "REPORT.md"),
        ]
        args.extend(extra_args or [])
        return subprocess.run(args, capture_output=True, text=True, check=True, cwd=str(tmpdir))

    def _mk_waves(self, tmpdir: Path) -> None:
        # W1: a confirmed finding + a matching needs_validation -> attaches.
        _write(
            tmpdir, "W1.md",
            _vuln_block(
                1, "src/Repo.php", 42, "dql_concat", "injection", "Repo::find",
                "$dql = 'SELECT' . $s;",
            ),
            _nv_block(
                1, "src/Repo.php", 42, "dql_concat", "injection", "Repo::find",
                "$dql = 'SELECT' . $s;",
            ),
        )
        # W2: an unmatched hardening note + an unmatched needs_validation.
        _write(
            tmpdir, "W2.md",
            _hardening_block(
                1, "src/Other.php", 99, "csrf_missing", "authz", "Other::do",
                "doSomething();",
            ),
            _nv_block(
                2, "src/Unrelated.php", 5, "weak_random", "crypto", "Rand::gen",
                "mt_rand();",
            ),
        )
        # W3: a custom-sink finding that lands in manual_review, plus a
        # matching needs_validation -- proves the union `merged + manual`
        # (not just `merged`) is what gets passed to attach_side_records.
        _write(
            tmpdir, "W3.md",
            _vuln_block(
                2, "src/Custom.php", 7, "other:not_mapped_anywhere",
                "other:not_mapped_anywhere", "Custom::act", "doCustomThing();",
                severity="Medium", confidence=5,
            ),
            _nv_block(
                3, "src/Custom.php", 7, "other:not_mapped_anywhere",
                "other:not_mapped_anywhere", "Custom::act", "doCustomThing();",
            ),
        )

    def test_findings_json_written_and_shaped(self):
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            self._mk_waves(tmpdir)
            self._run_cli(tmpdir)

            fj_path = tmpdir / FINDINGS_JSON_NAME
            self.assertTrue(fj_path.is_file())
            payload = json.loads(fj_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], SCHEMA_VERSION)

            confirmed = payload["confirmed"]
            self.assertEqual(
                {e["review_bucket"] for e in confirmed}, {"main", "manual_review"}
            )
            nv_entries = payload["needs_validation"]
            self.assertEqual(len(nv_entries), 3)
            matched = [e for e in nv_entries if e["matched_to"] is not None]
            unmatched = [e for e in nv_entries if e["matched_to"] is None]
            self.assertEqual(len(matched), 2, "W1's and W3's NV must attach (main AND manual_review)")
            self.assertEqual(len(unmatched), 1, "W2's Unrelated.php NV has no matching sink")

            hardening_entries = payload["hardening"]
            self.assertEqual(len(hardening_entries), 1)
            self.assertIsNone(hardening_entries[0]["matched_to"])

    def test_unmatched_records_render_in_report(self):
        """Regression: before this package, the CLI parsed wave_format=2
        buckets via parse_findings_file (discarding NV/hardening) and never
        called attach_side_records, so `## Needs validation` / `## Hardening
        notes` never reached REPORT.md even though the renderer supported
        them."""
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            self._mk_waves(tmpdir)
            self._run_cli(tmpdir)
            report = (tmpdir / "REPORT.md").read_text(encoding="utf-8")
            self.assertIn("## Needs validation", report)
            self.assertIn("## Hardening notes", report)

    def test_findings_json_idempotent_across_repeated_runs(self):
        """DoD #6: findings.json must be byte-identical on runs 1, 2 and 3 in
        the same review_root -- unlike REPORT.md, whose `## Diff vs previous
        run` section differs starting on run 2 (state file now exists)."""
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            self._mk_waves(tmpdir)
            fj_path = tmpdir / FINDINGS_JSON_NAME

            self._run_cli(tmpdir)
            bytes_1 = fj_path.read_bytes()
            self._run_cli(tmpdir)
            bytes_2 = fj_path.read_bytes()
            self._run_cli(tmpdir)
            bytes_3 = fj_path.read_bytes()

            self.assertEqual(bytes_1, bytes_2)
            self.assertEqual(bytes_2, bytes_3)

    def test_findings_json_written_in_single_file_mode(self):
        """`--single-file` (legacy monolithic report) must still get the
        public findings.json contract -- the fixed-path write is not gated
        on the split-report code path."""
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            self._mk_waves(tmpdir)
            self._run_cli(tmpdir, extra_args=["--single-file"])
            payload = json.loads((tmpdir / FINDINGS_JSON_NAME).read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
            self.assertTrue(payload["confirmed"])

    def test_findings_json_written_on_zero_input_incomplete_run(self):
        """The INCOMPLETE zero-input branch (all waves failed) must still
        emit a (empty) findings.json -- a consumer must never have to guess
        whether a missing file means "no findings" or "run crashed before
        this stage"."""
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            gaps = tmpdir / "dispatch_gaps.json"
            gaps.write_text(
                json.dumps([{"slice_id": "W1", "reason": "timeout", "returncode": None}]),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable, _CLI_SCRIPT,
                    "--input-glob", str(tmpdir / "*.md"),
                    "--output", str(tmpdir / "REPORT.md"),
                ],
                capture_output=True, text=True, check=True, cwd=str(tmpdir),
            )
            self.assertIn("INCOMPLETE", result.stdout)
            fj_path = tmpdir / FINDINGS_JSON_NAME
            self.assertTrue(fj_path.is_file())
            payload = json.loads(fj_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
            self.assertEqual(payload["confirmed"], [])
            self.assertEqual(payload["needs_validation"], [])
            self.assertEqual(payload["hardening"], [])


if __name__ == "__main__":
    unittest.main()
