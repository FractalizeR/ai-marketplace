"""Tests for the adversarial refute pass module (`bin/dedupe/refute.py`)."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedupe as df  # noqa: E402
from dedupe.refute import (  # noqa: E402
    RefuteRecord,
    apply_refute_records,
    compute_refute_summary,
    parse_refute_md,
    validate_refute_evidence,
    write_refute_invalid_md,
)


class ParseRefuteMdTests(unittest.TestCase):
    """`parse_refute_md` — flat YAML subset parser."""

    def test_parses_two_records(self):
        body = textwrap.dedent(
            """\
            # Adversarial refute records.
            refute_records:
              - finding_key: abc12345:src/A.php:10:csrf_missing
                refute_file: src/A.php
                refute_line: 8
                rationale: voter denyAccessUnlessGranted ROLE_ADMIN before write
                confidence: 9
              - finding_key: def67890:src/B.php:20:weak_random
                refute_file: src/B.php
                refute_line: 22
                rationale: random_bytes(16) wrapping mt_rand fallback
                confidence: 8
            """
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "refute.md"
            path.write_text(body, encoding="utf-8")
            records = parse_refute_md(path)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].finding_key, "abc12345:src/A.php:10:csrf_missing")
        self.assertEqual(records[0].refute_line, 8)
        self.assertEqual(records[0].confidence, 9)
        self.assertEqual(records[1].finding_key, "def67890:src/B.php:20:weak_random")
        self.assertIn("random_bytes", records[1].rationale)

    def test_malformed_yaml_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "refute.md"
            path.write_text("not yaml at all\n###\nrandom garbage", encoding="utf-8")
            records = parse_refute_md(path)
        self.assertEqual(records, [])

    def test_missing_file_returns_empty_list(self):
        records = parse_refute_md(Path("/nonexistent/refute.md"))
        self.assertEqual(records, [])

    def test_quoted_strings_stripped(self):
        body = textwrap.dedent(
            """\
            refute_records:
              - finding_key: "abc12345:src/A.php:10:csrf_missing"
                refute_file: 'src/A.php'
                refute_line: 8
                rationale: "voter check"
                confidence: 9
            """
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "refute.md"
            path.write_text(body, encoding="utf-8")
            records = parse_refute_md(path)
        self.assertEqual(records[0].finding_key, "abc12345:src/A.php:10:csrf_missing")
        self.assertEqual(records[0].refute_file, "src/A.php")
        self.assertEqual(records[0].rationale, "voter check")


class ValidateRefuteEvidenceTests(unittest.TestCase):
    """Auto-validation of refute_file:refute_line via ±5 line window."""

    def _mk_record(self, refute_file: str, refute_line: int) -> RefuteRecord:
        return RefuteRecord(
            finding_key="x:y:1:z",
            refute_file=refute_file,
            refute_line=refute_line,
            rationale="test",
            confidence=9,
        )

    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            ok, reason = validate_refute_evidence(
                self._mk_record("nonexistent/path.php", 1),
                Path(td),
            )
        self.assertFalse(ok)
        self.assertEqual(reason, "file_not_found")

    def test_window_with_only_blanks_and_comments_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "src" / "X.php"
            target.parent.mkdir()
            # 11 lines all blank or comment — window centred on line 6
            # (indices 1..11) contains nothing executable.
            target.write_text(
                "\n".join(
                    [
                        "<?php",
                        "// comment",
                        "// another comment",
                        "",
                        "/* block */",
                        "// target",
                        " * doc continuation",
                        "// trailing",
                        "",
                        "# php attr-style? not really",
                        "// last",
                    ]
                ),
                encoding="utf-8",
            )
            ok, reason = validate_refute_evidence(
                self._mk_record("src/X.php", 6),
                Path(td),
            )
        # Line 1 is `<?php` → has identifier `php` ≥ 3 chars → window includes it,
        # so the heuristic actually returns True (which is what we want for any
        # real PHP file). Cover the negative case by pointing past file end.
        self.assertTrue(ok)
        # Now point past file end — clamps; window ends up only with comments.
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "src" / "Y.php"
            target.parent.mkdir()
            target.write_text(
                "// only comment here\n// second comment\n// third comment",
                encoding="utf-8",
            )
            ok, reason = validate_refute_evidence(
                self._mk_record("src/Y.php", 2),
                Path(td),
            )
        self.assertFalse(ok)
        self.assertEqual(reason, "no_code_token_in_window")

    def test_window_with_real_code_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "src" / "Z.php"
            target.parent.mkdir()
            target.write_text(
                "<?php\n"
                "function makeToken(): string {\n"
                "    return bin2hex(random_bytes(16));\n"
                "}\n",
                encoding="utf-8",
            )
            ok, reason = validate_refute_evidence(
                self._mk_record("src/Z.php", 3),
                Path(td),
            )
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_line_out_of_range_clamps_to_file_bounds(self):
        # refute_line way past file end: window is empty after clamping.
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "src" / "W.php"
            target.parent.mkdir()
            target.write_text("// just one comment line\n", encoding="utf-8")
            ok, reason = validate_refute_evidence(
                self._mk_record("src/W.php", 99999),
                Path(td),
            )
        # Window clamps; only the single comment line survives → no code token.
        self.assertFalse(ok)
        self.assertEqual(reason, "no_code_token_in_window")


class ApplyRefuteRecordsTests(unittest.TestCase):
    """`apply_refute_records` — match by finding_key, validate, tag."""

    def _mk_finding(self, sink_kind: str = "csrf_missing") -> df.Finding:
        return df.Finding(
            title_line="h",
            sink_file="src/Auth/Controller.php",
            sink_line=42,
            sink_kind=sink_kind,
            root_cause_family="authz",
            enclosing_symbol="Controller::callback",
            sink_snippet="if (! $request->session()->get('oauth_state')) { abort(403); }",
            severity="High",
            confidence=9,
        )

    def _mk_project(self, td: Path, refute_target_lines: list[str]) -> Path:
        target = td / "src" / "Auth" / "Guard.php"
        target.parent.mkdir(parents=True)
        target.write_text("\n".join(refute_target_lines), encoding="utf-8")
        return td

    def test_matching_finding_gets_refute_claimed_flag(self):
        f = self._mk_finding()
        merged, _ = df.dedupe([f])
        # Calculate the expected finding_key from the dedup primary.
        primary = merged[0].primary
        finding_key = (
            f"{primary.sink_hash}:{primary.sink_file}:"
            f"{primary.sink_line}:{primary.sink_kind}"
        )
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            self._mk_project(td_path, [
                "<?php",
                "function checkState($req): void {",
                "    if (! hash_equals(session('oauth_state'), $req->input('state'))) abort(403);",
                "}",
            ])
            rec = RefuteRecord(
                finding_key=finding_key,
                refute_file="src/Auth/Guard.php",
                refute_line=3,
                rationale="hash_equals on session oauth_state",
                confidence=9,
            )
            merged_after, invalid = apply_refute_records(merged, [rec], td_path)
        self.assertEqual(invalid, [])
        self.assertIn(df.FLAG_REFUTE_CLAIMED, merged_after[0].flags)
        self.assertEqual(merged_after[0].refute_rationale, "hash_equals on session oauth_state")
        self.assertEqual(merged_after[0].refute_confidence, 9)

    def test_non_matching_finding_key_goes_to_invalid(self):
        f = self._mk_finding()
        merged, _ = df.dedupe([f])
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            self._mk_project(td_path, ["<?php", "function noop() {}"])
            rec = RefuteRecord(
                finding_key="deadbeef:src/Other.php:1:csrf_missing",
                refute_file="src/Auth/Guard.php",
                refute_line=2,
                rationale="x",
                confidence=8,
            )
            merged_after, invalid = apply_refute_records(merged, [rec], td_path)
        self.assertNotIn(df.FLAG_REFUTE_CLAIMED, merged_after[0].flags)
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0].reason, "finding_not_found")

    def test_bad_finding_key_shape_goes_to_invalid(self):
        f = self._mk_finding()
        merged, _ = df.dedupe([f])
        with tempfile.TemporaryDirectory() as td:
            rec = RefuteRecord(
                finding_key="missing-fields-only-one-colon:nope",
                refute_file="src/X.php",
                refute_line=1,
                rationale="x",
                confidence=8,
            )
            _, invalid = apply_refute_records(merged, [rec], Path(td))
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0].reason, "bad_finding_key")

    def test_evidence_invalid_record_goes_to_invalid(self):
        """Matching finding + validate fails → invalid (with the validator's reason)."""
        f = self._mk_finding()
        merged, _ = df.dedupe([f])
        primary = merged[0].primary
        finding_key = (
            f"{primary.sink_hash}:{primary.sink_file}:"
            f"{primary.sink_line}:{primary.sink_kind}"
        )
        with tempfile.TemporaryDirectory() as td:
            rec = RefuteRecord(
                finding_key=finding_key,
                refute_file="nonexistent.php",
                refute_line=1,
                rationale="x",
                confidence=9,
            )
            merged_after, invalid = apply_refute_records(merged, [rec], Path(td))
        self.assertNotIn(df.FLAG_REFUTE_CLAIMED, merged_after[0].flags)
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0].reason, "file_not_found")


class ComputeRefuteSummaryTests(unittest.TestCase):
    def test_counts_match(self):
        # Build two merged + one manual; tag one merged with REFUTE_CLAIMED.
        f1 = df.Finding(
            title_line="h", sink_file="src/A.php", sink_line=1,
            sink_kind="csrf_missing", root_cause_family="authz",
            enclosing_symbol="A::m", sink_snippet="x", severity="High", confidence=9,
        )
        f2 = df.Finding(
            title_line="h", sink_file="src/B.php", sink_line=1,
            sink_kind="weak_random", root_cause_family="crypto",
            enclosing_symbol="B::m", sink_snippet="y", severity="High", confidence=9,
        )
        merged, _ = df.dedupe([f1, f2])
        merged[0].flags.append(df.FLAG_REFUTE_CLAIMED)
        summary = compute_refute_summary(merged, [], [])
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(summary["refute_claimed"], 1)
        self.assertEqual(summary["refute_invalid"], 0)
        self.assertEqual(summary["manual_review"], 0)


class WriteRefuteInvalidMdTests(unittest.TestCase):
    def test_empty_invalid_writes_placeholder(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "REPORT" / "refute_invalid.md"
            write_refute_invalid_md([], path)
            text = path.read_text(encoding="utf-8")
        self.assertIn("Refute records — auto-validation failed", text)
        self.assertIn("No invalid refute records", text)

    def test_records_rendered(self):
        from dedupe.refute import RefuteInvalid
        invalid = [
            RefuteInvalid(
                finding_key="abc:src/X.php:1:csrf_missing",
                refute_file="src/Other.php",
                refute_line=5,
                rationale="rationale text",
                reason="file_not_found",
            )
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "refute_invalid.md"
            write_refute_invalid_md(invalid, path)
            text = path.read_text(encoding="utf-8")
        self.assertIn("abc:src/X.php:1:csrf_missing", text)
        self.assertIn("file_not_found", text)
        self.assertIn("rationale text", text)


class CliRefuteIntegrationTests(unittest.TestCase):
    """End-to-end: run dedupe_findings.py with --refute and verify output."""

    def test_cli_with_refute_flag_emits_tag_and_invalid_md(self):
        import subprocess
        cli = str(Path(__file__).resolve().parent.parent / "dedupe_findings.py")

        # Build wave file with one finding.
        from tests.test_dedupe_findings import _mk_finding_md  # type: ignore
        snippet = "$x = 1;\nreturn $x;"
        wave_md = _mk_finding_md(
            n=1,
            sink_file="src/Auth/Controller.php",
            sink_line=42,
            sink_kind="csrf_missing",
            root_cause_family="authz",
            enclosing_symbol="Controller::callback",
            sink_snippet=snippet,
            severity="High",
            confidence=9,
        )

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            review_root = td_path / "review"
            waves = review_root / "waves"
            waves.mkdir(parents=True)
            (waves / "W1.md").write_text(wave_md, encoding="utf-8")

            project_root = td_path / "project"
            (project_root / "src" / "Auth").mkdir(parents=True)
            (project_root / "src" / "Auth" / "Guard.php").write_text(
                "<?php\nfunction checkCsrf() { return hash_equals($a, $b); }\n",
                encoding="utf-8",
            )

            # Compute finding_key by running parser+dedupe on the same input
            # (cheap; no need to subprocess just for this).
            findings = df.parse_findings_file(waves / "W1.md")
            merged, _ = df.dedupe(findings)
            primary = merged[0].primary
            finding_key = (
                f"{primary.sink_hash}:{primary.sink_file}:"
                f"{primary.sink_line}:{primary.sink_kind}"
            )

            # Refute: one valid record + one with bad finding_key.
            refute_md = textwrap.dedent(f"""\
                refute_records:
                  - finding_key: {finding_key}
                    refute_file: src/Auth/Guard.php
                    refute_line: 2
                    rationale: hash_equals csrf check present
                    confidence: 9
                  - finding_key: deadbeef:src/Nonexistent.php:1:weak_random
                    refute_file: src/Auth/Guard.php
                    refute_line: 2
                    rationale: stale claim
                    confidence: 5
                """)
            refute_path = review_root / "refute.md"
            refute_path.write_text(refute_md, encoding="utf-8")

            output = review_root / "REPORT.md"
            details = review_root / "REPORT"
            result = subprocess.run(
                [
                    "python3", cli,
                    "--input-glob", str(waves / "*.md"),
                    "--output", str(output),
                    "--details-dir", str(details),
                    "--refute", str(refute_path),
                    "--project-root", str(project_root),
                    "--no-state",
                ],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.exists())
            self.assertTrue((details / "refute_invalid.md").exists())
            report_text = output.read_text(encoding="utf-8")
            self.assertIn("REFUTE_CLAIMED", report_text,
                          "REPORT.md must show [REFUTE_CLAIMED] tag")
            self.assertIn("Adversarial refute pass", report_text,
                          "Executive summary must include refute counters")
            invalid_text = (details / "refute_invalid.md").read_text(encoding="utf-8")
            self.assertIn("deadbeef:src/Nonexistent.php:1:weak_random", invalid_text)
            self.assertIn("finding_not_found", invalid_text)


if __name__ == "__main__":
    unittest.main()
