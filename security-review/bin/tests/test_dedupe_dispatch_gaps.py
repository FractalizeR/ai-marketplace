"""Tests for the dedupe `--dispatch-gaps` delta (Phase 2A S5)."""

from __future__ import annotations

import contextlib
import io
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


def _gaps_payload(**overrides) -> dict:
    payload = {
        "schema_version": 1,
        "items": [
            {
                "kind": "coverage", "section_path": "attack_surface.http_controllers",
                "label": "HTTP controllers", "status": "partial", "reason": "declared 2 of 6",
                "declared": 2, "found": 6, "missing_pct": 66.7,
                "files": ["src/A.php", "src/B.php", "src/C.php", "src/D.php"],
            },
            {
                "kind": "extractor_failed", "section_path": "data_access.models",
                "label": "Models", "status": "partial", "reason": "extractor_failed: timeout",
                "files": ["src/Model/M1.php"],
            },
            {
                "kind": "uninterpreted", "section_path": "auth_layer",
                "label": "security config", "status": "partial",
                "reason": "config_uninterpreted: security: no_console",
                "files": ["config/packages/security.yaml"],
            },
        ],
    }
    payload.update(overrides)
    return payload


def _plan(*slices: tuple[str, list[str]]) -> list[dict]:
    return [{"slice_id": sid, "target_files": files} for sid, files in slices]


class ReadReconGapsUnitTests(unittest.TestCase):
    def _root(self, d: str, payload) -> Path:
        root = Path(d)
        (root / "recon_gaps.json").write_text(
            payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8"
        )
        return root

    def test_missing_file_gives_no_lines(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(dff.read_recon_gaps(Path(d), []), [])

    def test_corrupt_or_non_object_gives_no_lines(self):
        for raw in ("{not json", "[]", '"x"'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as d:
                self.assertEqual(dff.read_recon_gaps(self._root(d, raw), []), [])

    def test_empty_items_gives_no_lines(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(dff.read_recon_gaps(self._root(d, _gaps_payload(items=[])), []), [])

    def test_unknown_schema_version_warns_and_gives_no_lines(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._root(d, _gaps_payload(schema_version=2))
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(dff.read_recon_gaps(root, []), [])
        self.assertIn("schema_version 2", err.getvalue())

    def test_three_kinds_split_reviewed_and_not_reviewed_by_plan(self):
        plan = _plan(
            ("W1_PART1", ["src/A.php", "src/B.php"]),
            ("WGAP_PART1", ["src/C.php", "src/Model/M1.php"]),
        )
        with tempfile.TemporaryDirectory() as d:
            lines = dff.read_recon_gaps(self._root(d, _gaps_payload()), plan)
        self.assertEqual(len(lines), 3)
        # items are ordered by (kind, section_path, label)
        cov, failed, unint = lines
        self.assertIn("HTTP controllers", cov)
        self.assertIn("Declared 2, found 6 (66.7% missing)", cov)
        self.assertIn("3 file(s) reviewed, 1 NOT reviewed (`src/D.php`)", cov)
        self.assertIn("extractor_failed: timeout", failed)
        self.assertIn("1 file(s) reviewed, 0 NOT reviewed.", failed)
        self.assertIn("security config", unint)
        self.assertIn("0 file(s) reviewed, 1 NOT reviewed (`config/packages/security.yaml`)", unint)

    def test_not_reviewed_preview_is_capped(self):
        files = [f"src/F{i}.php" for i in range(8)]
        payload = _gaps_payload(items=[{
            "kind": "coverage", "section_path": "s", "label": "L", "status": "partial",
            "declared": 0, "found": 8, "missing_pct": 100, "files": files,
        }])
        with tempfile.TemporaryDirectory() as d:
            (line,) = dff.read_recon_gaps(self._root(d, payload), _plan(("W1_PART1", [])))
        self.assertIn("0 file(s) reviewed, 8 NOT reviewed", line)
        self.assertIn("+3 more", line)

    def test_without_plan_reports_status_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            lines = dff.read_recon_gaps(self._root(d, _gaps_payload()), None)
        self.assertEqual(len(lines), 3)
        for line in lines:
            self.assertIn("review status unknown (no plan given)", line)
            self.assertNotIn("NOT reviewed", line)
        self.assertIn("4 file(s) involved", lines[0])

    def test_output_is_deterministic_for_shuffled_items(self):
        payload = _gaps_payload()
        shuffled = _gaps_payload(items=list(reversed(payload["items"])))
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            a = dff.read_recon_gaps(self._root(d1, payload), None)
            b = dff.read_recon_gaps(self._root(d2, shuffled), None)
        self.assertEqual(a, b)


class ReconGapsInReportTests(unittest.TestCase):
    def _run_report(self, review: Path, *extra: str) -> str:
        waves = review / "waves"
        waves.mkdir(exist_ok=True)
        (waves / "W1_PART1.md").write_text(_mk_finding_md(), encoding="utf-8")
        out = review / "REPORT.md"
        rc = dff.main(["--input-glob", str(waves / "*.md"), "--output", str(out), "--no-state", *extra])
        self.assertEqual(rc, 0)
        return out.read_text()

    def test_recon_gaps_and_plan_render_reviewed_and_not_reviewed(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            (review / "recon_gaps.json").write_text(json.dumps(_gaps_payload()), encoding="utf-8")
            plan = review / "waves_plan.json"
            plan.write_text(json.dumps(_plan(("WGAP_PART1", ["src/A.php", "src/B.php"]))), encoding="utf-8")
            text = self._run_report(review, "--waves-plan", str(plan))
        self.assertIn("## Coverage Gaps", text)
        self.assertIn("2 file(s) reviewed, 2 NOT reviewed", text)
        self.assertNotIn("INCOMPLETE AUDIT", text)

    def test_without_plan_status_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            (review / "recon_gaps.json").write_text(json.dumps(_gaps_payload()), encoding="utf-8")
            text = self._run_report(review)
        self.assertIn("review status unknown (no plan given)", text)

    def test_no_file_means_no_section(self):
        with tempfile.TemporaryDirectory() as d:
            text = self._run_report(Path(d))
        self.assertNotIn("## Coverage Gaps", text)

    def test_unknown_schema_version_means_no_section(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            (review / "recon_gaps.json").write_text(json.dumps(_gaps_payload(schema_version=9)), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                text = self._run_report(review)
        self.assertNotIn("## Coverage Gaps", text)

    def test_zero_input_pass_carries_recon_gaps_next_to_dispatch_gaps(self):
        with tempfile.TemporaryDirectory() as d:
            review = Path(d)
            (review / "waves").mkdir()
            (review / "recon_gaps.json").write_text(json.dumps(_gaps_payload()), encoding="utf-8")
            _write_gaps(review / "dispatch_gaps.json", [
                {"slice_id": "WGAP_PART1", "reason": "crash", "returncode": 1},
            ])
            out = review / "REPORT.md"
            rc = dff.main(["--input-glob", str(review / "waves" / "*.md"), "--output", str(out), "--no-state"])
            text = out.read_text()
        self.assertEqual(rc, 0)
        self.assertIn("INCOMPLETE AUDIT", text)
        self.assertIn("WGAP_PART1", text)
        self.assertIn("HTTP controllers", text)


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
