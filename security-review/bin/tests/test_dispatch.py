"""Tests for shared/dispatch.py (Phase 2A).

Subprocess is the single injected seam — every test passes a FAKE runner that
simulates exit/write behaviour; no real `opencode`/`codex` binary is invoked.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.contracts import (  # noqa: E402
    DispatchConfigError,
    DispatchGapError,
    Roots,
    RunResult,
)
from shared import dispatch as dp  # noqa: E402
from shared.model_resolver import TierMap  # noqa: E402


def make_roots(d: Path) -> Roots:
    return Roots(
        project_root=d / "proj",
        review_root=d / "review",
        core_root=d / "core",
        capture_dir=None,
    )


def wave_cb(slice, model_id, roots, cap):
    # slice_id at argv[1], model_id at argv[2], capture at argv[3].
    return ["worker", slice["slice_id"], model_id, str(cap or "")]


def make_slice(slice_id, model="opus"):
    return {
        "slice_id": slice_id,
        "wave_id": slice_id.split("_")[0],
        "themes": ["t"],
        "checklists": ["/abs/c.md"],
        "relevant_section_paths": [],
        "entry_points_in_scope": [],
        "target_files": ["a.php"],
        "model": model,
        "mode": "project",
    }


TM = TierMap(high="HIGH-ID", fast="FAST-ID", provenance="proposed")


def writing_runner(roots, *, success_ids, returncode=0, timed_out=False,
                   model_record=None, timeout_record=None):
    """Fake runner: writes the wave file for slice_ids in success_ids."""

    def runner(argv, timeout):
        if timeout_record is not None:
            timeout_record.append(timeout)
        sid = argv[1]
        if model_record is not None:
            model_record[sid] = argv[2]
        if sid in success_ids:
            wp = dp.wave_output_path(roots, sid)
            wp.parent.mkdir(parents=True, exist_ok=True)
            wp.write_text(f"# findings {sid}\n", encoding="utf-8")
        return RunResult(
            returncode=None if timed_out else returncode,
            stdout=f"stdout-{sid}",
            stderr="",
            timed_out=timed_out,
        )

    return runner


class WaveDispatchTests(unittest.TestCase):
    def test_all_present_no_gaps(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1"), make_slice("W3_PART1", model="sonnet")]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1", "W3_PART1"}),
            )
            self.assertTrue(report.all_present)
            self.assertEqual(report.gaps, [])

    def test_label_to_tier_to_id(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1", model="opus"),
                    make_slice("W3_PART1", model="sonnet")]
            rec: dict = {}
            dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1", "W3_PART1"},
                                      model_record=rec),
            )
            self.assertEqual(rec["W1_PART1"], "HIGH-ID")   # opus -> high
            self.assertEqual(rec["W3_PART1"], "FAST-ID")   # sonnet -> fast

    def test_unknown_label_raises(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1", model="gpt5")]
            with self.assertRaises(DispatchConfigError):
                dp.dispatch_waves(
                    plan, TM, roots=roots, command_builder=wave_cb,
                    runner=writing_runner(roots, success_ids=set()),
                )

    def test_strict_raises_on_gap(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1"), make_slice("W2_PART1")]
            with self.assertRaises(DispatchGapError) as ctx:
                dp.dispatch_waves(
                    plan, TM, roots=roots, command_builder=wave_cb,
                    runner=writing_runner(roots, success_ids={"W1_PART1"}),
                )
            self.assertEqual([g.slice_id for g in ctx.exception.gaps], ["W2_PART1"])

    def test_allow_gaps_writes_json(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1"), make_slice("W2_PART1")]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1"},
                                      returncode=1),
                strict=False,
            )
            self.assertFalse(report.all_present)
            gaps_file = roots.review_root / "dispatch_gaps.json"
            self.assertTrue(gaps_file.is_file())
            data = json.loads(gaps_file.read_text())
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["slice_id"], "W2_PART1")
            self.assertEqual(data[0]["reason"], "crash")
            self.assertEqual(set(data[0].keys()), {"slice_id", "reason", "returncode"})

    def test_gaps_json_plan_index_order(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("A"), make_slice("B"), make_slice("C")]
            dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids=set()),
                strict=False,
            )
            data = json.loads((roots.review_root / "dispatch_gaps.json").read_text())
            self.assertEqual([g["slice_id"] for g in data], ["A", "B", "C"])

    def test_three_reasons_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("CRASH"), make_slice("TIMEOUT"), make_slice("MISSING")]

            def runner(argv, timeout):
                sid = argv[1]
                if sid == "CRASH":
                    return RunResult(returncode=2, stdout="", stderr="", timed_out=False)
                if sid == "TIMEOUT":
                    return RunResult(returncode=None, stdout="", stderr="", timed_out=True)
                return RunResult(returncode=0, stdout="", stderr="", timed_out=False)

            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb, runner=runner,
                strict=False,
            )
            reasons = {r.slice_id: r.gap_reason for r in report.results}
            self.assertEqual(reasons["CRASH"], "crash")
            self.assertEqual(reasons["TIMEOUT"], "timeout")
            self.assertEqual(reasons["MISSING"], "missing_write")

    def test_fresh_present_wins_over_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1")]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1"}, returncode=1),
                strict=False,
            )
            self.assertTrue(report.all_present)
            self.assertIsNone(report.results[0].gap_reason)

    def test_fresh_present_wins_over_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1")]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1"}, timed_out=True),
                strict=False,
            )
            self.assertTrue(report.all_present)

    def test_stale_prior_run_file_plus_crash_is_gap(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            # Pre-create a stale wave file from a "previous run".
            wp = dp.wave_output_path(roots, "W1_PART1")
            wp.parent.mkdir(parents=True, exist_ok=True)
            wp.write_text("# stale findings\n", encoding="utf-8")
            plan = [make_slice("W1_PART1")]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids=set(), returncode=1),
                strict=False,
            )
            self.assertFalse(report.all_present)
            self.assertEqual(report.results[0].gap_reason, "crash")
            self.assertFalse(wp.exists())  # stale file was deleted, not resurrected

    def test_recover_capture_writes_wave_file_and_clears_gap(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1")]

            def recover(slice_id, roots_):
                return f"# recovered {slice_id}\n"

            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids=set(), returncode=1),
                strict=False, recover_capture=recover,
            )
            self.assertTrue(report.all_present)
            wp = dp.wave_output_path(roots, "W1_PART1")
            self.assertTrue(wp.is_file())  # dedupe-visible
            self.assertEqual(wp.read_text(), "# recovered W1_PART1\n")

    def test_recover_capture_none_keeps_gap(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1")]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids=set(), returncode=1),
                strict=False, recover_capture=lambda s, r: None,
            )
            self.assertFalse(report.all_present)

    def test_per_slice_config_written(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1")]
            dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1"}),
            )
            cfg = roots.review_root / "waves" / "W1_PART1.slice.json"
            self.assertTrue(cfg.is_file())
            data = json.loads(cfg.read_text())
            self.assertEqual(data["slice_id"], "W1_PART1")
            self.assertIn("checklists", data)
            self.assertIn("target_files", data)

    def test_timeout_passed_to_runner(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1")]
            rec: list = []
            dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1"},
                                      timeout_record=rec),
                timeout=42.0,
            )
            self.assertEqual(rec, [42.0])

    def test_max_parallel_capped_at_6(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice(f"S{i}") for i in range(40)]
            lock = threading.Lock()
            state = {"inflight": 0, "max": 0}

            def runner(argv, timeout):
                with lock:
                    state["inflight"] += 1
                    state["max"] = max(state["max"], state["inflight"])
                time.sleep(0.01)
                with lock:
                    state["inflight"] -= 1
                sid = argv[1]
                wp = dp.wave_output_path(roots, sid)
                wp.write_text("x", encoding="utf-8")
                return RunResult(returncode=0, stdout="", stderr="", timed_out=False)

            dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb, runner=runner,
                max_parallel=6,
            )
            self.assertLessEqual(state["max"], 6)
            self.assertGreater(state["max"], 1)  # actually parallel

    def test_results_sorted_by_plan_index(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice(f"S{i}") for i in range(10)]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={f"S{i}" for i in range(10)}),
            )
            self.assertEqual([r.plan_index for r in report.results], list(range(10)))


class RoleDispatchTests(unittest.TestCase):
    def test_recon_artifact_present(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            roots.review_root.mkdir(parents=True, exist_ok=True)

            def cb(role, roots_):
                (roots_.review_root / "CONTEXT.md").write_text("ctx", encoding="utf-8")
                return ["recon-worker", role]

            def runner(argv, timeout):
                return RunResult(returncode=0, stdout="", stderr="", timed_out=False)

            res = dp.dispatch_role("recon", command_builder=cb, runner=runner, roots=roots)
            self.assertTrue(res.output_present)
            self.assertEqual(res.role, "recon")

    def test_refute_artifact_absent_is_gap(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            roots.review_root.mkdir(parents=True, exist_ok=True)

            def cb(role, roots_):
                return ["refute-worker", role]

            def runner(argv, timeout):
                return RunResult(returncode=1, stdout="", stderr="", timed_out=False)

            res = dp.dispatch_role("refute", command_builder=cb, runner=runner, roots=roots)
            self.assertFalse(res.output_present)

    def test_role_single_process(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            roots.review_root.mkdir(parents=True, exist_ok=True)
            calls = {"n": 0}

            def cb(role, roots_):
                (roots_.review_root / "refute.md").write_text("r", encoding="utf-8")
                return ["w", role]

            def runner(argv, timeout):
                calls["n"] += 1
                return RunResult(returncode=0, stdout="", stderr="", timed_out=False)

            dp.dispatch_role("refute", command_builder=cb, runner=runner, roots=roots)
            self.assertEqual(calls["n"], 1)

    def test_role_recover_capture_materializes(self):
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            roots.review_root.mkdir(parents=True, exist_ok=True)

            def cb(role, roots_):
                return ["w", role]

            def runner(argv, timeout):
                return RunResult(returncode=1, stdout="", stderr="", timed_out=False)

            res = dp.dispatch_role(
                "recon", command_builder=cb, runner=runner, roots=roots,
                recover_capture=lambda role, r: "recovered-ctx",
            )
            self.assertTrue(res.output_present)
            self.assertEqual((roots.review_root / "CONTEXT.md").read_text(), "recovered-ctx")


class CliTests(unittest.TestCase):
    def setUp(self):
        import io
        self._old_stdout = sys.stdout
        sys.stdout = io.StringIO()

    def tearDown(self):
        sys.stdout = self._old_stdout

    def _write_inputs(self, d: Path):
        plan = [make_slice("W1_PART1"), make_slice("W2_PART1")]
        (d / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        (d / "model_map.json").write_text(
            json.dumps(TM.as_dict()), encoding="utf-8")
        return d / "plan.json", d / "model_map.json"

    def test_cli_all_present_exit0(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            plan_p, mm_p = self._write_inputs(dd)
            review = dd / "review"

            def runner(argv, timeout):
                # template -> shlex argv; slice_id is the 2nd token here.
                sid = argv[1]
                wp = review / "waves" / f"{sid}.md"
                wp.parent.mkdir(parents=True, exist_ok=True)
                wp.write_text("f", encoding="utf-8")
                return RunResult(returncode=0, stdout="", stderr="", timed_out=False)

            rc = dp.main([
                "--plan", str(plan_p), "--model-map", str(mm_p),
                "--project-root", str(dd / "proj"),
                "--review-root", str(review),
                "--core-root", str(dd / "core"),
                "--worker-cmd-template", "worker {slice_id} {model}",
            ], runner=runner)
            self.assertEqual(rc, 0)

    def test_cli_gaps_exit1_writes_json(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            plan_p, mm_p = self._write_inputs(dd)
            review = dd / "review"

            def runner(argv, timeout):
                return RunResult(returncode=1, stdout="", stderr="", timed_out=False)

            rc = dp.main([
                "--plan", str(plan_p), "--model-map", str(mm_p),
                "--project-root", str(dd / "proj"),
                "--review-root", str(review),
                "--core-root", str(dd / "core"),
                "--worker-cmd-template", "worker {slice_id} {model}",
                "--allow-gaps",
            ], runner=runner)
            self.assertEqual(rc, 1)
            self.assertTrue((review / "dispatch_gaps.json").is_file())

    def test_cli_strict_gap_exit2(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            plan_p, mm_p = self._write_inputs(dd)
            review = dd / "review"

            def runner(argv, timeout):
                return RunResult(returncode=1, stdout="", stderr="", timed_out=False)

            rc = dp.main([
                "--plan", str(plan_p), "--model-map", str(mm_p),
                "--project-root", str(dd / "proj"),
                "--review-root", str(review),
                "--core-root", str(dd / "core"),
                "--worker-cmd-template", "worker {slice_id} {model}",
            ], runner=runner)
            self.assertEqual(rc, 2)

    def test_cli_role_refute_single_process(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            review = dd / "review"
            review.mkdir(parents=True, exist_ok=True)
            calls = {"n": 0}

            def runner(argv, timeout):
                calls["n"] += 1
                (review / "refute.md").write_text("r", encoding="utf-8")
                return RunResult(returncode=0, stdout="", stderr="", timed_out=False)

            rc = dp.main([
                "--project-root", str(dd / "proj"),
                "--review-root", str(review),
                "--core-root", str(dd / "core"),
                "--role", "refute",
                "--role-cmd-template", "refute-worker {role}",
            ], runner=runner)
            self.assertEqual(rc, 0)
            self.assertEqual(calls["n"], 1)


class RegressionFixTests(unittest.TestCase):
    """Post-code-review hardening (H1 spawn-failure, M1 stale gaps file)."""

    def test_raising_runner_becomes_crash_gap_not_abort(self):
        # A runner that RAISES for one slice must not abort the whole batch; that
        # slice becomes a crash gap and the others still succeed (review H1).
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            plan = [make_slice("W1_PART1"), make_slice("W2_PART1")]

            def runner(argv, timeout):
                sid = argv[1]
                if sid == "W2_PART1":
                    raise RuntimeError("simulated non-conforming runner blow-up")
                wp = dp.wave_output_path(roots, sid)
                wp.parent.mkdir(parents=True, exist_ok=True)
                wp.write_text("# ok\n", encoding="utf-8")
                return RunResult(returncode=0, stdout="", stderr="", timed_out=False)

            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb, runner=runner,
                strict=False,
            )
            self.assertEqual([g.slice_id for g in report.gaps], ["W2_PART1"])
            self.assertEqual(report.gaps[0].gap_reason, "crash")

    def test_default_runner_spawn_failure_returns_crash(self):
        # Missing binary → non-zero RunResult, NOT a raised OSError (review H1).
        result = dp.default_runner(["definitely-missing-bin-xyz-2a"], None)
        self.assertFalse(result.timed_out)
        self.assertNotIn(result.returncode, (0, None))

    def test_default_runner_feeds_devnull_stdin(self):
        # A fanned-out worker is non-interactive; `codex exec` reads extra prompt
        # input from stdin, so an inherited non-EOF stdin blocks it forever. The
        # runner MUST pass stdin=DEVNULL (verified live, 3C). Harness-neutral.
        import subprocess as _sp
        from unittest import mock

        captured = {}

        def fake_run(argv, **kwargs):
            captured.update(kwargs)

            class _P:
                returncode = 0
                stdout = ""
                stderr = ""

            return _P()

        with mock.patch.object(dp.subprocess, "run", fake_run):
            dp.default_runner(["echo", "hi"], 5)
        self.assertEqual(captured.get("stdin"), _sp.DEVNULL)

    def test_clean_run_removes_stale_gaps_file(self):
        # A stale dispatch_gaps.json from a prior allow-gaps run must be cleared by
        # a subsequent clean run so dedupe can't mark a healthy report INCOMPLETE
        # (review M1).
        with tempfile.TemporaryDirectory() as d:
            roots = make_roots(Path(d))
            roots.review_root.mkdir(parents=True, exist_ok=True)
            stale = roots.review_root / "dispatch_gaps.json"
            stale.write_text('[{"slice_id": "W9_PART1", "reason": "crash"}]\n',
                             encoding="utf-8")
            plan = [make_slice("W1_PART1")]
            report = dp.dispatch_waves(
                plan, TM, roots=roots, command_builder=wave_cb,
                runner=writing_runner(roots, success_ids={"W1_PART1"}),
                strict=False,
            )
            self.assertTrue(report.all_present)
            self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
