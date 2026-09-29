"""Remembered-verdict state (`.findings_state.json`) and `--verdicts-in`."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
sys.path.insert(0, str(BIN_DIR))

from dedupe.state import compute_evidence_hash  # noqa: E402
from dedupe.state import (  # noqa: E402
    Resolution,
    STATE_FILENAME,
    STATE_SCHEMA_VERSION,
    VerdictsInError,
    active_rejections,
    load_resolutions,
    load_verdicts_in,
    save_state,
)


class StateFileTests(unittest.TestCase):
    def test_save_writes_only_schema_version_and_resolutions(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            target = save_state(review_root, resolutions={
                "hash1": Resolution(verdict="rejected", source="audit-triage"),
            })
            self.assertEqual(target.name, STATE_FILENAME)
            payload = json.loads(target.read_text())
        self.assertEqual(set(payload), {"schema_version", "resolutions"})
        self.assertEqual(payload["schema_version"], STATE_SCHEMA_VERSION)
        self.assertEqual(STATE_SCHEMA_VERSION, 2)

    def test_missing_file_gives_empty_journal(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(load_resolutions(Path(td)), {})

    def test_corrupt_json_gives_empty_journal(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text("{not json")
            self.assertEqual(load_resolutions(review_root), {})

    def test_schema2_file_with_legacy_keys_is_read_and_extras_dropped_on_save(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text(json.dumps({
                "schema_version": 2,
                "findings": [{"sink_hash": "aaaa1111"}],
                "baseline": None,
                "run_id": "abc",
                "resolutions": {
                    "hash1": {"verdict": "rejected", "source": "audit-triage", "run_seq": 3},
                },
            }))
            self.assertEqual(set(load_resolutions(review_root)), {"hash1"})
            save_state(review_root, resolutions={
                "hash2": Resolution(verdict="rejected", source="audit-triage"),
            })
            payload = json.loads((review_root / STATE_FILENAME).read_text())
        self.assertEqual(set(payload), {"schema_version", "resolutions"})
        self.assertEqual(set(payload["resolutions"]), {"hash1", "hash2"})

    def test_schema1_file_gives_empty_journal_and_warns(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text(json.dumps({
                "schema_version": 1,
                "findings": [{"sink_hash": "abcd1234"}],
            }), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(load_resolutions(review_root), {})
        self.assertIn("schema_version 1", err.getvalue())

    def test_unknown_future_schema_version_gives_empty_journal_and_warns(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text(
                json.dumps({"schema_version": 99, "resolutions": {}})
            )
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(load_resolutions(review_root), {})
        self.assertIn("schema_version 99", err.getvalue())


class ResolutionsAccumulateTests(unittest.TestCase):
    """`save_state`'s resolutions merge is read-modify-write, not a full
    overwrite — the journal accumulates across runs."""

    def test_resolutions_persist_across_separate_save_calls(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state(review_root, resolutions={
                "hash1": Resolution(verdict="rejected", source="audit-triage"),
            })
            save_state(review_root, resolutions={
                "hash2": Resolution(verdict="rejected", source="audit-triage"),
            })
            loaded = load_resolutions(review_root)
        self.assertEqual(set(loaded), {"hash1", "hash2"})

    def test_same_hash_overwritten_by_latest_call(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state(review_root, resolutions={
                "hash1": Resolution(verdict="rejected", source="audit-triage"),
            })
            save_state(review_root, resolutions={
                "hash1": Resolution(verdict="reaffirmed", source="triage"),
            })
            loaded = load_resolutions(review_root)
        self.assertEqual(loaded["hash1"].verdict, "reaffirmed")
        self.assertEqual(loaded["hash1"].source, "triage")

    def test_run_seq_advances_only_on_calls_that_supply_resolutions(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state(review_root, resolutions={
                "hash1": Resolution(verdict="rejected", source="audit-triage"),
            })
            first_seq = load_resolutions(review_root)["hash1"].run_seq
            # A plain run with no fresh resolutions must not touch hash1's run_seq.
            save_state(review_root, resolutions={})
            self.assertEqual(load_resolutions(review_root)["hash1"].run_seq, first_seq)
            # A run that DOES supply a (possibly unrelated) resolution bumps
            # the counter for what it touches.
            save_state(review_root, resolutions={
                "hash2": Resolution(verdict="rejected", source="audit-triage"),
            })
            reloaded = load_resolutions(review_root)
            self.assertEqual(reloaded["hash1"].run_seq, first_seq)
            self.assertGreater(reloaded["hash2"].run_seq, first_seq)

    def test_run_seq_never_appears_in_findings_serialization(self):
        """run_seq is an audit trail INSIDE state.json only — Resolution's
        own to_dict is the boundary that matters here; findings.json/REPORT.md
        never construct a Resolution from state at all (see
        renderer._render_resolution_note, which never reads run_seq)."""
        res = Resolution(verdict="rejected", source="audit-triage", run_seq=7)
        self.assertIn("run_seq", res.to_dict())  # present in state.json (by design)
        # But the rendered note must not mention it — covered in test_renderer.py.


class ActiveRejectionsTests(unittest.TestCase):
    """`active_rejections` is the freshness gate: a rejected mark with code
    evidence only stays active while that evidence is unchanged."""

    def _mk_project(self, td: Path, guard_lines: list[str]) -> Path:
        project_root = td / "project"
        guard = project_root / "src" / "Guard.php"
        guard.parent.mkdir(parents=True)
        guard.write_text("\n".join(guard_lines), encoding="utf-8")
        return project_root

    def test_rejected_with_unchanged_evidence_stays_active(self):
        with tempfile.TemporaryDirectory() as td:
            project_root = self._mk_project(Path(td), [
                "<?php", "function check() {", "    deny_unless(hasRole('admin'));", "}",
            ])
            evidence_hash = compute_evidence_hash("src/Guard.php", 3, project_root)
            resolutions = {"h1": Resolution(
                verdict="rejected", evidence_hash=evidence_hash,
                refute_file="src/Guard.php", refute_line=3, source="audit-triage",
            )}
            active = active_rejections(resolutions, project_root)
        self.assertIn("h1", active)

    def test_key_scenario_protection_removed_drops_the_mark(self):
        """The scenario DoD #5 names by name: the protection at
        refute_file:refute_line is removed (sink untouched) -> the mark must
        be dropped on the NEXT run, without re-importing the verdict."""
        with tempfile.TemporaryDirectory() as td:
            project_root = self._mk_project(Path(td), [
                "<?php", "function check() {", "    deny_unless(hasRole('admin'));", "}",
            ])
            evidence_hash = compute_evidence_hash("src/Guard.php", 3, project_root)
            resolutions = {"h1": Resolution(
                verdict="rejected", evidence_hash=evidence_hash,
                refute_file="src/Guard.php", refute_line=3, source="audit-triage",
            )}
            # Protection removed; only line 3 changes, nothing else moves.
            (project_root / "src" / "Guard.php").write_text(
                "\n".join(["<?php", "function check() {", "    // no check anymore", "}"]),
                encoding="utf-8",
            )
            active = active_rejections(resolutions, project_root)
        self.assertNotIn("h1", active)

    def test_unrelated_edit_elsewhere_keeps_the_mark(self):
        """Control for the scenario above: touching code OUTSIDE the cited
        line must not invalidate the mark."""
        with tempfile.TemporaryDirectory() as td:
            project_root = self._mk_project(Path(td), [
                "<?php", "function check() {", "    deny_unless(hasRole('admin'));", "}",
                "function unrelated() { return 1; }",
            ])
            evidence_hash = compute_evidence_hash("src/Guard.php", 3, project_root)
            resolutions = {"h1": Resolution(
                verdict="rejected", evidence_hash=evidence_hash,
                refute_file="src/Guard.php", refute_line=3, source="audit-triage",
            )}
            (project_root / "src" / "Guard.php").write_text(
                "\n".join([
                    "<?php", "function check() {", "    deny_unless(hasRole('admin'));", "}",
                    "function unrelated() { return 2; }",  # changed, but not line 3
                ]),
                encoding="utf-8",
            )
            active = active_rejections(resolutions, project_root)
        self.assertIn("h1", active)

    def test_regression_guard_path_based_hash_would_miss_the_removal(self):
        """Empirical demonstration that `evidence_hash` MUST be content-based:
        a hash of the (refute_file, refute_line) location tuple never
        changes when the code at that location changes, so it would fail to
        catch exactly the regression `active_rejections` exists to catch."""
        with tempfile.TemporaryDirectory() as td:
            project_root = self._mk_project(Path(td), [
                "<?php", "function check() {", "    deny_unless(hasRole('admin'));", "}",
            ])
            path_based_hash = hashlib.sha256(b"src/Guard.php:3").hexdigest()[:8]
            resolutions = {"h1": Resolution(
                verdict="rejected", evidence_hash=path_based_hash,
                refute_file="src/Guard.php", refute_line=3, source="audit-triage",
            )}
            (project_root / "src" / "Guard.php").write_text(
                "\n".join(["<?php", "function check() {", "    // no check anymore", "}"]),
                encoding="utf-8",
            )
            # A path-based hash is unchanged (path:line didn't move) -> if
            # `active_rejections` compared against IT, "h1" would incorrectly
            # stay active. We assert the path-based hash itself is stable
            # (proving it CANNOT have caught the regression), which is why
            # `compute_evidence_hash` must never be defined this way.
            still_matches_path_hash = path_based_hash == hashlib.sha256(b"src/Guard.php:3").hexdigest()[:8]
            self.assertTrue(still_matches_path_hash)
            active = active_rejections(resolutions, project_root)
        # With the REAL (content-based) compute_evidence_hash, the mark drops
        # even though a path-based hash would not have caught it.
        self.assertNotIn("h1", active)

    def test_reaffirmed_never_rendered_as_active(self):
        resolutions = {"h1": Resolution(verdict="reaffirmed", source="triage")}
        active = active_rejections(resolutions, Path("/nonexistent"))
        self.assertEqual(active, {})

    def test_rejected_without_refute_file_has_no_evidence_to_go_stale(self):
        """External triage with no code citation: never auto-invalidated."""
        resolutions = {"h1": Resolution(verdict="rejected", source="triage")}
        active = active_rejections(resolutions, Path("/nonexistent"))
        self.assertIn("h1", active)

    def test_missing_evidence_file_drops_the_mark(self):
        resolutions = {"h1": Resolution(
            verdict="rejected", evidence_hash="deadbeef",
            refute_file="src/Gone.php", refute_line=1, source="audit-triage",
        )}
        active = active_rejections(resolutions, Path("/nonexistent"))
        self.assertEqual(active, {})


class LoadVerdictsInTests(unittest.TestCase):
    """`--verdicts-in` fail-closed import (Stage 2 / P2.5). Every violation
    must refuse the WHOLE import, never apply a partial result."""

    def _write(self, td: Path, payload: dict) -> Path:
        p = td / "verdicts.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    def _valid_payload(self, sha: str) -> dict:
        return {
            "schema_version": 1,
            "findings_json_sha256": sha,
            "verdicts": [
                {"sink_hash": "abcd1234", "verdict": "rejected", "source": "triage-bot"},
            ],
        }

    def test_valid_import_builds_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), self._valid_payload("deadbeef"))
            out = load_verdicts_in(
                path, valid_sink_hashes={"abcd1234"},
                findings_json_sha256="deadbeef", project_root=Path(td),
            )
        self.assertEqual(set(out), {"abcd1234"})
        self.assertEqual(out["abcd1234"].verdict, "rejected")
        self.assertEqual(out["abcd1234"].source, "triage-bot")
        self.assertEqual(out["abcd1234"].evidence_hash, "")

    def test_hash_mismatch_refuses_whole_import(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), self._valid_payload("stale-hash"))
            with self.assertRaises(VerdictsInError):
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )

    def test_unknown_top_level_field_refuses_import(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            payload["extra_field"] = "nope"
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError) as ctx:
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )
            self.assertIn("extra_field", str(ctx.exception))

    def test_unknown_entry_field_refuses_import(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            payload["verdicts"][0]["unexpected"] = "x"
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError) as ctx:
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )
            self.assertIn("unexpected", str(ctx.exception))

    def test_unknown_sink_hash_refuses_whole_import_and_is_enumerated(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            payload["verdicts"].append(
                {"sink_hash": "ffffffff", "verdict": "rejected", "source": "triage-bot"}
            )
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError) as ctx:
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},  # ffffffff is NOT in here
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )
            self.assertIn("ffffffff", str(ctx.exception))

    def test_duplicate_sink_hash_refuses_import(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            payload["verdicts"].append(
                {"sink_hash": "abcd1234", "verdict": "reaffirmed", "source": "triage-bot"}
            )
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError) as ctx:
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )
            self.assertIn("abcd1234", str(ctx.exception))

    def test_bad_verdict_value_refuses_import(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            payload["verdicts"][0]["verdict"] = "maybe"
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError):
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )

    def test_unknown_condition_key_refuses_import(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            payload["verdicts"][0]["condition_keys"] = ["not_a_real_key"]
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError):
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )

    def test_refute_file_without_refute_line_refuses_import(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            payload["verdicts"][0]["refute_file"] = "src/X.php"
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError):
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )

    def test_missing_required_field_refuses_import(self):
        with tempfile.TemporaryDirectory() as td:
            payload = self._valid_payload("deadbeef")
            del payload["verdicts"][0]["source"]
            path = self._write(Path(td), payload)
            with self.assertRaises(VerdictsInError):
                load_verdicts_in(
                    path, valid_sink_hashes={"abcd1234"},
                    findings_json_sha256="deadbeef", project_root=Path(td),
                )

    def test_refute_file_and_line_compute_evidence_hash(self):
        with tempfile.TemporaryDirectory() as td:
            project_root = Path(td)
            guard = project_root / "src" / "Guard.php"
            guard.parent.mkdir(parents=True)
            guard.write_text("<?php\ndeny_unless(true);\n")
            payload = self._valid_payload("deadbeef")
            payload["verdicts"][0]["refute_file"] = "src/Guard.php"
            payload["verdicts"][0]["refute_line"] = 2
            path = self._write(project_root, payload)
            out = load_verdicts_in(
                path, valid_sink_hashes={"abcd1234"},
                findings_json_sha256="deadbeef", project_root=project_root,
            )
            self.assertEqual(
                out["abcd1234"].evidence_hash,
                compute_evidence_hash("src/Guard.php", 2, project_root),
            )

    def _evidence_import(self, td: Path, **entry):
        payload = self._valid_payload("deadbeef")
        payload["verdicts"][0].update(entry)
        path = self._write(td, payload)
        return load_verdicts_in(
            path, valid_sink_hashes={"abcd1234", "nohash00"},
            findings_json_sha256="deadbeef", project_root=td,
        )

    def test_nohash_sentinel_verdict_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(VerdictsInError) as ctx:
                self._evidence_import(Path(td), sink_hash="nohash00")
            self.assertIn("nohash00", str(ctx.exception))

    def test_evidence_in_missing_file_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(VerdictsInError) as ctx:
                self._evidence_import(Path(td), refute_file="src/Gone.php", refute_line=2)
            self.assertIn("cannot be located", str(ctx.exception))

    def test_evidence_line_out_of_range_or_blank_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src").mkdir()
            (root / "src" / "Guard.php").write_text("<?php\n\ndeny();\n")
            for line in (2, 99):
                with self.assertRaises(VerdictsInError):
                    self._evidence_import(root, refute_file="src/Guard.php", refute_line=line)

    def test_evidence_absolute_path_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside.php"
            outside.write_text("<?php\ndeny();\n")
            with self.assertRaises(VerdictsInError) as ctx:
                self._evidence_import(root, refute_file=str(outside), refute_line=2)
            self.assertIn("relative path", str(ctx.exception))

    def test_evidence_parent_traversal_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "project"
            root.mkdir()
            (Path(td) / "secret.php").write_text("<?php\ndeny();\n")
            with self.assertRaises(VerdictsInError):
                self._evidence_import(root, refute_file="../secret.php", refute_line=2)


class CrossRunResolutionMemoryTests(unittest.TestCase):
    """End-to-end: a `rejected` verdict imported with `--verdicts-in`
    persists across runs via `.findings_state.json`, survives as a `Previously
    rejected` annotation WITHOUT suppressing the finding, drops automatically
    when the cited evidence changes, and keeps REPORT.md / findings.json
    byte-stable across repeated runs.
    """

    CLI = str(BIN_DIR / "dedupe_findings.py")

    def _mk_project(self, td_path: Path):
        from tests.test_dedupe_findings import _mk_finding_md  # type: ignore

        review_root = td_path / "review"
        waves = review_root / "waves"
        waves.mkdir(parents=True)
        (waves / "W1.md").write_text(
            _mk_finding_md(
                n=1,
                sink_file="src/Auth/Controller.php",
                sink_line=42,
                sink_kind="csrf_missing",
                root_cause_family="authz",
                enclosing_symbol="Controller::callback",
                sink_snippet="$ok = $request->get('token');\nreturn $ok;",
                severity="High",
                confidence=9,
            ),
            encoding="utf-8",
        )
        project_root = td_path / "project"
        guard = project_root / "src" / "Auth" / "Guard.php"
        guard.parent.mkdir(parents=True)
        guard.write_text(
            "<?php\nfunction checkCsrf() { return hash_equals($a, $b); }\n"
            "function unrelated() { return 1; }\n",
            encoding="utf-8",
        )
        return review_root, waves, project_root

    def _run(self, *, review_root, waves, project_root, verdicts_in=None):
        import subprocess
        args = [
            "python3", self.CLI,
            "--input-glob", str(waves / "*.md"),
            "--output", str(review_root / "REPORT.md"),
            "--details-dir", str(review_root / "REPORT"),
            "--project-root", str(project_root),
        ]
        if verdicts_in is not None:
            args += ["--verdicts-in", str(verdicts_in)]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        # The finding is `authz` family -> its body lives in REPORT/authz.md.
        detail = (review_root / "REPORT" / "authz.md").read_text(encoding="utf-8")
        return (
            (review_root / "REPORT.md").read_text(encoding="utf-8") + "\n" + detail,
            (review_root / "findings.json").read_bytes(),
        )

    def _import_rejection(self, review_root, waves, project_root):
        """Run 0: a plain run produces findings.json, then the verdict bound
        to its hash is imported."""
        self._run(review_root=review_root, waves=waves, project_root=project_root)
        raw = (review_root / "findings.json").read_bytes()
        sink_hash = json.loads(raw)["confirmed"][0]["sink_hash"]
        verdicts = review_root / "verdicts.json"
        verdicts.write_text(json.dumps({
            "schema_version": 1,
            "findings_json_sha256": hashlib.sha256(raw).hexdigest(),
            "verdicts": [{
                "sink_hash": sink_hash, "verdict": "rejected", "source": "audit-triage",
                "refute_file": "src/Auth/Guard.php", "refute_line": 2,
            }],
        }), encoding="utf-8")
        return self._run(
            review_root=review_root, waves=waves, project_root=project_root,
            verdicts_in=verdicts,
        )

    def test_mark_persists_without_reimport_and_does_not_suppress_finding(self):
        with tempfile.TemporaryDirectory() as td:
            review_root, waves, project_root = self._mk_project(Path(td))
            report0, _ = self._import_rejection(review_root, waves, project_root)
            self.assertIn("Previously rejected", report0)

            report1, _ = self._run(
                review_root=review_root, waves=waves, project_root=project_root,
            )
            self.assertIn("Previously rejected", report1)
            self.assertIn("src/Auth/Guard.php:2", report1)
            self.assertIn("`src/Auth/Controller.php:42`", report1)

    def test_idempotent_across_repeated_runs(self):
        with tempfile.TemporaryDirectory() as td:
            review_root, waves, project_root = self._mk_project(Path(td))
            self._import_rejection(review_root, waves, project_root)
            runs = [
                self._run(review_root=review_root, waves=waves, project_root=project_root)
                for _ in range(3)
            ]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])

    def test_evidence_removed_drops_mark_on_next_run(self):
        """The protection is removed at refute_file:refute_line while the sink
        is untouched -> the mark is gone on the very next run."""
        with tempfile.TemporaryDirectory() as td:
            review_root, waves, project_root = self._mk_project(Path(td))
            self._import_rejection(review_root, waves, project_root)
            guard = project_root / "src" / "Auth" / "Guard.php"

            # Control: an UNRELATED edit in the same file must not drop the mark.
            guard.write_text(
                "<?php\nfunction checkCsrf() { return hash_equals($a, $b); }\n"
                "function unrelated() { return 2; }\n",
                encoding="utf-8",
            )
            report_control, _ = self._run(
                review_root=review_root, waves=waves, project_root=project_root,
            )
            self.assertIn("Previously rejected", report_control)

            guard.write_text(
                "<?php\nfunction checkCsrf() { return true; /* FIXME removed check */ }\n"
                "function unrelated() { return 2; }\n",
                encoding="utf-8",
            )
            report_after, _ = self._run(
                review_root=review_root, waves=waves, project_root=project_root,
            )
        self.assertNotIn("Previously rejected", report_after)
        self.assertIn("`src/Auth/Controller.php:42`", report_after)


if __name__ == "__main__":
    unittest.main()
