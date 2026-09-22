"""Cross-run findings-state diff: save/load round-trip + compute_diff."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
sys.path.insert(0, str(BIN_DIR))

from dedupe.models import FLAG_REFUTE_CLAIMED, Finding, MergedFinding  # noqa: E402
from dedupe.refute import compute_evidence_hash  # noqa: E402
from dedupe.state import (  # noqa: E402
    FindingSnapshot,
    Resolution,
    STATE_FILENAME,
    STATE_SCHEMA_VERSION,
    VerdictsInError,
    active_rejections,
    compute_diff,
    load_resolutions,
    compute_run_id,
    load_continuation_baseline,
    load_state,
    load_verdicts_in,
    resolutions_from_refuted_findings,
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


class SchemaMigrationTests(unittest.TestCase):
    """Stage 2 / P2.5: schema 1 -> 2 is a MIGRATION, not a reset — a state
    file written by the pre-Stage-2 pipeline must still be read, with
    `verdict`/`condition_keys` backfilled, not silently dropped (which would
    make every finding look New on the first post-upgrade run)."""

    def _write_schema1_state(self, review_root: Path, sink_hash: str) -> None:
        review_root.mkdir(parents=True, exist_ok=True)
        (review_root / STATE_FILENAME).write_text(json.dumps({
            "schema_version": 1,
            "findings": [
                {
                    "sink_hash": sink_hash, "sink_file": "src/A.php", "sink_line": 10,
                    "sink_kind": "idor_lookup", "severity": "High", "title": "Test A",
                },
            ],
        }), encoding="utf-8")

    def test_schema1_state_loads_with_migrated_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            self._write_schema1_state(review_root, "abcd1234")
            loaded = load_state(review_root)
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].verdict, "confirmed")
        self.assertEqual(loaded[0].condition_keys, ())

    def test_schema1_state_not_all_new_on_diff(self):
        """The concrete regression this migration exists to prevent: a
        schema-1 state file must not make every current finding look `new`."""
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            self._write_schema1_state(review_root, "abcd1234")
            previous = load_state(review_root)
            current = [FindingSnapshot("abcd1234", "src/A.php", 10, "idor_lookup", "High", "Test A")]
            diff = compute_diff(previous, current)
        self.assertEqual(diff.new, [])
        self.assertEqual(len(diff.recurring), 1)

    def test_schema1_state_has_no_resolutions(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            self._write_schema1_state(review_root, "abcd1234")
            self.assertEqual(load_resolutions(review_root), {})

    def test_unreadable_future_schema_version_still_returns_none(self):
        """Broadening acceptance to {1, 2} must not silently accept an
        unknown future version too."""
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            (review_root / STATE_FILENAME).write_text(
                json.dumps({"schema_version": 99, "findings": []})
            )
            self.assertIsNone(load_state(review_root))
            self.assertEqual(load_resolutions(review_root), {})


class ResolutionsAccumulateTests(unittest.TestCase):
    """`save_state`'s resolutions merge is read-modify-write, not a full
    overwrite — the journal accumulates across runs."""

    def test_resolutions_persist_across_separate_save_calls(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state([], review_root, resolutions={
                "hash1": Resolution(verdict="rejected", source="refute"),
            })
            save_state([], review_root, resolutions={
                "hash2": Resolution(verdict="rejected", source="refute"),
            })
            loaded = load_resolutions(review_root)
        self.assertEqual(set(loaded), {"hash1", "hash2"})

    def test_same_hash_overwritten_by_latest_call(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state([], review_root, resolutions={
                "hash1": Resolution(verdict="rejected", source="refute"),
            })
            save_state([], review_root, resolutions={
                "hash1": Resolution(verdict="reaffirmed", source="triage"),
            })
            loaded = load_resolutions(review_root)
        self.assertEqual(loaded["hash1"].verdict, "reaffirmed")
        self.assertEqual(loaded["hash1"].source, "triage")

    def test_run_seq_advances_only_on_calls_that_supply_resolutions(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state([], review_root, resolutions={
                "hash1": Resolution(verdict="rejected", source="refute"),
            })
            first_seq = load_resolutions(review_root)["hash1"].run_seq
            # A plain run with no fresh resolutions must not touch hash1's run_seq.
            save_state([], review_root, resolutions={})
            self.assertEqual(load_resolutions(review_root)["hash1"].run_seq, first_seq)
            # A run that DOES supply a (possibly unrelated) resolution bumps
            # the counter for what it touches.
            save_state([], review_root, resolutions={
                "hash2": Resolution(verdict="rejected", source="refute"),
            })
            reloaded = load_resolutions(review_root)
            self.assertEqual(reloaded["hash1"].run_seq, first_seq)
            self.assertGreater(reloaded["hash2"].run_seq, first_seq)

    def test_run_seq_never_appears_in_findings_serialization(self):
        """run_seq is an audit trail INSIDE state.json only — Resolution's
        own to_dict is the boundary that matters here; findings.json/REPORT.md
        never construct a Resolution from state at all (see
        renderer._render_resolution_note, which never reads run_seq)."""
        res = Resolution(verdict="rejected", source="refute", run_seq=7)
        self.assertIn("run_seq", res.to_dict())  # present in state.json (by design)
        # But the rendered note must not mention it — covered in test_renderer.py.


class ResolutionsFromRefutedFindingsTests(unittest.TestCase):
    def _mk_merged(self, sink_snippet="if (true) { deny(); }", **overrides) -> MergedFinding:
        f = Finding(
            title_line="h", sink_file="src/A.php", sink_line=10,
            sink_kind="csrf_missing", root_cause_family="authz",
            enclosing_symbol="A::m", sink_snippet=sink_snippet,
            severity="High", confidence=9,
        )
        mf = MergedFinding(primary=f)
        for k, v in overrides.items():
            setattr(mf, k, v)
        return mf

    def test_builds_resolution_for_refute_claimed_finding(self):
        with tempfile.TemporaryDirectory() as td:
            project_root = Path(td)
            guard = project_root / "src" / "Guard.php"
            guard.parent.mkdir(parents=True)
            guard.write_text("<?php\nfunction check() {\n    deny_unless(hasRole('admin'));\n}\n")
            mf = self._mk_merged(
                flags=[FLAG_REFUTE_CLAIMED],
                refute_file="src/Guard.php", refute_line=3,
                refute_rationale="role check", refute_confidence=9,
            )
            out = resolutions_from_refuted_findings([mf], project_root)
            self.assertIn(mf.primary.sink_hash, out)
            res = out[mf.primary.sink_hash]
            self.assertEqual(res.verdict, "rejected")
            self.assertEqual(res.source, "refute")
            self.assertEqual(res.refute_file, "src/Guard.php")
            self.assertEqual(res.refute_line, 3)
            self.assertEqual(
                res.evidence_hash,
                compute_evidence_hash("src/Guard.php", 3, project_root),
            )

    def test_skips_finding_without_refute_claimed_flag(self):
        with tempfile.TemporaryDirectory() as td:
            mf = self._mk_merged()  # no flags
            out = resolutions_from_refuted_findings([mf], Path(td))
        self.assertEqual(out, {})

    def test_skips_nohash00_finding(self):
        with tempfile.TemporaryDirectory() as td:
            mf = self._mk_merged(
                sink_snippet="",  # -> nohash00
                flags=[FLAG_REFUTE_CLAIMED],
                refute_file="src/Guard.php", refute_line=1,
            )
            self.assertEqual(mf.primary.sink_hash, "nohash00")
            out = resolutions_from_refuted_findings([mf], Path(td))
        self.assertEqual(out, {})


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
                refute_file="src/Guard.php", refute_line=3, source="refute",
            )}
            active = active_rejections(resolutions, project_root)
        self.assertIn("h1", active)

    def test_key_scenario_protection_removed_drops_the_mark(self):
        """The scenario DoD #5 names by name: the protection at
        refute_file:refute_line is removed (sink untouched) -> the mark must
        be dropped on the NEXT run, without re-running --refute."""
        with tempfile.TemporaryDirectory() as td:
            project_root = self._mk_project(Path(td), [
                "<?php", "function check() {", "    deny_unless(hasRole('admin'));", "}",
            ])
            evidence_hash = compute_evidence_hash("src/Guard.php", 3, project_root)
            resolutions = {"h1": Resolution(
                verdict="rejected", evidence_hash=evidence_hash,
                refute_file="src/Guard.php", refute_line=3, source="refute",
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
                refute_file="src/Guard.php", refute_line=3, source="refute",
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
                refute_file="src/Guard.php", refute_line=3, source="refute",
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
            refute_file="src/Gone.php", refute_line=1, source="refute",
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


class ContinuationBaselineTests(unittest.TestCase):
    """A second dedupe pass over the same wave files re-states one run. Diffing
    it against the snapshot that run's own first pass wrote made every finding
    read as recurring and none as new, so the section contradicted the report it
    sat in."""

    CLI = str(BIN_DIR / "dedupe_findings.py")

    def _wave(self, waves: Path, *, line: int, snippet: str) -> None:
        from tests.test_dedupe_findings import _mk_finding_md  # type: ignore
        waves.mkdir(parents=True, exist_ok=True)
        (waves / "W1.md").write_text(
            _mk_finding_md(
                n=1,
                sink_file="src/Api/Controller.php",
                sink_line=line,
                sink_kind="idor_lookup",
                root_cause_family="authz",
                enclosing_symbol="Controller::show",
                sink_snippet=snippet,
                severity="High",
                confidence=9,
            ),
            encoding="utf-8",
        )

    def _dedupe(self, review_root: Path, *, refute: Path | None = None) -> str:
        import subprocess
        args = [
            "python3", self.CLI,
            "--input-glob", str(review_root / "waves" / "*.md"),
            "--output", str(review_root / "REPORT.md"),
            "--details-dir", str(review_root / "REPORT"),
            "--project-root", str(review_root),
        ]
        if refute is not None:
            args += ["--refute", str(refute)]
        proc = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return (review_root / "REPORT.md").read_text(encoding="utf-8")

    def _empty_refute(self, review_root: Path) -> Path:
        path = review_root / "refute.md"
        path.write_text("refute_records: []\n", encoding="utf-8")
        return path

    def test_refute_pass_of_a_first_run_reports_no_previous_run(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            self._wave(review_root / "waves", line=10, snippet="$id = $req->get('id');")
            self.assertNotIn("## Diff vs previous run", self._dedupe(review_root))
            report = self._dedupe(review_root, refute=self._empty_refute(review_root))
            self.assertNotIn("## Diff vs previous run", report)

    def test_refute_pass_repeats_the_first_passs_diff(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            waves = review_root / "waves"
            # Run 1 — the genuine previous run.
            self._wave(waves, line=10, snippet="$id = $req->get('id');")
            self._dedupe(review_root)
            # Run 2, first pass — a different sink, so one new and one closed.
            self._wave(waves, line=77, snippet="$other = $req->get('slug');")
            first = self._dedupe(review_root)
            self.assertIn("- New findings (not in previous state): 1", first)
            self.assertIn("- Recurring (also in previous state): 0", first)
            self.assertIn("- Closed (in previous state, gone now): 1", first)
            # Run 2, second pass — same waves, so the same diff, not a self-diff.
            second = self._dedupe(review_root, refute=self._empty_refute(review_root))
            self.assertIn("- New findings (not in previous state): 1", second)
            self.assertIn("- Recurring (also in previous state): 0", second)
            self.assertIn("- Closed (in previous state, gone now): 1", second)

    def test_plain_rerun_over_the_same_waves_is_a_continuation_too(self):
        # No flag distinguishes this pass; only the wave files do. A flag-based
        # signal left exactly this case self-diffing.
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            waves = review_root / "waves"
            self._wave(waves, line=10, snippet="$id = $req->get('id');")
            self._dedupe(review_root)
            self._wave(waves, line=77, snippet="$other = $req->get('slug');")
            first = self._dedupe(review_root)
            second = self._dedupe(review_root)
            self.assertIn("- New findings (not in previous state): 1", second)
            self.assertIn("- Closed (in previous state, gone now): 1", second)
            self.assertEqual(
                first.split("## Diff vs previous run")[1],
                second.split("## Diff vs previous run")[1],
            )

    def test_third_and_later_passes_keep_the_same_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            waves = review_root / "waves"
            self._wave(waves, line=10, snippet="$id = $req->get('id');")
            self._dedupe(review_root)
            self._wave(waves, line=77, snippet="$other = $req->get('slug');")
            self._dedupe(review_root)
            refute = self._empty_refute(review_root)
            self._dedupe(review_root, refute=refute)
            third = self._dedupe(review_root, refute=refute)
            self.assertIn("- New findings (not in previous state): 1", third)
            self.assertIn("- Closed (in previous state, gone now): 1", third)

    def test_a_later_audit_diffs_against_the_latest_findings(self):
        # New wave content is a new run, so the carried baseline must not leak
        # past the run that owns it.
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            waves = review_root / "waves"
            self._wave(waves, line=10, snippet="$id = $req->get('id');")
            self._dedupe(review_root)
            self._dedupe(review_root, refute=self._empty_refute(review_root))
            self._wave(waves, line=10, snippet="$id = $req->get('id'); // reworded")
            report = self._dedupe(review_root)
            self.assertIn("- New findings (not in previous state): 1", report)
            self.assertIn("- Closed (in previous state, gone now): 1", report)


class RunIdentityTests(unittest.TestCase):
    """`run_id` is what tells a re-statement of one run from a fresh audit."""

    def _waves(self, root: Path, bodies: dict[str, str]) -> list[Path]:
        root.mkdir(parents=True, exist_ok=True)
        out = []
        for name, body in bodies.items():
            path = root / name
            path.write_text(body, encoding="utf-8")
            out.append(path)
        return out

    def test_same_files_same_id_regardless_of_argument_order(self):
        with tempfile.TemporaryDirectory() as td:
            paths = self._waves(Path(td), {"W1.md": "a", "W2.md": "b"})
            self.assertEqual(compute_run_id(paths), compute_run_id(list(reversed(paths))))

    def test_changed_content_changes_the_id(self):
        with tempfile.TemporaryDirectory() as td:
            paths = self._waves(Path(td), {"W1.md": "a"})
            before = compute_run_id(paths)
            paths[0].write_text("a2", encoding="utf-8")
            self.assertNotEqual(before, compute_run_id(paths))

    def test_added_or_removed_wave_changes_the_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            one = compute_run_id(self._waves(root, {"W1.md": "a"}))
            two = compute_run_id(self._waves(root, {"W1.md": "a", "W2.md": "b"}))
            self.assertNotEqual(one, two)

    def test_empty_input_never_matches_a_recorded_id(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state([], review_root, baseline=None, run_id="")
            self.assertEqual(compute_run_id([]), "")
            self.assertEqual(load_continuation_baseline(review_root, ""), (False, None))


class ContinuationBaselineUnitTests(unittest.TestCase):
    RUN = "0123456789abcdef"

    def _snapshot(self):
        return [FindingSnapshot("abcd1234", "src/A.php", 10, "idor_lookup", "High", "A")]

    def test_state_without_the_new_keys_is_not_a_continuation(self):
        # A file written by a build that predates `baseline`/`run_id`: falling
        # back is right, claiming "no previous run" would erase real history.
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state(self._snapshot(), review_root)
            payload = json.loads((review_root / STATE_FILENAME).read_text(encoding="utf-8"))
            del payload["baseline"]
            del payload["run_id"]
            (review_root / STATE_FILENAME).write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(load_continuation_baseline(review_root, self.RUN), (False, None))

    def test_recorded_null_baseline_is_distinct_from_an_absent_one(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state([], review_root, baseline=None, run_id=self.RUN)
            self.assertEqual(load_continuation_baseline(review_root, self.RUN), (True, None))

    def test_a_different_run_id_is_not_a_continuation(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state([], review_root, baseline=self._snapshot(), run_id=self.RUN)
            self.assertEqual(load_continuation_baseline(review_root, "ffff"), (False, None))

    def test_malformed_baseline_falls_back_instead_of_reading_as_empty(self):
        # `(True, [])` here would call every finding New on a half-written file.
        for broken in (42, "x", {"a": 1}):
            with tempfile.TemporaryDirectory() as td:
                review_root = Path(td)
                save_state([], review_root, baseline=self._snapshot(), run_id=self.RUN)
                payload = json.loads((review_root / STATE_FILENAME).read_text(encoding="utf-8"))
                payload["baseline"] = broken
                (review_root / STATE_FILENAME).write_text(json.dumps(payload), encoding="utf-8")
                self.assertEqual(
                    load_continuation_baseline(review_root, self.RUN), (False, None),
                    msg=f"baseline={broken!r}",
                )

    def test_schema_version_stays_readable_by_a_build_without_these_keys(self):
        # Moving the version would make such a build reject the whole file and
        # reset `resolutions`, the one accumulated part of this state.
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td)
            save_state(self._snapshot(), review_root, baseline=None, run_id=self.RUN)
            payload = json.loads((review_root / STATE_FILENAME).read_text(encoding="utf-8"))
            self.assertIn(payload["schema_version"], (1, 2))



if __name__ == "__main__":
    unittest.main()
