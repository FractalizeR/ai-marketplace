"""Tests for build_index.py -- validate_sidecar / validate_all (sidecar
contract v2, rules 1-12), emit_verdicts, emit_index (INDEX.md v2), and the
CLI that wires them to a triage run's .work/ artifacts.

Sidecar fixtures follow agents/triage-verify.md's OUTPUT CONTRACT (v2):
locations are addressed by `record_id`; `sink_hash` is carried as data.
Most tests run over the REAL e2e fixture (fixtures_lib.build_review_root),
which already has confirmed+needs_validation and confirmed+hardening pairs
sharing a sink_hash plus merge groups; the bucket fixture
(fixtures_lib.build_bucket_review_root) supplies `[ATTACHED_WITHOUT_HASH]`
and two needs_validation records sharing one sink_hash.
"""

from __future__ import annotations

import contextlib
import copy
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

EXAMPLE_CONFIG = fixtures_lib.BIN_DIR.parent / ".audit-triage.example.json"

# Every sink_file the e2e fixture names, plus a file with a blank line 2 for
# the rule-6 "blank refute line" case.
PROJECT_FILES = ["src/Repo.php", "src/Token.php", "src/Misc.php", "src/AlsoUnrelated.php", "src/Unrelated.php"]

UNIT_FILES = {
    "u1injection": "med-u1injection-dql-injection.md",
    "u2crypto": "high-u2crypto-token-storage.md",
    "triagemanual": "triage-triagemanual-misc-pattern.md",
    "triageleads": "triage-triageleads-leads.md",
}


def _loc(r: pf.Record, status: str, candidate=None, *, note="checked", condition_keys=(), **extra) -> dict:
    loc = {
        "record_id": r.record_id,
        "sink_hash": r.sink_hash,
        "sink_file": r.sink_file,
        "sink_line": r.sink_line,
        "status": status,
        "note": note,
        "condition_keys": list(condition_keys),
        "verdict_candidate": candidate,
    }
    loc.update(extra)
    return loc


def _sidecar(unit_id, disposition, *, unit_file, severity_before, severity_after, locations, rationale="", title=None):
    return {
        "sidecar_version": 2,
        "unit_id": unit_id,
        "disposition": disposition,
        "title": title or f"synthetic unit {unit_id}",
        "unit_file": unit_file,
        "severity_before": severity_before,
        "severity_after": severity_after,
        "severity_change_rationale": rationale,
        "locations": list(locations),
        "fix_pattern_note": "",
    }


def valid_sidecars(recs: dict[str, pf.Record]) -> dict[str, dict]:
    """A contract-valid v2 sidecar set over FULL_GROUPING on the e2e fixture.

    Expected hand-back: b55e8630 / 809bd41e / 116a9474 reaffirmed,
    2395c9e0 rejected (confirmed#4 + needs_validation#1, one refute);
    33c924c1 / c79c6e5e / cb6923b3 withheld; nohash00 never sent."""
    misc_refute = {"refute_file": "src/Misc.php", "refute_line": 2}
    return {
        "u1injection": _sidecar(
            "u1injection", "work_unit",
            unit_file=UNIT_FILES["u1injection"], severity_before="Critical", severity_after="Medium",
            rationale="reachable from the internal network only",
            locations=[
                _loc(recs["confirmed#0"], "confirmed", "reaffirmed", condition_keys=["internal_network_only"]),
                _loc(recs["confirmed#1"], "confirmed", "reaffirmed"),
                _loc(recs["needs_validation#0"], "confirmed", "reaffirmed"),
            ],
        ),
        "u2crypto": _sidecar(
            "u2crypto", "work_unit",
            unit_file=UNIT_FILES["u2crypto"], severity_before="High", severity_after="High",
            locations=[
                _loc(recs["confirmed#2"], "confirmed", "reaffirmed"),
                _loc(recs["confirmed#3"], "changed"),
                _loc(recs["hardening#0"], "manual_review"),
            ],
        ),
        "triagemanual": _sidecar(
            "triagemanual", "triage",
            unit_file=UNIT_FILES["triagemanual"], severity_before="High", severity_after=None,
            rationale="refuted by an in-repo guard",
            locations=[
                _loc(recs["confirmed#4"], "false_positive", "rejected", **misc_refute),
                _loc(recs["confirmed#5"], "manual_review"),
                _loc(recs["needs_validation#1"], "false_positive", "rejected", **misc_refute),
            ],
        ),
        "triageleads": _sidecar(
            "triageleads", "triage",
            unit_file=UNIT_FILES["triageleads"], severity_before=None, severity_after=None,
            locations=[
                _loc(recs["needs_validation#2"], "manual_review"),
                _loc(
                    recs["hardening#1"], "false_positive", None,
                    note="closed by the ingress (synthetic)", condition_keys=["deployment_control_not_in_source"],
                ),
            ],
        ),
    }


class _E2EFixture(unittest.TestCase):
    """One real review_root + project tree + TICKETS_ROOT with every unit
    file, shared by a test class. Tests mutate deep copies of the sidecars."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.review_root = fixtures_lib.build_review_root(base / "review")
        cls.records = pf.load(cls.review_root)
        cls.recs = {r.record_id: r for r in cls.records}
        cls.grouping = copy.deepcopy(fixtures_lib.FULL_GROUPING)
        cls.project_root = fixtures_lib.build_project_tree(base / "project", PROJECT_FILES)
        (cls.project_root / "src" / "Blank.php").write_text("<?php\n\n// synthetic\n", encoding="utf-8")
        cls.tickets_root = base / "tickets"
        cls.tickets_root.mkdir()
        for name in UNIT_FILES.values():
            (cls.tickets_root / name).write_text("synthetic unit body\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def sidecars(self) -> dict[str, dict]:
        return valid_sidecars(self.recs)

    def violations(self, sidecars, *, project_root="default") -> list[str]:
        root = self.project_root if project_root == "default" else project_root
        return bi.validate_all(sidecars, self.grouping, self.records, self.tickets_root, root)

    def assertRule(self, violations: list[str], rule: int, *fragments: str):
        hits = [v for v in violations if f"rule {rule}:" in v and all(f in v for f in fragments)]
        self.assertTrue(hits, msg=f"no 'rule {rule}' violation mentioning {fragments}; got {violations}")

    @staticmethod
    def loc_of(sidecar: dict, record_id: str) -> dict:
        return next(loc for loc in sidecar["locations"] if loc["record_id"] == record_id)


# ---------------------------------------------------------------------------
# validate_sidecar / validate_all.
# ---------------------------------------------------------------------------


class ValidateSidecarTests(_E2EFixture):
    def test_valid_sidecar_set_has_no_violations(self):
        self.assertEqual(self.violations(self.sidecars()), [])

    def test_rule1_v1_sidecar_is_one_message_and_skips_the_rest(self):
        sidecars = self.sidecars()
        sidecars["u2crypto"]["sidecar_version"] = 1
        sidecars["u2crypto"]["locations"] = []  # would be a rule-3 violation if checked
        v = self.violations(sidecars)
        self.assertRule(v, 1, "u2crypto")
        self.assertEqual([x for x in v if x.startswith("u2crypto")], [x for x in v if "rule 1:" in x])
        self.assertEqual(len(v), 1)

    def test_rule2_placeholder_severity_before_rejected(self):
        sidecars = self.sidecars()
        sidecars["triageleads"]["severity_before"] = "—"
        self.assertRule(self.violations(sidecars), 2, "triageleads", "severity_before")

    def test_rule2_header_schema(self):
        sidecars = self.sidecars()
        sidecars["u1injection"]["unit_id"] = "other"
        sidecars["u1injection"]["disposition"] = "ticket"
        sidecars["u1injection"]["title"] = "  "
        del sidecars["u1injection"]["fix_pattern_note"]
        v = self.violations(sidecars)
        self.assertRule(v, 2, "u1injection", "unit_id")
        self.assertRule(v, 2, "u1injection", "disposition")
        self.assertRule(v, 2, "u1injection", "title")
        self.assertRule(v, 2, "u1injection", "fix_pattern_note")

    def test_rule2_sidecar_for_unknown_unit(self):
        sidecars = self.sidecars()
        sidecars["ghost"] = copy.deepcopy(sidecars["u2crypto"])
        self.assertRule(self.violations(sidecars), 2, "ghost", "not in grouping")

    def test_rule3_missing_location(self):
        sidecars = self.sidecars()
        sidecars["u1injection"]["locations"] = [
            loc for loc in sidecars["u1injection"]["locations"] if loc["record_id"] != "needs_validation#0"
        ]
        self.assertRule(self.violations(sidecars), 3, "u1injection", "needs_validation#0")

    def test_rule3_duplicate_and_foreign_location(self):
        sidecars = self.sidecars()
        locs = sidecars["u1injection"]["locations"]
        locs.append(copy.deepcopy(locs[0]))
        locs.append(_loc(self.recs["confirmed#2"], "confirmed", "reaffirmed"))
        v = self.violations(sidecars)
        self.assertRule(v, 3, "u1injection", "duplicated", "confirmed#0")
        self.assertRule(v, 3, "u1injection", "not in this unit", "confirmed#2")

    def test_rule4_sink_hash_must_match_the_record(self):
        sidecars = self.sidecars()
        # needs_validation#0 shares 809bd41e with confirmed#1; citing the
        # merge primary's hash instead is the #4 mix-up.
        self.loc_of(sidecars["u1injection"], "needs_validation#0")["sink_hash"] = "b55e8630"
        self.assertRule(self.violations(sidecars), 4, "u1injection/needs_validation#0")

    def test_rule4_status_enum(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["u2crypto"], "confirmed#3")["status"] = "fixed"
        self.assertRule(self.violations(sidecars), 4, "u2crypto/confirmed#3", "status")

    def test_rule5_confirmed_needs_reaffirmed(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["u2crypto"], "confirmed#2")["verdict_candidate"] = None
        self.assertRule(self.violations(sidecars), 5, "u2crypto/confirmed#2")

    def test_rule5_changed_and_manual_review_need_null(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["u2crypto"], "confirmed#3")["verdict_candidate"] = "reaffirmed"
        self.loc_of(sidecars["u2crypto"], "hardening#0").update(verdict_candidate="rejected", refute_file="src/Token.php", refute_line=1)
        v = self.violations(sidecars)
        self.assertRule(v, 5, "u2crypto/confirmed#3")
        self.assertRule(v, 5, "u2crypto/hardening#0")

    def test_rule5_false_positive_reaffirmed_rejected(self):
        sidecars = self.sidecars()
        loc = self.loc_of(sidecars["triagemanual"], "confirmed#4")
        loc["verdict_candidate"] = "reaffirmed"
        del loc["refute_file"], loc["refute_line"]
        self.assertRule(self.violations(sidecars), 5, "triagemanual/confirmed#4")

    def test_rule5_false_positive_null_needs_condition_keys_and_note(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["triageleads"], "hardening#1").update(condition_keys=[], note=" ")
        v = self.violations(sidecars)
        self.assertRule(v, 5, "triageleads/hardening#1", "condition_keys")
        self.assertRule(v, 5, "triageleads/hardening#1", "note")

    def test_false_positive_closed_outside_repo_is_valid(self):
        # triageleads/hardening#1 in the valid set is exactly this case.
        loc = self.loc_of(self.sidecars()["triageleads"], "hardening#1")
        self.assertEqual((loc["status"], loc["verdict_candidate"]), ("false_positive", None))
        self.assertEqual(self.violations(self.sidecars()), [])

    def _refute_violations(self, **refute) -> list[str]:
        sidecars = self.sidecars()
        loc = self.loc_of(sidecars["triagemanual"], "confirmed#4")
        loc.pop("refute_file", None)
        loc.pop("refute_line", None)
        loc.update(refute)
        return self.violations(sidecars)

    def test_rule6_absolute_refute_file(self):
        v = self._refute_violations(refute_file=str(self.project_root / "src" / "Misc.php"), refute_line=2)
        self.assertRule(v, 6, "triagemanual/confirmed#4", "relative")

    def test_rule6_dotdot_refute_file(self):
        v = self._refute_violations(refute_file="src/../../outside.php", refute_line=1)
        self.assertRule(v, 6, "triagemanual/confirmed#4", "'..'")

    def test_rule6_refute_file_missing(self):
        v = self._refute_violations(refute_file="src/Nope.php", refute_line=1)
        self.assertRule(v, 6, "triagemanual/confirmed#4", "does not exist")

    def test_rule6_refute_line_past_end(self):
        v = self._refute_violations(refute_file="src/Misc.php", refute_line=99)
        self.assertRule(v, 6, "triagemanual/confirmed#4", "past the end")

    def test_rule6_refute_line_blank(self):
        v = self._refute_violations(refute_file="src/Blank.php", refute_line=2)
        self.assertRule(v, 6, "triagemanual/confirmed#4", "blank")

    def test_rule6_rejected_without_refute(self):
        v = self._refute_violations()
        self.assertRule(v, 6, "triagemanual/confirmed#4", "refute_file")
        self.assertRule(v, 6, "triagemanual/confirmed#4", "refute_line")

    def test_rule6_refute_on_non_rejected_location(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["u2crypto"], "confirmed#2").update(refute_file="src/Token.php", refute_line=1)
        self.assertRule(self.violations(sidecars), 6, "u2crypto/confirmed#2", "only with")

    def test_rule6_project_root_unknown_only_when_needed(self):
        v = self.violations(self.sidecars(), project_root=None)
        self.assertRule(v, 6, "triagemanual/confirmed#4", "project_root unknown")
        self.assertTrue(all("triagemanual/" in x for x in v), msg=v)

        sidecars = self.sidecars()
        for rid in ("confirmed#4", "needs_validation#1"):
            loc = self.loc_of(sidecars["triagemanual"], rid)
            loc.update(verdict_candidate=None, condition_keys=["deployment_control_not_in_source"])
            del loc["refute_file"], loc["refute_line"]
        self.assertEqual(self.violations(sidecars, project_root=None), [])

    def test_rule7_unknown_condition_key(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["u1injection"], "confirmed#1")["condition_keys"] = ["not_a_real_key"]
        self.assertRule(self.violations(sidecars), 7, "u1injection/confirmed#1", "not_a_real_key")

    def test_rule8_work_unit_without_confirmed_or_changed(self):
        sidecars = self.sidecars()
        s = sidecars["u2crypto"]
        s["locations"] = [
            _loc(self.recs["confirmed#2"], "false_positive", None, condition_keys=["admin_only"]),
            _loc(self.recs["confirmed#3"], "manual_review"),
            _loc(self.recs["hardening#0"], "manual_review"),
        ]
        self.assertRule(self.violations(sidecars), 8, "u2crypto", "confirmed or changed")

    def test_rule8_work_unit_severity_and_prefix(self):
        sidecars = self.sidecars()
        sidecars["u2crypto"]["severity_after"] = "Low"
        self.assertRule(self.violations(sidecars), 8, "u2crypto", "prefix")
        sidecars["u2crypto"]["severity_after"] = None
        self.assertRule(self.violations(sidecars), 8, "u2crypto", "severity_after")

    def test_rule8_confirmed_hardening_note_does_not_justify_a_work_unit(self):
        # confirmed#2 refuted, confirmed#3 unresolved, the hardening note on
        # confirmed#3's hash verified correct: nothing real to fix.
        sidecars = self.sidecars()
        sidecars["u2crypto"]["locations"] = [
            _loc(self.recs["confirmed#2"], "false_positive", None, condition_keys=["admin_only"]),
            _loc(self.recs["confirmed#3"], "manual_review"),
            _loc(self.recs["hardening#0"], "confirmed", "reaffirmed"),
        ]
        self.assertRule(self.violations(sidecars), 8, "u2crypto", "confirmed or changed")

    def test_rule12_confirmed_finding_in_a_triage_unit(self):
        sidecars = self.sidecars()
        s = sidecars["u2crypto"]
        s.update(disposition="triage", severity_after=None, unit_file="triage-u2crypto-token-storage.md")
        (self.tickets_root / s["unit_file"]).write_text("synthetic\n", encoding="utf-8")
        self.addCleanup((self.tickets_root / s["unit_file"]).unlink)
        v = self.violations(sidecars)
        self.assertRule(v, 12, "u2crypto/confirmed#2", "status confirmed", "Phase 4.5")
        self.assertRule(v, 12, "u2crypto/confirmed#3", "status changed")
        self.assertFalse([x for x in v if "rule 12:" in x and "hardening#0" in x], msg=v)

    def test_rule12_confirmed_lead_in_a_triage_unit(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["triageleads"], "needs_validation#2").update(status="confirmed", verdict_candidate="reaffirmed")
        v = self.violations(sidecars)
        self.assertRule(v, 12, "triageleads/needs_validation#2", "needs_validation")
        self.assertEqual([x for x in v if "rule 12:" not in x], [])

    def test_rule12_confirmed_hardening_note_may_stay_in_triage(self):
        sidecars = self.sidecars()
        loc = self.loc_of(sidecars["triageleads"], "hardening#1")
        loc.update(status="confirmed", verdict_candidate="reaffirmed", condition_keys=[])
        self.assertEqual(self.violations(sidecars), [])

    def test_promoted_lead_is_a_valid_work_unit(self):
        sidecars = self.sidecars()
        name = "high-triageleads-promoted-lead.md"
        (self.tickets_root / name).write_text("synthetic\n", encoding="utf-8")
        self.addCleanup((self.tickets_root / name).unlink)
        s = sidecars["triageleads"]
        s.update(disposition="work_unit", unit_file=name, severity_before=None, severity_after="High")
        self.loc_of(s, "needs_validation#2").update(status="confirmed", verdict_candidate="reaffirmed")
        # The old triage file is now unclaimed -> rule 11, not a sidecar fault.
        v = self.violations(sidecars)
        self.assertEqual([x for x in v if "rule 11" not in x], [])

    def test_rule9_triage_needs_null_severity_and_triage_prefix(self):
        sidecars = self.sidecars()
        sidecars["triageleads"]["severity_after"] = "Low"
        sidecars["u2crypto"]["disposition"] = "triage"
        sidecars["u2crypto"]["severity_after"] = None
        v = self.violations(sidecars)
        self.assertRule(v, 9, "triageleads", "severity_after")
        self.assertRule(v, 9, "u2crypto", "prefix")

    def test_rule10_unit_file_missing_malformed_or_shared(self):
        sidecars = self.sidecars()
        sidecars["u1injection"]["unit_file"] = "med-u1injection-not-written.md"
        sidecars["u2crypto"]["unit_file"] = "High u2crypto.md"
        sidecars["triageleads"]["unit_file"] = UNIT_FILES["triagemanual"]
        v = self.violations(sidecars)
        self.assertRule(v, 10, "u1injection", "does not exist")
        self.assertRule(v, 10, "u2crypto", "basename")
        self.assertRule(v, 10, "triageleads", "names unit_id")
        self.assertRule(v, 10, "claimed by more than one")

    def test_rule11_orphan_unit_file_only_when_nothing_pending(self):
        orphan = self.tickets_root / "low-stale-leftover.md"
        orphan.write_text("stale\n", encoding="utf-8")
        self.addCleanup(orphan.unlink)
        self.assertRule(self.violations(self.sidecars()), 11, "low-stale-leftover.md")

        # A pending unit may already have written its file: no orphan call yet.
        sidecars = self.sidecars()
        del sidecars["triageleads"]
        self.assertEqual(self.violations(sidecars), [])

    def test_unit_file_written_sidecar_missing_is_pending_not_orphan(self):
        sidecars = self.sidecars()
        del sidecars["u2crypto"]
        self.assertEqual(self.violations(sidecars), [])
        self.assertEqual(bi.pending_units(sidecars, self.grouping), ["u2crypto"])

    def test_all_violations_reported_at_once(self):
        sidecars = self.sidecars()
        sidecars["triageleads"]["severity_before"] = "—"
        self.loc_of(sidecars["u1injection"], "confirmed#1")["condition_keys"] = ["bogus"]
        v = self.violations(sidecars)
        self.assertRule(v, 2, "triageleads")
        self.assertRule(v, 7, "u1injection")


# ---------------------------------------------------------------------------
# emit_verdicts.
# ---------------------------------------------------------------------------


def _bare(*locs, unit="u") -> dict:
    return {unit: {"locations": list(locs)}}


class EmitVerdictsTests(_E2EFixture):
    def test_valid_set_hand_back(self):
        result = bi.emit_verdicts(self.records, self.sidecars())
        by_hash = {e["sink_hash"]: e for e in result["verdicts"]}
        self.assertEqual(
            {h: e["verdict"] for h, e in by_hash.items()},
            {"b55e8630": "reaffirmed", "809bd41e": "reaffirmed", "116a9474": "reaffirmed", "2395c9e0": "rejected"},
        )
        self.assertEqual(by_hash["2395c9e0"]["refute_file"], "src/Misc.php")
        self.assertEqual(by_hash["2395c9e0"]["refute_line"], 2)
        self.assertEqual(by_hash["b55e8630"]["condition_keys"], ["internal_network_only"])
        self.assertTrue(all(e["source"] == "audit-triage" for e in result["verdicts"]))
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(result["withheld"], ["33c924c1", "c79c6e5e", "cb6923b3"])
        self.assertEqual([e["sink_hash"] for e in result["verdicts"]], sorted(by_hash))

    def test_hash_with_an_unverified_record_is_withheld(self):
        # confirmed#1 reaffirmed, needs_validation#0 (same 809bd41e) sits in
        # a unit with no sidecar yet: the hash is not decided.
        sidecars = _bare(_loc(self.recs["confirmed#1"], "confirmed", "reaffirmed"))
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertEqual(result["verdicts"], [])
        self.assertIn("809bd41e", result["withheld"])

    def test_nv_rejected_vs_confirmed_manual_review_in_another_unit_is_withheld(self):
        sidecars = {
            **_bare(_loc(self.recs["needs_validation#0"], "false_positive", "rejected", refute_file="src/Repo.php", refute_line=1), unit="a"),
            **_bare(_loc(self.recs["confirmed#1"], "manual_review"), unit="b"),
        }
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertNotIn("809bd41e", [e["sink_hash"] for e in result["verdicts"]])
        self.assertIn("809bd41e", result["withheld"])
        self.assertNotIn("809bd41e", result["conflicts"])

    def test_nv_rejected_vs_confirmed_confirmed_is_a_conflict(self):
        sidecars = {
            **_bare(_loc(self.recs["needs_validation#0"], "false_positive", "rejected", refute_file="src/Repo.php", refute_line=1), unit="a"),
            **_bare(_loc(self.recs["confirmed#1"], "confirmed", "reaffirmed"), unit="b"),
        }
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertEqual(result["conflicts"], ["809bd41e"])
        self.assertEqual(result["verdicts"], [])

    def test_changed_vs_false_positive_is_a_conflict(self):
        sidecars = _bare(
            _loc(self.recs["confirmed#1"], "changed"),
            _loc(self.recs["needs_validation#0"], "false_positive", None, condition_keys=["admin_only"]),
        )
        self.assertEqual(bi.emit_verdicts(self.records, sidecars)["conflicts"], ["809bd41e"])

    def test_confirmed_hardening_note_does_not_block_a_rejection(self):
        # confirmed#3 and hardening#0 share 33c924c1.
        sidecars = _bare(
            _loc(self.recs["confirmed#3"], "false_positive", "rejected", refute_file="src/Token.php", refute_line=1),
            _loc(self.recs["hardening#0"], "confirmed", "reaffirmed"),
        )
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(
            [(e["sink_hash"], e["verdict"]) for e in result["verdicts"]], [("33c924c1", "rejected")]
        )

    def test_hardening_status_never_votes_on_the_finding(self):
        # An unverified hardening note does not hold the finding's verdict
        # back, and a false_positive one does not conflict with it.
        for hardening_loc in ([], [_loc(self.recs["hardening#0"], "false_positive", None, condition_keys=["admin_only"])]):
            sidecars = _bare(_loc(self.recs["confirmed#3"], "confirmed", "reaffirmed"), *hardening_loc)
            result = bi.emit_verdicts(self.records, sidecars)
            self.assertEqual([(e["sink_hash"], e["verdict"]) for e in result["verdicts"]], [("33c924c1", "reaffirmed")])

    def test_hardening_only_hash_is_withheld(self):
        # cb6923b3 is carried by hardening#1 alone.
        sidecars = _bare(_loc(self.recs["hardening#1"], "confirmed", "reaffirmed"))
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertEqual(result["verdicts"], [])
        self.assertIn("cb6923b3", result["withheld"])

    def test_false_positive_closed_outside_repo_is_withheld(self):
        sidecars = _bare(_loc(self.recs["hardening#1"], "false_positive", None, condition_keys=["admin_only"]))
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertEqual(result["verdicts"], [])
        self.assertIn("cb6923b3", result["withheld"])

    def test_rejected_mixed_with_false_positive_null_is_withheld(self):
        sidecars = _bare(
            _loc(self.recs["confirmed#4"], "false_positive", "rejected", refute_file="src/Misc.php", refute_line=2),
            _loc(self.recs["needs_validation#1"], "false_positive", None, condition_keys=["admin_only"]),
        )
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertEqual(result["verdicts"], [])
        self.assertIn("2395c9e0", result["withheld"])

    def test_nohash00_never_emitted(self):
        sidecars = _bare(_loc(self.recs["needs_validation#2"], "confirmed", "reaffirmed"))
        result = bi.emit_verdicts(self.records, sidecars)
        self.assertNotIn("nohash00", json.dumps(result))

    def test_unknown_condition_key_dropped_known_kept_and_unioned(self):
        sidecars = _bare(
            _loc(self.recs["confirmed#1"], "confirmed", "reaffirmed", condition_keys=["admin_only", "not_a_real_key"]),
            _loc(self.recs["needs_validation#0"], "confirmed", "reaffirmed", condition_keys=["internal_network_only"]),
        )
        entry = bi.emit_verdicts(self.records, sidecars)["verdicts"][0]
        self.assertEqual(entry["condition_keys"], ["admin_only", "internal_network_only"])

    def test_reaffirmed_never_carries_refute(self):
        loc = _loc(self.recs["confirmed#2"], "confirmed", "reaffirmed", refute_file="src/Token.php", refute_line=1)
        entry = bi.emit_verdicts(self.records, _bare(loc))["verdicts"][0]
        self.assertNotIn("refute_file", entry)
        self.assertNotIn("refute_line", entry)

    def test_location_citing_the_wrong_hash_counts_as_unverified(self):
        loc = _loc(self.recs["confirmed#2"], "confirmed", "reaffirmed")
        loc["sink_hash"] = "33c924c1"
        result = bi.emit_verdicts(self.records, _bare(loc))
        self.assertEqual(result["verdicts"], [])


class EmitVerdictsBucketTests(unittest.TestCase):
    """Two needs_validation records share `ece1e87f` with different sink_kind
    (bucket fixture; precondition in test_fixtures_buckets.py)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.records = pf.load(fixtures_lib.build_bucket_review_root(Path(cls.tmp.name) / "review"))
        cls.pair = [r for r in cls.records if r.sink_hash == "ece1e87f"]
        assert len(cls.pair) == 2, cls.pair

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_two_nv_same_hash_same_refute_is_one_verdict(self):
        locs = [_loc(r, "false_positive", "rejected", refute_file="src/Example/Guard.php", refute_line=3) for r in self.pair]
        result = bi.emit_verdicts(self.records, _bare(*locs))
        self.assertEqual(
            result["verdicts"],
            [{"sink_hash": "ece1e87f", "verdict": "rejected", "source": "audit-triage",
              "refute_file": "src/Example/Guard.php", "refute_line": 3}],
        )

    def test_two_nv_same_hash_different_refute_is_a_conflict(self):
        locs = [
            _loc(r, "false_positive", "rejected", refute_file="src/Example/Guard.php", refute_line=line)
            for r, line in zip(self.pair, (3, 4))
        ]
        result = bi.emit_verdicts(self.records, _bare(*locs))
        self.assertEqual(result["verdicts"], [])
        self.assertEqual(result["conflicts"], ["ece1e87f"])

    def test_one_of_the_pair_unverified_is_withheld(self):
        loc = _loc(self.pair[0], "false_positive", "rejected", refute_file="src/Example/Guard.php", refute_line=3)
        result = bi.emit_verdicts(self.records, _bare(loc))
        self.assertEqual(result["verdicts"], [])
        self.assertIn("ece1e87f", result["withheld"])


# ---------------------------------------------------------------------------
# emit_index.
# ---------------------------------------------------------------------------


def _section(text: str, heading: str) -> str:
    start = text.index(f"## {heading}")
    nxt = text.find("\n## ", start + 1)
    return text[start : nxt if nxt != -1 else len(text)]


def _trace_rows(text: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in _section(text, "Traceability").splitlines():
        if line.startswith("| `"):
            cells = [c.strip() for c in line.strip("|").split(" | ")]
            rows[cells[0].strip("`")] = cells
    return rows


TRACE_COLUMNS = ["record_id", "sink_hash", "verdict", "location", "unit_file", "status", "condition_keys", "flags", "matched_to", "discovered_via"]


class EmitIndexTests(_E2EFixture):
    HEADER = {
        "audit_root": "/synthetic/review",
        "findings_json_sha256": "0" * 64,
        "project_root": "/synthetic/project",
        "project_root_resolved": [5, 6],
    }

    def index(self, sidecars=None, **kwargs) -> str:
        return bi.emit_index(
            self.records, self.grouping, self.sidecars() if sidecars is None else sidecars, header=self.HEADER, **kwargs
        )

    def test_every_record_has_its_own_traceability_row(self):
        rows = _trace_rows(self.index())
        self.assertEqual(set(rows), {r.record_id for r in self.records})
        for r in self.records:
            self.assertEqual(rows[r.record_id][1], f"`{r.sink_hash}`")

    def test_records_sharing_a_hash_keep_their_own_status(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["u1injection"], "needs_validation#0").update(status="manual_review", verdict_candidate=None)
        rows = _trace_rows(self.index(sidecars))
        status = TRACE_COLUMNS.index("status")
        self.assertEqual(rows["confirmed#1"][status], "confirmed")
        self.assertEqual(rows["needs_validation#0"][status], "manual_review")
        self.assertEqual(rows["confirmed#3"][status], "changed")
        self.assertEqual(rows["hardening#0"][status], "manual_review")

    def test_traceability_carries_unit_file_and_verified_condition_keys(self):
        rows = _trace_rows(self.index())
        self.assertEqual(rows["confirmed#0"][TRACE_COLUMNS.index("unit_file")], f"`{UNIT_FILES['u1injection']}`")
        self.assertEqual(rows["confirmed#0"][TRACE_COLUMNS.index("condition_keys")], "— → internal_network_only")
        self.assertEqual(rows["confirmed#0"][TRACE_COLUMNS.index("discovered_via")], "checklist:injection.md")

    def test_traceability_flags_and_matched_to_from_the_e2e_fixture(self):
        rows = _trace_rows(self.index())
        self.assertIn("[MERGED_DESPITE_HASH_MISMATCH]", rows["confirmed#1"][TRACE_COLUMNS.index("flags")])
        self.assertEqual(rows["needs_validation#0"][TRACE_COLUMNS.index("matched_to")], "b55e8630")

    def test_traceability_shows_the_actual_location_of_a_changed_record(self):
        sidecars = self.sidecars()
        r = self.recs["confirmed#3"]
        self.loc_of(sidecars["u2crypto"], "confirmed#3").update(sink_file="src/Moved.php", sink_line=r.sink_line + 7)
        rows = _trace_rows(self.index(sidecars))
        col = TRACE_COLUMNS.index("location")
        self.assertEqual(rows["confirmed#3"][col], f"`{r.sink_file}:{r.sink_line} → src/Moved.php:{r.sink_line + 7}`")
        # Unchanged location: the audit one alone.
        r0 = self.recs["confirmed#0"]
        self.assertEqual(rows["confirmed#0"][col], f"`{r0.sink_file}:{r0.sink_line}`")

    def test_triage_units_not_in_work_units(self):
        text = self.index()
        work = _section(text, "Work units")
        triage = _section(text, "Triage")
        for u in ("u1injection", "u2crypto"):
            self.assertIn(UNIT_FILES[u], work)
            self.assertNotIn(UNIT_FILES[u], triage)
        for u in ("triagemanual", "triageleads"):
            self.assertIn(UNIT_FILES[u], triage)
            self.assertNotIn(UNIT_FILES[u], work)

    def test_triage_section_lists_each_record_with_status_and_note(self):
        triage = _section(self.index(), "Triage")
        self.assertIn("`hardening#1` hardening `src/Unrelated.php:99`", triage)
        self.assertIn("**false_positive**: closed by the ingress (synthetic)", triage)
        self.assertIn("`needs_validation#1` needs_validation", triage)

    def test_work_unit_row_shows_severity_history_and_status_counts(self):
        work = _section(self.index(), "Work units")
        row = next(l for l in work.splitlines() if UNIT_FILES["u1injection"] in l)
        self.assertIn("Critical → Medium", row)
        self.assertIn("confirmed 3", row)
        row = next(l for l in work.splitlines() if UNIT_FILES["u2crypto"] in l)
        self.assertIn("confirmed 1, changed 1, manual_review 1", row)

    def test_severity_history_lists_only_changed_units_with_rationale(self):
        history = _section(self.index(), "Severity history")
        self.assertIn(UNIT_FILES["u1injection"], history)
        self.assertIn("reachable from the internal network only", history)
        self.assertIn(UNIT_FILES["triagemanual"], history)  # High -> null (re-filed as triage)
        self.assertNotIn(UNIT_FILES["u2crypto"], history)
        self.assertNotIn(UNIT_FILES["triageleads"], history)  # null -> null

    def test_priority_column_only_with_config(self):
        self.assertNotIn("Priority", _section(self.index(), "Work units"))
        self.assertNotIn("Tracker priority", self.index())
        pmap = {"crit": "P0", "high": "P1", "med": "P2", "low": "P3", "triage": "P4"}
        text = self.index(priority_map=pmap)
        work = _section(text, "Work units")
        self.assertIn("Priority", work)
        self.assertIn("| P2 |", next(l for l in work.splitlines() if UNIT_FILES["u1injection"] in l))
        self.assertIn("| P1 |", next(l for l in work.splitlines() if UNIT_FILES["u2crypto"] in l))
        self.assertIn("Tracker priority: P4", _section(text, "Triage"))

    def test_header(self):
        text = self.index()
        self.assertIn("- project_root: `/synthetic/project` (sink files resolved: 5/6)", text)
        self.assertIn(f"- findings_json_sha256: `{'0' * 64}`", text)
        self.assertIn("- records: confirmed 6, needs_validation 3, hardening 2", text)
        self.assertIn("- units: work_unit 2, triage 2, pending 0", text)

    def test_pending_unit_listed_and_traced_as_pending(self):
        sidecars = self.sidecars()
        del sidecars["triageleads"]
        text = self.index(sidecars)
        self.assertIn("- `triageleads` — 2 record(s)", _section(text, "Pending verification"))
        rows = _trace_rows(text)
        self.assertEqual(rows["hardening#1"][TRACE_COLUMNS.index("status")], "pending")
        self.assertEqual(rows["hardening#1"][TRACE_COLUMNS.index("unit_file")], "`triageleads` (pending)")
        self.assertIn("pending 1", text)

    def test_hand_back_section_counts_conflicts_and_withheld(self):
        sidecars = self.sidecars()
        self.loc_of(sidecars["u1injection"], "needs_validation#0").update(
            status="false_positive", verdict_candidate="rejected", refute_file="src/Repo.php", refute_line=1
        )
        hand_back = _section(self.index(sidecars), "Verdict hand-back")
        self.assertIn("- Sent: 3 (reaffirmed 2, rejected 1)", hand_back)
        self.assertIn("Conflicts", hand_back)
        self.assertIn("  - `809bd41e`: `confirmed#1`, `needs_validation#0`", hand_back)
        self.assertIn("- Withheld (not sent, not an error): 3", hand_back)

    def test_no_prior_resolution_section_on_a_fresh_run(self):
        self.assertFalse(any(r.prior_resolution for r in self.records))
        self.assertNotIn("## Prior-run resolutions", self.index())


class EmitIndexBucketTests(unittest.TestCase):
    def test_attached_without_hash_flag_and_matched_to_in_traceability(self):
        with tempfile.TemporaryDirectory() as td:
            records = pf.load(fixtures_lib.build_bucket_review_root(Path(td) / "review"))
        flagged = [r for r in records if "[ATTACHED_WITHOUT_HASH]" in r.flags]
        self.assertTrue(flagged, msg="bucket fixture precondition -- see test_fixtures_buckets.py")
        grouping = {"triagebucket": [r.record_id for r in records]}
        rows = _trace_rows(bi.emit_index(records, grouping, {}, header={}))
        for r in flagged:
            self.assertIn("[ATTACHED_WITHOUT_HASH]", rows[r.record_id][TRACE_COLUMNS.index("flags")])
            self.assertEqual(rows[r.record_id][TRACE_COLUMNS.index("matched_to")], r.matched_to)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _run_bi(argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = bi.main(argv)
    return rc, out.getvalue(), err.getvalue()


class BuildIndexCliTests(unittest.TestCase):
    """Writes `.work/parsed.json` directly (parse_findings.py's persisted
    shape incl. `project_root`), so these tests don't depend on Phase 1's CLI."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.review_root = fixtures_lib.build_review_root(base / "review")
        self.records = pf.load(self.review_root)
        self.recs = {r.record_id: r for r in self.records}
        self.project_root = fixtures_lib.build_project_tree(base / "project", PROJECT_FILES)
        self.tickets_root = base / "tickets"
        self.work = self.tickets_root / ".work"
        self.work.mkdir(parents=True)

    def prepare(self, sidecars: dict | None = None, *, project_root=True, grouping=None):
        parsed = {
            "schema_version": 1,
            "audit_root": str(self.review_root),
            "findings_json_sha256": pf.findings_json_sha256(self.review_root),
            "records": [r.to_dict() for r in self.records],
        }
        if project_root:
            parsed["project_root"] = str(self.project_root)
            parsed["project_root_resolved"] = [5, 5]
        (self.work / "parsed.json").write_text(json.dumps(parsed), encoding="utf-8")
        (self.work / "grouping.json").write_text(json.dumps(grouping or fixtures_lib.FULL_GROUPING), encoding="utf-8")
        sidecars = valid_sidecars(self.recs) if sidecars is None else sidecars
        verify = self.work / "verify"
        verify.mkdir(exist_ok=True)
        for unit_id, sidecar in sidecars.items():
            (verify / f"{unit_id}.json").write_text(json.dumps(sidecar), encoding="utf-8")
            (self.tickets_root / sidecar["unit_file"]).write_text("synthetic\n", encoding="utf-8")

    def outputs_exist(self) -> tuple[bool, bool]:
        return (self.tickets_root / "INDEX.md").exists(), (self.work / "verdicts.json").exists()

    def test_valid_run_writes_both_and_the_engine_accepts_the_verdicts(self):
        self.prepare()
        rc, out, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 0, msg=err)
        self.assertEqual(self.outputs_exist(), (True, True))
        payload = json.loads((self.work / "verdicts.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["findings_json_sha256"], pf.findings_json_sha256(self.review_root))
        self.assertEqual(
            sorted((e["sink_hash"], e["verdict"]) for e in payload["verdicts"]),
            [("116a9474", "reaffirmed"), ("2395c9e0", "rejected"), ("809bd41e", "reaffirmed"), ("b55e8630", "reaffirmed")],
        )
        result = fixtures_lib.run_dedupe(
            self.review_root, "--verdicts-in", str(self.work / "verdicts.json"), "--project-root", str(self.project_root)
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_violation_exits_2_and_writes_neither_output(self):
        sidecars = valid_sidecars(self.recs)
        sidecars["triageleads"]["severity_before"] = "—"
        sidecars["u2crypto"]["locations"].pop()
        self.prepare(sidecars)
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 2)
        self.assertEqual(self.outputs_exist(), (False, False))
        self.assertIn("rule 2:", err)
        # A previous run's outputs are left as they were, not rewritten.
        (self.tickets_root / "INDEX.md").write_text("previous run\n", encoding="utf-8")
        rc, _, _ = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 2)
        self.assertEqual((self.tickets_root / "INDEX.md").read_text(encoding="utf-8"), "previous run\n")
        self.assertIn("rule 3:", err)

    def test_pending_unit_is_a_warning_exit_0(self):
        sidecars = valid_sidecars(self.recs)
        del sidecars["triageleads"]
        self.prepare(sidecars)
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 0, msg=err)
        self.assertIn("pending verification", err)
        self.assertIn("triageleads", (self.tickets_root / "INDEX.md").read_text(encoding="utf-8"))

    def test_corrupt_sidecar_is_a_violation(self):
        self.prepare()
        (self.work / "verify" / "u2crypto.json").write_text("{not json", encoding="utf-8")
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 2)
        self.assertIn("u2crypto: rule 2:", err)
        self.assertEqual(self.outputs_exist(), (False, False))

    def test_conflict_exits_0_and_is_not_handed_back(self):
        sidecars = valid_sidecars(self.recs)
        loc = next(l for l in sidecars["u1injection"]["locations"] if l["record_id"] == "needs_validation#0")
        loc.update(status="false_positive", verdict_candidate="rejected", refute_file="src/Repo.php", refute_line=1)
        self.prepare(sidecars)
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 0, msg=err)
        self.assertIn("809bd41e", err)
        payload = json.loads((self.work / "verdicts.json").read_text(encoding="utf-8"))
        self.assertNotIn("809bd41e", [e["sink_hash"] for e in payload["verdicts"]])

    def test_missing_project_root_fails_only_on_rejected(self):
        self.prepare(project_root=False)
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 2)
        self.assertIn("project_root unknown", err)

    def test_config_adds_priority_column(self):
        self.prepare()
        rc, _, err = _run_bi([str(self.tickets_root), "--config", str(EXAMPLE_CONFIG)])
        self.assertEqual(rc, 0, msg=err)
        text = (self.tickets_root / "INDEX.md").read_text(encoding="utf-8")
        work = _section(text, "Work units")
        self.assertIn("| blocker |", next(l for l in work.splitlines() if UNIT_FILES["u2crypto"] in l))
        self.assertIn("| normal |", next(l for l in work.splitlines() if UNIT_FILES["u1injection"] in l))
        self.assertIn("Tracker priority: minor", text)

    def test_bad_config_exits_2(self):
        self.prepare()
        cfg = Path(self.tmp.name) / "cfg.json"
        cfg.write_text(json.dumps({"severity_to_priority": {"crit": "x", "high": "y", "medium": "z"}}), encoding="utf-8")
        rc, _, err = _run_bi([str(self.tickets_root), "--config", str(cfg)])
        self.assertEqual(rc, 2)
        self.assertIn("severity_to_priority.med", err)
        self.assertIn("triage_bucket_priority", err)
        self.assertEqual(self.outputs_exist(), (False, False))

    def test_grouping_edited_after_phase_3_is_rechecked(self):
        grouping = copy.deepcopy(fixtures_lib.FULL_GROUPING)
        grouping["triageleads"].remove("hardening#1")
        sidecars = valid_sidecars(self.recs)
        sidecars["triageleads"]["locations"].pop()
        self.prepare(sidecars, grouping=grouping)
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 2)
        self.assertIn("orphan", err)

    def test_malformed_grouping_exits_2_without_a_traceback(self):
        # parse_findings.assert_full_coverage reports these as CoverageError,
        # naming the offending unit.
        base = copy.deepcopy(fixtures_lib.FULL_GROUPING)
        cases = {
            "non-string element": ({**base, "u1injection": [*base["u1injection"], {"record_id": "confirmed#0"}]}, "u1injection"),
            "non-list value": ({**base, "extra": 7}, "extra (int)"),
            "empty group": ({**base, "emptyunit": []}, "emptyunit"),
        }
        for name, (grouping, unit_fragment) in cases.items():
            with self.subTest(name):
                for p in (self.tickets_root / "INDEX.md", self.work / "verdicts.json"):
                    p.unlink(missing_ok=True)
                self.prepare(grouping=grouping)
                rc, _, err = _run_bi([str(self.tickets_root)])
                self.assertEqual(rc, 2, msg=err)
                self.assertIn("coverage check failed", err)
                self.assertIn(unit_fragment, err)
                self.assertEqual(self.outputs_exist(), (False, False))

    def test_missing_parsed_json_fails_loudly(self):
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 2)
        self.assertIn("parsed.json not found", err)

    def test_missing_grouping_fails_loudly(self):
        self.prepare()
        (self.work / "grouping.json").unlink()
        rc, _, err = _run_bi([str(self.tickets_root)])
        self.assertEqual(rc, 2)
        self.assertIn("grouping.json not found", err)


class FullCliChainTests(unittest.TestCase):
    """`--check-only` -> step 0.3 -> Phase 1 -> grouping -> Phase 3 -> v2
    sidecars -> build_index -> the engine's real `--verdicts-in`. Depends on
    parse_findings.py's `--check-only` / `--project-root` / persisted
    `project_root`."""

    def test_full_cli_chain(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            review_root = fixtures_lib.build_review_root(base / "review")
            project_root = fixtures_lib.build_project_tree(base / "project", PROJECT_FILES)
            tickets_root = base / "tickets"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = pf.main([str(review_root), "--tickets-root", str(tickets_root), "--check-only"])
            self.assertEqual(rc, 0)
            self.assertFalse(tickets_root.exists(), msg="--check-only must not write")

            (tickets_root / ".work").mkdir(parents=True)  # step 0.3
            (tickets_root / ".gitignore").write_text("*\n", encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                rc = pf.main([str(review_root), "--tickets-root", str(tickets_root), "--project-root", str(project_root)])
            self.assertEqual(rc, 0)
            parsed = json.loads((tickets_root / ".work" / "parsed.json").read_text(encoding="utf-8"))
            self.assertEqual(Path(parsed["project_root"]).resolve(), project_root.resolve())

            grouping_path = tickets_root / ".work" / "grouping.json"
            grouping_path.write_text(json.dumps(fixtures_lib.FULL_GROUPING), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                rc = pf.main([str(review_root), "--tickets-root", str(tickets_root), "--grouping", str(grouping_path)])
            self.assertEqual(rc, 0)

            recs = {r.record_id: r for r in pf.load(review_root)}
            verify = tickets_root / ".work" / "verify"
            verify.mkdir()
            for unit_id, sidecar in valid_sidecars(recs).items():
                (verify / f"{unit_id}.json").write_text(json.dumps(sidecar), encoding="utf-8")
                (tickets_root / sidecar["unit_file"]).write_text("synthetic\n", encoding="utf-8")

            rc, _, err = _run_bi([str(tickets_root)])
            self.assertEqual(rc, 0, msg=err)
            index_text = (tickets_root / "INDEX.md").read_text(encoding="utf-8")
            for rid in recs:
                self.assertIn(f"`{rid}`", index_text)

            result = fixtures_lib.run_dedupe(
                review_root, "--verdicts-in", str(tickets_root / ".work" / "verdicts.json"),
                "--project-root", str(project_root),
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
