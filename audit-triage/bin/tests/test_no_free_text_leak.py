"""Dedicated schema-leak regression test for `build_index.emit_verdicts`.

README.md ("The verdict hand-back"): `.work/verdicts.json` may carry
`sink_hash`/`verdict`/`source`/`condition_keys`/`refute_file`/`refute_line`
ONLY -- never free text. The rationale lives in `.work/`-sidecars and
`INDEX.md`, which never leave the local working tree; `.findings_state.json`
(which stores these verdicts on the audit side) outlives individual runs and
someone will eventually `git add -f` it.

This test must fail loudly the moment `emit_verdicts` starts copying a
free-text field through (e.g. a `note` added to the entry fields built in
`build_index._decide_hash`). What ships here is the permanent, always-green
guard.
"""

from __future__ import annotations

import functools
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import build_index as bi  # noqa: E402
from parse_findings import Record  # noqa: E402

_SECURITY_REVIEW_BIN = Path(__file__).resolve().parents[3] / "security-review" / "bin"


@functools.lru_cache(maxsize=None)
def _engine_verdicts_in_entry_keys() -> frozenset:
    """The audit engine's own accepted per-entry field set. Imports the
    engine's `dedupe` package (it stays in sys.modules; security-review/bin
    is removed from sys.path again). Nothing in it is called or written."""
    sys.path.insert(0, str(_SECURITY_REVIEW_BIN))
    try:
        from dedupe import state
    finally:
        sys.path.remove(str(_SECURITY_REVIEW_BIN))
    return frozenset(state._VERDICTS_IN_ENTRY_KEYS)

# A distinctive marker that must never survive into the emitted JSON, no
# matter which field of the sidecar it is smuggled through.
_LEAK_MARKER = "RATIONALE-LEAK-MARKER-4f8c1e"


def _record(record_id: str, sink_hash: str) -> Record:
    return Record(
        record_id=record_id,
        verdict=record_id.split("#")[0],
        sink_hash=sink_hash,
        sink_file="src/X.php",
        sink_line=1,
        sink_kind="dql_concat",
        root_cause_family="injection",
        enclosing_symbol="X::run",
    )


_RECORDS = [_record("confirmed#0", "deadbeef"), _record("confirmed#1", "cafebabe")]


def _poisoned_sidecar() -> dict:
    """A v2 sidecar with the marker planted in every free-text field the
    triage-verify.md sidecar contract defines (title,
    severity_change_rationale, fix_pattern_note, and a location's own `note`)
    plus an out-of-schema field on the location, to also catch a future
    accidental widening of the location shape."""
    return {
        "sidecar_version": 2,
        "unit_id": "upoisoned",
        "disposition": "triage",
        "title": _LEAK_MARKER,
        "unit_file": "triage-upoisoned-leak.md",
        "severity_before": "High",
        "severity_after": None,
        "severity_change_rationale": _LEAK_MARKER,
        "fix_pattern_note": _LEAK_MARKER,
        "locations": [
            {
                "record_id": "confirmed#0",
                "sink_hash": "deadbeef",
                "sink_file": "src/X.php",
                "sink_line": 1,
                "status": "false_positive",
                "note": _LEAK_MARKER,
                "condition_keys": ["admin_only"],
                "verdict_candidate": "rejected",
                "refute_file": "src/Y.php",
                "refute_line": 10,
                "rationale_text_field_that_should_not_exist": _LEAK_MARKER,
            }
        ],
    }


def _poisoned_confirmed_sidecar() -> dict:
    base = _poisoned_sidecar()
    loc = dict(base["locations"][0], record_id="confirmed#1", sink_hash="cafebabe", status="confirmed", verdict_candidate="reaffirmed")
    del loc["refute_file"], loc["refute_line"]
    return {**base, "unit_id": "uconfirmed", "locations": [loc]}


class NoFreeTextLeakTests(unittest.TestCase):
    def test_marker_absent_from_serialized_output(self):
        result = bi.emit_verdicts(_RECORDS, {"upoisoned": _poisoned_sidecar()})
        serialized = json.dumps(result)
        self.assertNotIn(_LEAK_MARKER, serialized, msg="free-text rationale leaked into emit_verdicts() output")

    def test_every_entry_key_is_in_the_allowed_whitelist(self):
        result = bi.emit_verdicts(_RECORDS, {"upoisoned": _poisoned_sidecar(), "uconfirmed": _poisoned_confirmed_sidecar()})
        self.assertEqual(len(result["verdicts"]), 2, msg="fixture must produce both a rejected and a reaffirmed entry")
        self.assertTrue(result["verdicts"], msg="fixture must actually produce an entry to be a meaningful check")
        for entry in result["verdicts"]:
            extra = set(entry) - _engine_verdicts_in_entry_keys()
            self.assertFalse(extra, msg=f"entry has field(s) outside the accepted schema: {extra}")

    def test_multiple_sidecars_all_poisoned_still_clean(self):
        sidecars = {"upoisoned": _poisoned_sidecar(), "uconfirmed": _poisoned_confirmed_sidecar()}
        result = bi.emit_verdicts(_RECORDS, sidecars)
        self.assertNotIn(_LEAK_MARKER, json.dumps(result))

    def test_emitted_index_is_allowed_free_text_but_verdicts_are_not(self):
        # INDEX.md is local (under .gitignore) and may carry notes; only
        # verdicts.json is the no-free-text boundary.
        sidecars = {"upoisoned": _poisoned_sidecar(), "uconfirmed": _poisoned_confirmed_sidecar()}
        grouping = {"upoisoned": ["confirmed#0"], "uconfirmed": ["confirmed#1"]}
        self.assertIn(_LEAK_MARKER, bi.emit_index(_RECORDS, grouping, sidecars, header={}))
        self.assertNotIn(_LEAK_MARKER, json.dumps(bi.emit_verdicts(_RECORDS, sidecars)))

    def test_engine_state_module_exists(self):
        self.assertTrue((_SECURITY_REVIEW_BIN / "dedupe" / "state.py").is_file())

    def test_allowed_whitelist_matches_the_verdicts_in_contract(self):
        # Against the audit plugin's OWN accepted-field set, so a widening
        # or narrowing on either side is caught, not just a leak.
        engine_keys = _engine_verdicts_in_entry_keys()
        self.assertTrue(engine_keys, msg="engine key set must not be empty")
        self.assertEqual(bi._VERDICT_ENTRY_ALLOWED_KEYS, engine_keys)


if __name__ == "__main__":
    unittest.main()
