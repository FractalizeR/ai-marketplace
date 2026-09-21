"""Dedicated schema-leak regression test for `build_index.emit_verdicts`.

README.md ("The verdict hand-back"): `.work/verdicts.json` may carry
`sink_hash`/`verdict`/`source`/`condition_keys`/`refute_file`/`refute_line`
ONLY -- never free text. The rationale lives in `.work/`-sidecars and
`INDEX.md`, which never leave the local working tree; `.findings_state.json`
(which stores these verdicts on the audit side) outlives individual runs and
someone will eventually `git add -f` it.

This test must fail loudly the moment `emit_verdicts` starts copying a
free-text field through -- see the task's DoD #5 for the manual red/green
demonstration (temporarily add a leaking field to
`build_index._location_verdict_entry`, run this file, observe the failure,
revert). What ships here is the permanent, always-green guard.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import build_index as bi  # noqa: E402

_ALLOWED_KEYS = frozenset({"sink_hash", "verdict", "source", "condition_keys", "refute_file", "refute_line"})

# A distinctive marker that must never survive into the emitted JSON, no
# matter which field of the sidecar it is smuggled through.
_LEAK_MARKER = "RATIONALE-LEAK-MARKER-4f8c1e"


def _poisoned_sidecar() -> dict:
    """A sidecar with the marker planted in every free-text field the real
    triage-verify.md sidecar schema defines (severity_change_rationale,
    fix_pattern_note, and a location's own `note`) plus an out-of-schema
    field on the location, to also catch a future accidental widening of
    the location shape."""
    return {
        "unit_id": "u-poisoned",
        "severity_before": "High",
        "severity_after": "Medium",
        "severity_change_rationale": _LEAK_MARKER,
        "fix_pattern_note": _LEAK_MARKER,
        "locations": [
            {
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


class NoFreeTextLeakTests(unittest.TestCase):
    def test_marker_absent_from_serialized_output(self):
        result = bi.emit_verdicts({"u-poisoned": _poisoned_sidecar()})
        serialized = json.dumps(result)
        self.assertNotIn(_LEAK_MARKER, serialized, msg="free-text rationale leaked into emit_verdicts() output")

    def test_every_entry_key_is_in_the_allowed_whitelist(self):
        result = bi.emit_verdicts({"u-poisoned": _poisoned_sidecar()})
        self.assertTrue(result["verdicts"], msg="fixture must actually produce an entry to be a meaningful check")
        for entry in result["verdicts"]:
            extra = set(entry) - _ALLOWED_KEYS
            self.assertFalse(extra, msg=f"entry has field(s) outside the accepted schema: {extra}")

    def test_multiple_sidecars_all_poisoned_still_clean(self):
        sidecars = {
            "u1": _poisoned_sidecar(),
            "u2": {**_poisoned_sidecar(), "locations": [
                {**_poisoned_sidecar()["locations"][0], "sink_hash": "cafebabe", "verdict_candidate": "reaffirmed"}
            ]},
        }
        result = bi.emit_verdicts(sidecars)
        self.assertNotIn(_LEAK_MARKER, json.dumps(result))

    def test_allowed_whitelist_matches_the_verdicts_in_contract(self):
        # Cross-check against the audit plugin's OWN accepted-field set
        # (security-review/bin/dedupe/state.py `_VERDICTS_IN_ENTRY_KEYS`) so
        # a widening on either side is caught, not just a leak.
        self.assertEqual(bi._VERDICT_ENTRY_ALLOWED_KEYS, _ALLOWED_KEYS)


if __name__ == "__main__":
    unittest.main()
