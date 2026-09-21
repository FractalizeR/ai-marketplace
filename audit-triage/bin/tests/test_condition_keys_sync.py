"""Cross-plugin enum sync check: parse_findings.CONDITION_KEYS must mirror
security-review/bin/dedupe/models.py:CONDITION_KEYS byte-for-byte (README.md
Configuration: "the two plugins must be kept in sync the same way the audit
plugin's own sink_kind/root_cause_family enums are").

Read-only: loads the audit plugin's models.py via importlib (no sys.path
mutation of the shared `dedupe` package name, so this cannot collide with
security-review's own test suite if ever run in the same process) purely to
compare its CONDITION_KEYS constant. Never imports/executes anything else
from security-review, and never writes to security-review/.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import parse_findings as pf  # noqa: E402

_MODELS_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "security-review" / "bin" / "dedupe" / "models.py"
)


def _load_security_review_condition_keys() -> frozenset:
    spec = importlib.util.spec_from_file_location("_sr_models_sync_check", _MODELS_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses' own type-hint resolution looks the module up in
    # sys.modules while exec'ing it (needed under `from __future__ import
    # annotations`) -- register it first, then remove it again once loaded
    # so this stays a read-only, isolated peek, not a lasting import.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module.CONDITION_KEYS


class ConditionKeysSyncTests(unittest.TestCase):
    def test_source_file_exists(self):
        self.assertTrue(_MODELS_PATH.is_file(), msg=f"expected {_MODELS_PATH} to exist")

    def test_condition_keys_match_security_review(self):
        audit_plugin_keys = _load_security_review_condition_keys()
        self.assertEqual(
            pf.CONDITION_KEYS,
            audit_plugin_keys,
            msg=(
                "audit-triage/bin/parse_findings.py:CONDITION_KEYS has drifted from "
                "security-review/bin/dedupe/models.py:CONDITION_KEYS -- update the "
                "mirror in parse_findings.py (and README.md's mention of it) to match."
            ),
        )


if __name__ == "__main__":
    unittest.main()
