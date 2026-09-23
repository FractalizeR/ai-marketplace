"""Precondition test for `fixtures/buckets/*.md` -- the synthetic wave
fixture that exists solely to provoke two `attach_side_records` outcomes the
engine's own e2e fixture (borrowed read-only, see fixtures_lib.py) never
exercises:

  (a) a `needs_validation` record bound to a `confirmed` finding by location
      rather than by matching `sink_hash` -- `[ATTACHED_WITHOUT_HASH]` in
      `findings.json`.
  (b) two `needs_validation` records that share one `sink_hash` (identical
      `sink_snippet` -- `sink_hash` is a pure hash of the snippet, see
      `security-review/bin/dedupe/models.py::_sink_hash_from_snippet`) but
      disagree on `sink_kind`.

Both are run through the REAL `security-review/bin/dedupe_findings.py` CLI
(via `fixtures_lib.build_bucket_review_root`), not synthesized directly as
JSON -- so a future change to the engine's binding logic
(`pipeline.attach_side_records`) that stops producing either case makes
*this* precondition test fail loudly, instead of quietly hollowing out
whatever later test in audit-triage relies on `[ATTACHED_WITHOUT_HASH]` /
same-hash-different-kind existing in a real findings.json.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures_lib  # noqa: E402

FLAG_ATTACHED_WITHOUT_HASH = "[ATTACHED_WITHOUT_HASH]"


class BucketFixturePreconditionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = fixtures_lib.build_bucket_review_root(Path(cls.tmp.name) / "review")
        cls.findings = json.loads((cls.review_root / "findings.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_at_least_one_needs_validation_attached_without_hash(self):
        nv = self.findings["needs_validation"]
        flagged = [r for r in nv if FLAG_ATTACHED_WITHOUT_HASH in r.get("flags", [])]
        self.assertGreaterEqual(
            len(flagged), 1,
            msg=(
                f"expected at least one needs_validation record carrying "
                f"{FLAG_ATTACHED_WITHOUT_HASH!r} in findings.json; got flags "
                f"{[r.get('flags') for r in nv]}"
            ),
        )
        # It must actually be bound (matched_to set), not merely flagged --
        # the flag is set exactly when bound_by_hash is False, never on an
        # unmatched record (see pipeline.attach_side_records._mark).
        for r in flagged:
            self.assertIsNotNone(r["matched_to"], msg=f"{r} carries the flag but has no matched_to")

    def test_two_needs_validation_share_a_hash_with_different_sink_kind(self):
        nv = self.findings["needs_validation"]
        by_hash: dict[str, set[str]] = defaultdict(set)
        by_hash_records: dict[str, list[dict]] = defaultdict(list)
        for r in nv:
            by_hash[r["sink_hash"]].add(r["sink_kind"])
            by_hash_records[r["sink_hash"]].append(r)

        offending = {h: kinds for h, kinds in by_hash.items() if len(kinds) >= 2}
        self.assertTrue(
            offending,
            msg=(
                "expected at least one sink_hash shared by two needs_validation "
                f"records with different sink_kind; got needs_validation={nv}"
            ),
        )
        # At least two DISTINCT records (not just two distinct kinds counted
        # once) must carry that shared hash.
        sink_hash = next(iter(offending))
        self.assertGreaterEqual(len(by_hash_records[sink_hash]), 2)

    def test_no_confirmed_or_hardening_regression(self):
        # Sanity: the bucket fixture still parses to a non-trivial payload --
        # an empty confirmed list would mean the [ATTACHED_WITHOUT_HASH]
        # anchor finding silently failed to parse/merge.
        self.assertGreaterEqual(len(self.findings["confirmed"]), 1)
        self.assertGreaterEqual(len(self.findings["needs_validation"]), 3)


if __name__ == "__main__":
    unittest.main()
