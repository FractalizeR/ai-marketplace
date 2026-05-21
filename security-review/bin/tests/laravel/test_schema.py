"""Schema-shape tests for Wave 2-E Laravel recon_bags.* keys.

Validates:
  * `routes_authz_matrix`, `sensitive_columns`, `runtime` are declared in
    `RECON_BAGS_SCHEMA`.
  * Each section has the exact set of allowed item_keys / data_keys per the
    contract in NEXT_RELEASE_PLAN.md.
  * All three sections are optional (`required=False`) — Wave 2.5 sync-step
    will tighten `required` once consumers can rely on them.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PLUGIN_BIN = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PLUGIN_BIN))

from recon.recipes import laravel  # noqa: E402


class FrameworkSpecificSchemaWave2ETests(unittest.TestCase):
    def test_three_new_sections_in_schema(self):
        schema = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]
        self.assertIn("routes_authz_matrix", schema)
        self.assertIn("sensitive_columns", schema)
        self.assertIn("runtime", schema)

    def test_three_new_sections_are_optional(self):
        schema = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]
        for key in ("routes_authz_matrix", "sensitive_columns", "runtime"):
            self.assertFalse(
                schema[key].required,
                msg=f"{key} must be optional during Wave 2 transition",
            )

    def test_routes_authz_matrix_item_keys(self):
        spec = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]["routes_authz_matrix"]
        self.assertEqual(spec.shape, "list")
        self.assertEqual(
            spec.item_keys,
            frozenset({
                "route_name", "file", "line", "methods", "path",
                "effective_middleware", "matched_access_control", "firewall",
                "csrf_protection", "authz_evidence",
            }),
        )

    def test_sensitive_columns_item_keys(self):
        spec = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]["sensitive_columns"]
        self.assertEqual(spec.shape, "list")
        self.assertEqual(
            spec.item_keys,
            frozenset({
                "entity_class", "file", "field_name", "column_type",
                "name_pattern_matched", "encryption_status", "encryption_evidence",
            }),
        )

    def test_runtime_data_keys(self):
        spec = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]["runtime"]
        self.assertEqual(spec.shape, "scalar")
        self.assertEqual(spec.data_keys, frozenset({"octane", "octane_server"}))


class FutureKeysAllowlistConsistencyTests(unittest.TestCase):
    """Allowlist FUTURE_FRAMEWORK_KEYS_3_4 must be EMPTY after Wave 2.5.

    Wave 2-E declared `routes_authz_matrix`, `sensitive_columns`, `runtime`
    in laravel.RECON_BAGS_SCHEMA (and Wave 2-D the first two for
    symfony). With both recipes carrying the keys, the transitional bridge
    is no longer needed; the allowlist is shrunk to ∅. This test guards
    against accidental re-introduction of obsolete entries.
    """

    def test_allowlist_emptied(self):
        from validate_context import FUTURE_FRAMEWORK_KEYS_3_4
        self.assertEqual(
            FUTURE_FRAMEWORK_KEYS_3_4,
            frozenset(),
            msg="FUTURE_FRAMEWORK_KEYS_3_4 must remain empty — Wave 2 closed "
                "the 3.4.0 transitional window.",
        )


if __name__ == "__main__":
    unittest.main()
