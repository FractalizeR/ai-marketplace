"""Wave 2-D (3.4.0) — schema declarations for new recon_bags keys.

Verifies that `routes_authz_matrix` and `sensitive_columns` are registered in
`RECON_BAGS_SCHEMA` with the contracted item_keys. These checks are
deliberately structural (no PHP runtime needed) so the schema invariant is
guarded even when the extractor isn't on PATH.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent.parent
sys.path.insert(0, str(BIN_DIR))

from recon.recipes import symfony as recipe_symfony  # noqa: E402


class RoutesAuthzMatrixSchema(unittest.TestCase):
    def test_section_registered(self) -> None:
        spec = recipe_symfony.RECON_BAGS_SCHEMA["stack"]["symfony"].get("routes_authz_matrix")
        self.assertIsNotNone(spec, "routes_authz_matrix must be in RECON_BAGS_SCHEMA")
        self.assertEqual(spec.shape, "list")
        self.assertFalse(spec.required, "routes_authz_matrix must be optional (3.4.0 transitional)")

    def test_item_keys_match_contract(self) -> None:
        spec = recipe_symfony.RECON_BAGS_SCHEMA["stack"]["symfony"]["routes_authz_matrix"]
        expected = frozenset({
            "route_name", "file", "line", "methods", "path",
            "effective_middleware", "matched_access_control", "firewall",
            "csrf_protection", "authz_evidence",
        })
        self.assertEqual(spec.item_keys, expected)


class SensitiveColumnsSchema(unittest.TestCase):
    def test_section_registered(self) -> None:
        spec = recipe_symfony.RECON_BAGS_SCHEMA["stack"]["symfony"].get("sensitive_columns")
        self.assertIsNotNone(spec, "sensitive_columns must be in RECON_BAGS_SCHEMA")
        self.assertEqual(spec.shape, "list")
        self.assertFalse(spec.required, "sensitive_columns must be optional (3.4.0 transitional)")

    def test_item_keys_match_contract(self) -> None:
        spec = recipe_symfony.RECON_BAGS_SCHEMA["stack"]["symfony"]["sensitive_columns"]
        expected = frozenset({
            "entity_class", "file", "field_name", "column_type",
            "name_pattern_matched", "encryption_status", "encryption_evidence",
        })
        self.assertEqual(spec.item_keys, expected)


class SanityProbesIncludeNewSections(unittest.TestCase):
    def test_routes_authz_probe_present(self) -> None:
        probes = recipe_symfony.sanity_probes()
        labels = {p.label for p in probes}
        self.assertIn("symfony.routes_authz_matrix", labels)
        probe = next(p for p in probes if p.label == "symfony.routes_authz_matrix")
        self.assertEqual(probe.section_path,
                         "recon_bags.stack.symfony.routes_authz_matrix")
        # content_filter narrows to actual #[Route] usage.
        self.assertIsNotNone(probe.content_filter)

    def test_sensitive_columns_probe_present(self) -> None:
        probes = recipe_symfony.sanity_probes()
        labels = {p.label for p in probes}
        self.assertIn("symfony.sensitive_columns", labels)
        probe = next(p for p in probes if p.label == "symfony.sensitive_columns")
        self.assertEqual(probe.section_path,
                         "recon_bags.stack.symfony.sensitive_columns")
        self.assertIsNotNone(probe.content_filter)


if __name__ == "__main__":
    unittest.main()
