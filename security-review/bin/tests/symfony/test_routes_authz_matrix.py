"""Wave 2-D (3.4.0) — `recon_bags.stack.symfony.routes_authz_matrix` emitter.

Drives `_build_routes_authz_matrix` against the synthetic
`fixtures/symfony_routes_authz` project. Tests are skipped when `php` is
unavailable on PATH (the emitter calls extract_php_metadata.php for routes).
"""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent.parent
PLUGIN_ROOT = BIN_DIR.parent
sys.path.insert(0, str(BIN_DIR))

from recon.recipes import symfony as recipe_symfony  # noqa: E402

FIX = THIS_DIR.parent / "fixtures" / "symfony_routes_authz"


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class RoutesAuthzMatrixEmitter(unittest.TestCase):
    """End-to-end emitter against the synthetic Symfony fixture."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = recipe_symfony._build_routes_authz_matrix(
            FIX, PLUGIN_ROOT, exclude=None, console_router_data=None,
        )

    def _items_by_name(self) -> dict:
        return {it["route_name"]: it for it in (self.payload.items or [])}

    def test_status_ok(self) -> None:
        self.assertEqual(self.payload.status, "ok")

    def test_admin_create_route_full_evidence(self) -> None:
        items = self._items_by_name()
        self.assertIn("admin_users_create", items)
        item = items["admin_users_create"]
        self.assertEqual(item["methods"], ["POST"])
        self.assertEqual(item["path"], "/admin/users")
        self.assertEqual(item["effective_middleware"], [])
        self.assertEqual(item["matched_access_control"], "^/admin")
        self.assertEqual(item["firewall"], "admin")
        # IsGranted attribute → route_attribute hard_deny.
        sources = {ev["source"] for ev in item["authz_evidence"]}
        self.assertIn("route_attribute", sources)
        self.assertIn("access_control", sources)
        attr_ev = next(ev for ev in item["authz_evidence"]
                       if ev["source"] == "route_attribute")
        self.assertEqual(attr_ev["roles"], ["ROLE_ADMIN"])
        self.assertEqual(attr_ev["strength"], "hard_deny")

    def test_delete_route_method_call_evidence(self) -> None:
        items = self._items_by_name()
        self.assertIn("admin_users_delete", items)
        item = items["admin_users_delete"]
        self.assertEqual(item["methods"], ["DELETE"])
        sources = {ev["source"] for ev in item["authz_evidence"]}
        # denyAccessUnlessGranted in the body must surface as method_call.
        self.assertIn("method_call", sources)
        method_ev = next(ev for ev in item["authz_evidence"]
                         if ev["source"] == "method_call")
        self.assertEqual(method_ev["roles"], ["ROLE_SUPERADMIN"])
        self.assertEqual(method_ev["strength"], "hard_deny")

    def test_public_route_only_access_control_evidence(self) -> None:
        items = self._items_by_name()
        self.assertIn("public_health", items)
        item = items["public_health"]
        # Only access_control evidence — no IsGranted, no deny call.
        sources = {ev["source"] for ev in item["authz_evidence"]}
        self.assertEqual(sources, {"access_control"})
        self.assertEqual(item["matched_access_control"], "^/health")

    def test_csrf_protection_unknown_for_non_form(self) -> None:
        # Non-form controllers — Symfony has no per-route CSRF declaration,
        # so we report `unknown`. Workers refine via Form linkage.
        for item in (self.payload.items or []):
            self.assertEqual(item["csrf_protection"], "unknown")

    def test_effective_middleware_always_empty(self) -> None:
        # Symfony has no middleware concept — must be [] for cross-stack parity.
        for item in (self.payload.items or []):
            self.assertEqual(item["effective_middleware"], [])

    def test_source_files_includes_security_yaml(self) -> None:
        self.assertIn("config/packages/security.yaml", self.payload.source_files or [])


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class RoutesAuthzMatrixConsoleOverlay(unittest.TestCase):
    """When console_router_data is supplied, it overrides static path/methods
    on a route_name match."""

    def test_console_overlay_overrides_path(self) -> None:
        console_data = {
            "admin_users_create": {
                "path": "/console-overridden/admin/users",
                "method": "POST|PUT",
                "controller": "App\\Controller\\UserController::create",
            },
        }
        payload = recipe_symfony._build_routes_authz_matrix(
            FIX, PLUGIN_ROOT, exclude=None, console_router_data=console_data,
        )
        items = {it["route_name"]: it for it in (payload.items or [])}
        item = items["admin_users_create"]
        self.assertEqual(item["path"], "/console-overridden/admin/users")
        self.assertEqual(item["methods"], ["POST", "PUT"])


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class RoutesAuthzMatrixSchemaInvariants(unittest.TestCase):
    """Cross-cutting invariants the worker relies on."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = recipe_symfony._build_routes_authz_matrix(
            FIX, PLUGIN_ROOT, exclude=None, console_router_data=None,
        )

    def test_each_item_has_contract_keys(self) -> None:
        spec = recipe_symfony.RECON_BAGS_SCHEMA["stack"]["symfony"]["routes_authz_matrix"]
        expected = spec.item_keys or frozenset()
        for item in (self.payload.items or []):
            self.assertEqual(
                set(item.keys()), set(expected),
                msg=f"item key drift: {set(item.keys())} vs {set(expected)}",
            )

    def test_authz_evidence_entries_have_required_fields(self) -> None:
        for item in (self.payload.items or []):
            for ev in item["authz_evidence"]:
                for key in ("source", "file", "line", "roles", "strength"):
                    self.assertIn(key, ev, f"evidence missing {key}: {ev}")
                self.assertIn(ev["source"], {
                    "route_attribute", "access_control", "middleware",
                    "method_call", "voter", "policy",
                })
                self.assertIn(ev["strength"], {"hard_deny", "hard_allow", "soft"})


if __name__ == "__main__":
    unittest.main()
