"""Tests for `recon_bags.stack.laravel.routes_authz_matrix` emitter.

Coverage:
  * Routes via Route::middleware('auth')->group(...) — middleware inheritance.
  * Multi-middleware groups + per-route chained middleware (throttle).
  * Routes with no authz at all — empty evidence list.
  * Controller-level __construct $this->middleware() (with ->only() scoping).
  * $this->authorize('ability') — method_call evidence.
  * FormRequest-typed parameter — form_request_authorize evidence (soft).
  * CSRF: required for routes/web.php, unknown for routes/api.php.
"""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

PLUGIN_BIN = Path(__file__).resolve().parent.parent.parent
PLUGIN_ROOT = PLUGIN_BIN.parent
sys.path.insert(0, str(PLUGIN_BIN))

from recon.recipes import laravel  # noqa: E402

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "laravel_routes_authz"


def _php_available() -> bool:
    return shutil.which("php") is not None


class RoutesAuthzMatrixBuilderTests(unittest.TestCase):
    """Static-only — does not require PHP extractor.

    The static portion of the recipe re-uses _parse_routes_file (regex) +
    direct text reads of controllers (regex). Form-request authorize
    detection is best-effort: form_request_authorize map is built only from
    `classes_app`, which the PHP extractor populates. We pre-feed a synthetic
    classes_app list so this suite stays PHP-free.
    """

    @classmethod
    def setUpClass(cls):
        # Synthetic classes_app: only FormRequest entry needed for FR detection.
        synthetic_classes = [
            {
                "fqn": "App\\Http\\Requests\\StoreUserRequest",
                "file": str((FIX / "app/Http/Requests/StoreUserRequest.php").resolve()),
            },
        ]
        cls.payload = laravel._build_routes_authz_matrix(FIX, synthetic_classes)
        cls.items = cls.payload.items or []

    def _by_path(self, path: str) -> dict:
        matches = [it for it in self.items if it["path"] == path]
        if not matches:
            raise AssertionError(
                f"no item with path={path!r}; items={[it['path'] for it in self.items]!r}"
            )
        return matches[0]

    def test_status_ok(self):
        self.assertEqual(self.payload.status, "ok")

    def test_simple_route_with_group_middleware(self):
        item = self._by_path("/dashboard")
        self.assertIn("auth", item["effective_middleware"])
        # auth → middleware evidence with hard_deny strength.
        auth_evidence = [
            ev for ev in item["authz_evidence"]
            if ev["source"] == "middleware" and "auth" in ev["roles"]
        ]
        self.assertEqual(len(auth_evidence), 1)
        self.assertEqual(auth_evidence[0]["strength"], "hard_deny")

    def test_route_group_middleware_inheritance(self):
        # /api/users sits in middleware(['auth','admin'])->group + chained middleware('throttle:60,1').
        item = self._by_path("/api/users")
        for token in ("auth", "admin", "throttle:60,1"):
            self.assertIn(
                token, item["effective_middleware"],
                msg=f"missing token {token} in effective_middleware: "
                    f"{item['effective_middleware']!r}",
            )

    def test_throttle_middleware_is_soft(self):
        item = self._by_path("/api/users")
        throttle = [
            ev for ev in item["authz_evidence"]
            if ev["source"] == "middleware" and any("throttle" in r for r in ev["roles"])
        ]
        self.assertEqual(len(throttle), 1)
        self.assertEqual(throttle[0]["strength"], "soft")

    def test_route_without_authz_has_empty_evidence(self):
        item = self._by_path("/public")
        self.assertEqual(item["effective_middleware"], [])
        self.assertEqual(item["authz_evidence"], [])

    def test_controller_middleware_only_scoping(self):
        # UserController::__construct: $this->middleware('verified')->only(['dashboard'])
        # Must apply to /dashboard but NOT to /users (different method).
        dashboard = self._by_path("/dashboard")
        self.assertIn("verified", dashboard["effective_middleware"])

        users_create = self._by_path("/users")
        self.assertNotIn(
            "verified", users_create["effective_middleware"],
            msg="`verified` middleware must not leak to non-`dashboard` actions "
                "(only(['dashboard']) scoping)",
        )

    def test_method_call_authorize_evidence(self):
        # UserController::dashboard() calls $this->authorize('view-dashboard').
        dashboard = self._by_path("/dashboard")
        method_calls = [
            ev for ev in dashboard["authz_evidence"]
            if ev["source"] == "method_call"
        ]
        self.assertEqual(len(method_calls), 1)
        self.assertEqual(method_calls[0]["roles"], ["view-dashboard"])
        self.assertEqual(method_calls[0]["strength"], "hard_deny")
        self.assertEqual(
            method_calls[0]["file"],
            "app/Http/Controllers/UserController.php",
        )

    def test_csrf_required_for_web_group(self):
        for path in ("/dashboard", "/api/users", "/public", "/users"):
            self.assertEqual(
                self._by_path(path)["csrf_protection"],
                "required",
                msg=f"web-group route {path} must have csrf_protection=required",
            )

    def test_csrf_unknown_for_api_group(self):
        item = self._by_path("/api/me")
        self.assertEqual(item["csrf_protection"], "unknown")

    def test_form_request_authorize_method(self):
        # /users → UserController::create(StoreUserRequest $request).
        item = self._by_path("/users")
        fr_evidence = [
            ev for ev in item["authz_evidence"]
            if ev["source"] == "form_request_authorize"
        ]
        self.assertEqual(len(fr_evidence), 1)
        self.assertEqual(fr_evidence[0]["strength"], "soft")
        self.assertEqual(fr_evidence[0]["roles"], [])

    def test_route_name_extracted(self):
        dashboard = self._by_path("/dashboard")
        self.assertEqual(dashboard["route_name"], "dashboard")

    def test_matched_access_control_always_null_for_laravel(self):
        for it in self.items:
            self.assertIsNone(it["matched_access_control"])
            self.assertIsNone(it["firewall"])

    def test_item_keys_match_schema(self):
        spec_keys = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]["routes_authz_matrix"].item_keys
        for row in self.items:
            self.assertEqual(
                set(row.keys()), set(spec_keys),
                msg=f"row keys diverge from schema: {row!r}",
            )

    def test_methods_list_for_post_verb(self):
        item = self._by_path("/users")
        self.assertEqual(item["methods"], ["POST"])

    def test_source_files_lists_routes_files(self):
        sources = self.payload.source_files or []
        self.assertIn("routes/web.php", sources)
        self.assertIn("routes/api.php", sources)

    def test_no_routes_dir_emits_none(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            payload = laravel._build_routes_authz_matrix(Path(td), [])
            self.assertEqual(payload.status, "none")


if __name__ == "__main__":
    unittest.main()
