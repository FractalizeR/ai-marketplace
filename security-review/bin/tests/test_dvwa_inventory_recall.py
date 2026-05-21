"""Inventory recall regression on the symfony_dvwa fixture.

The DVWA fixture defines 15 known vulnerabilities (`golden_findings.yaml`).
Worker-level recall (LLM) is measured manually — see fixture README.

This test only validates the **deterministic** half of the chain: the recipe's
inventory must surface every entry-point file, every repository, every
admin-bundle controller, and the relevant sinks (unserialize / file_get_contents
/ http client) so that downstream waves can land on them.

If a future recipe change accidentally drops one of these, the recall test
fails immediately — no need to wait for a manual run to notice.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
FIX_DVWA = THIS_DIR / "fixtures" / "symfony_dvwa"
RECON = BIN_DIR / "recon_inventory.py"

sys.path.insert(0, str(BIN_DIR))
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402


def _section_payload(text: str, section_id: str) -> dict | None:
    """Same dot-notation walker as `test_recipe_symfony.py::_section_payload`."""
    import re
    if "." not in section_id:
        anchor = f"<!-- section_id: {section_id} -->"
        idx = text.find(anchor)
        if idx == -1:
            return None
        rest = text[idx:]
        m = re.search(r"```yaml\s*\n(.*?)\n```", rest, re.DOTALL)
        if not m:
            return None
        return parse_yaml_subset(m.group(1))
    parts = section_id.split(".")
    base = _section_payload(text, parts[0])
    cur = base
    for p in parts[1:]:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class DvwaInventoryRecall(unittest.TestCase):
    """Per-section recall checks against the deliberately-vulnerable fixture."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = Path(cls.tmp.name) / "review"
        proc = subprocess.run(
            [sys.executable, str(RECON), str(FIX_DVWA),
             "--recipe", "symfony", "--review-root", str(cls.review_root),
             "--no-console"],
            capture_output=True, text=True, timeout=90,
        )
        assert proc.returncode == 0, proc.stderr
        cls.text = (cls.review_root / "CONTEXT.md").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # ------------------------------------------------------------------
    # attack_surface
    # ------------------------------------------------------------------

    def test_attack_surface_collects_all_user_routes(self):
        """Every controller method annotated with #[Route] must surface as
        an http_route entry. 9 attribute routes across 7 controllers + 3
        admin-bundle CRUD controllers (UserCrudController + OrderCrudController
        + DashboardController index)."""
        payload = _section_payload(self.text, "attack_surface")
        items = payload["items"]
        files = {it["file"] for it in items if it.get("kind") == "http_route"}
        # 9 attribute routes:
        # ApiController::search          /api/search
        # ApiController::restoreSession  /api/session/restore
        # AuthController::loginSuccess   /auth/login-success
        # AuthController::updateProfile  /auth/profile
        # FileController::download       /files/download
        # PostController::show           /posts/{id}
        # SearchController::render       /search/render
        # UserController::profile        /users/{id}
        # DashboardController::index     /admin            (kind=http_route, attribute on the dashboard)
        self.assertIn("src/Controller/ApiController.php", files)
        self.assertIn("src/Controller/AuthController.php", files)
        self.assertIn("src/Controller/FileController.php", files)
        self.assertIn("src/Controller/PostController.php", files)
        self.assertIn("src/Controller/SearchController.php", files)
        self.assertIn("src/Controller/UserController.php", files)

    def test_attack_surface_includes_three_crud_admin_controllers(self):
        payload = _section_payload(self.text, "attack_surface")
        admins = [it for it in payload["items"] if it.get("kind") == "http_route_admin"]
        files = {it["file"] for it in admins}
        # DashboardController extends AbstractDashboardController which is
        # *also* classified as `http_route_admin` (admin namespace), plus the
        # two AbstractCrudController subclasses.
        self.assertIn("src/Controller/Admin/UserCrudController.php", files)
        self.assertIn("src/Controller/Admin/OrderCrudController.php", files)

    # ------------------------------------------------------------------
    # data_access — repositories
    # ------------------------------------------------------------------

    def test_data_access_collects_all_three_repositories(self):
        payload = _section_payload(self.text, "data_access")
        files = {it["file"] for it in payload["items"]}
        self.assertEqual(files, {
            "src/Repository/UserRepository.php",
            "src/Repository/PostRepository.php",
            "src/Repository/OrderRepository.php",
        })

    # ------------------------------------------------------------------
    # serialization sink (DVWA-07)
    # ------------------------------------------------------------------

    def test_serialization_section_catches_untrusted_unserialize(self):
        payload = _section_payload(self.text, "serialization")
        files = {it["file"] for it in payload["items"]}
        self.assertIn("src/Controller/ApiController.php", files,
                      "DVWA-07 unserialize($cookie) was not surfaced in serialization section")

    # ------------------------------------------------------------------
    # file_operations sink (DVWA-05)
    # ------------------------------------------------------------------

    def test_file_operations_catches_path_traversal_call_site(self):
        payload = _section_payload(self.text, "file_operations")
        files = {it["file"] for it in payload["items"]}
        self.assertIn("src/Controller/FileController.php", files,
                      "DVWA-05 file_get_contents() was not surfaced in file_operations section")

    # ------------------------------------------------------------------
    # http_clients (PaymentClient SSRF pivot)
    # ------------------------------------------------------------------

    def test_http_clients_section_includes_payment_client(self):
        payload = _section_payload(self.text, "http_clients")
        files = {it["file"] for it in payload["items"]}
        self.assertIn("src/Service/PaymentClient.php", files)

    # ------------------------------------------------------------------
    # forms (DVWA-08, DVWA-09)
    # ------------------------------------------------------------------

    def test_forms_section_records_csrf_and_allow_extra_fields_flags(self):
        payload = _section_payload(self.text, "recon_bags.stack.symfony.forms")
        self.assertIsNotNone(payload, "forms section missing")
        forms = {it["class"]: it for it in payload["items"]}
        self.assertIn("App\\Form\\UserType", forms)
        ut = forms["App\\Form\\UserType"]
        # DVWA-08: csrf_protection explicitly false.
        self.assertFalse(ut["csrf_protection"],
                         "DVWA-08 (csrf_protection: false) not visible in inventory")
        # DVWA-09: allow_extra_fields explicitly true.
        self.assertTrue(ut["allow_extra_fields"],
                        "DVWA-09 (allow_extra_fields: true) not visible in inventory")

    # ------------------------------------------------------------------
    # easyadmin_crud_controllers + admin_authz_coverage (DVWA-11, DVWA-12)
    # ------------------------------------------------------------------

    def test_easyadmin_crud_controllers_includes_both_admin_classes(self):
        payload = _section_payload(self.text,
                                   "recon_bags.addon.easyadmin.crud_controllers")
        self.assertIsNotNone(payload)
        classes = {it["class"] for it in payload["items"]}
        self.assertIn("App\\Controller\\Admin\\UserCrudController", classes)
        self.assertIn("App\\Controller\\Admin\\OrderCrudController", classes)

    def test_user_crud_apikey_field_has_no_protective_modifiers(self):
        """DVWA-11 sensitive_field_unmasked anchor — the recipe must give the
        worker enough context to detect that `apiKey` is exposed as a plain
        TextField with no modifiers (worker matches `name` against the
        sensitive-name regex, then checks `modifiers`)."""
        payload = _section_payload(self.text,
                                   "recon_bags.addon.easyadmin.crud_controllers")
        user_crud = next(it for it in payload["items"]
                         if it["class"].endswith("UserCrudController"))
        fields = {f["name"]: f for f in user_crud["configure_fields"]}
        self.assertIn("apiKey", fields)
        self.assertEqual(fields["apiKey"]["modifiers"], [],
                         "DVWA-11: apiKey field unexpectedly has modifiers — recall would degrade")

    def test_admin_authz_coverage_marks_user_crud_unwired(self):
        """DVWA-12 trigger — UserCrudController has no UserVoter (only OrderVoter
        exists), so admin_authz_coverage must classify it as without_voter."""
        payload = _section_payload(self.text,
                                   "recon_bags.stack.symfony.admin_authz_coverage")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["status"], "partial")
        self.assertIn("UserCrudController", payload["data"]["crud_controllers_without_voter"])
        self.assertIn("OrderCrudController", payload["data"]["crud_controllers_with_voter"])

    # ------------------------------------------------------------------
    # twig_overrides — autoescape: false (DVWA-03 anchor)
    # ------------------------------------------------------------------

    def test_twig_overrides_records_global_autoescape_off(self):
        payload = _section_payload(self.text,
                                   "recon_bags.stack.symfony.twig_overrides")
        self.assertIsNotNone(payload)
        # twig_overrides is a scalar section — `data` is its keyed payload.
        data = payload.get("data", {})
        # Recipe stores the raw value; either the literal `false` or the string `"false"`.
        autoescape = data.get("autoescape_default")
        self.assertIn(autoescape, (False, "false"),
                      f"twig.yaml autoescape: false not surfaced (got {autoescape!r})")

    # ------------------------------------------------------------------
    # messenger_transports — section is collected (DVWA-07 reinforcement chain).
    # Recipe captures `name`, `dsn_type` and `serializer` per transport so the
    # worker can detect `native_php_serializer` from the inventory directly.
    # ------------------------------------------------------------------

    def test_messenger_transports_records_native_php_serializer(self):
        payload = _section_payload(self.text,
                                   "recon_bags.stack.symfony.messenger_transports")
        self.assertIsNotNone(payload)
        data = payload.get("data", {})
        transports = data.get("transports") or []
        async_transport = next((t for t in transports if t.get("name") == "async"), None)
        self.assertIsNotNone(async_transport,
                             f"async transport not found in {transports!r}")
        self.assertEqual(
            async_transport.get("serializer"),
            "messenger.transport.native_php_serializer",
            f"serializer field missing/incorrect: {async_transport!r}",
        )

    # ------------------------------------------------------------------
    # auth_layer — stateless firewall + plaintext hasher (DVWA-14, DVWA-15)
    # ------------------------------------------------------------------

    def test_auth_layer_kind_is_stateless(self):
        payload = _section_payload(self.text, "auth_layer")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["data"]["kind"], "stateless")

    def test_secrets_section_reports_plaintext_password_hasher(self):
        """DVWA-14 anchor in security.yaml. Recipe encodes password_hasher
        directly in `secrets.data.password_hasher`."""
        payload = _section_payload(self.text, "secrets")
        self.assertIsNotNone(payload)
        # Section is in pending_enrichment for the candidate-classification flow,
        # but the password_hasher field is filled deterministically.
        data = payload.get("data", {})
        self.assertEqual(data.get("password_hasher"), "plaintext")

    def test_secrets_candidates_include_yaml_resident_stripe_key(self):
        """DVWA-10 anchor: `sk_live_...` lives in `config/services.yaml`.
        Recipe must scan yaml files under `config/`, not only PHP sources."""
        payload = _section_payload(self.text, "secrets")
        candidates = payload.get("data", {}).get("candidates") or []
        yaml_hit = next(
            (c for c in candidates
             if c.get("file") == "config/services.yaml"
             and c.get("regex_match") == "stripe_live_key"),
            None,
        )
        self.assertIsNotNone(
            yaml_hit,
            f"yaml-resident sk_live_ secret missed; got {candidates!r}",
        )


if __name__ == "__main__":
    unittest.main()
