"""Unit + smoke tests for bin/recon/recipes/laravel.py."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_BIN = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = PLUGIN_BIN.parent
sys.path.insert(0, str(PLUGIN_BIN))

from recon.recipes import laravel  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "laravel_minimal"


def _php_available() -> bool:
    return shutil.which("php") is not None


# ---------------------------------------------------------------------------
# detect()
# ---------------------------------------------------------------------------


class DetectTests(unittest.TestCase):
    def test_detect_on_fixture_high_confidence(self):
        match = laravel.detect(FIXTURES)
        self.assertIsNotNone(match)
        self.assertEqual(match.name, "laravel")
        self.assertGreaterEqual(match.confidence, 0.7)
        self.assertEqual(match.version, "^10.0")

    def test_detect_returns_none_on_empty_dir(self):
        empty = Path(tempfile.mkdtemp())
        self.assertIsNone(laravel.detect(empty))

    def test_detect_partial_signals(self):
        """Just composer.json + laravel/framework — confidence above 0 but below 0.7."""
        root = Path(tempfile.mkdtemp())
        (root / "composer.json").write_text(
            json.dumps({"require": {"laravel/framework": "^10.0"}}),
            encoding="utf-8",
        )
        match = laravel.detect(root)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.4)

    def test_detect_full_signals(self):
        root = Path(tempfile.mkdtemp())
        (root / "composer.json").write_text(
            json.dumps({"require": {"laravel/framework": "^10.0"}}),
            encoding="utf-8",
        )
        (root / "artisan").write_text("<?php", encoding="utf-8")
        (root / "config").mkdir()
        (root / "config" / "app.php").write_text("<?php return [];", encoding="utf-8")
        (root / "app").mkdir()
        (root / "app" / "Models").mkdir()
        match = laravel.detect(root)
        self.assertEqual(match.confidence, 1.0)


# ---------------------------------------------------------------------------
# Helpers (route parser, alias parser, kind filters)
# ---------------------------------------------------------------------------


class RouteParserTests(unittest.TestCase):
    def test_parse_use_aliases_simple(self):
        text = "<?php\nuse App\\Http\\Controllers\\Foo;\nuse App\\Models\\Bar as Baz;\n"
        out = laravel._parse_use_aliases(text)
        self.assertEqual(out["Foo"], "App\\Http\\Controllers\\Foo")
        self.assertEqual(out["Baz"], "App\\Models\\Bar")

    def test_parse_use_aliases_group(self):
        text = "<?php\nuse App\\Http\\Controllers\\{Foo, Bar as B};\n"
        out = laravel._parse_use_aliases(text)
        self.assertEqual(out["Foo"], "App\\Http\\Controllers\\Foo")
        self.assertEqual(out["B"], "App\\Http\\Controllers\\Bar")

    def test_parse_routes_array_target(self):
        web = FIXTURES / "routes" / "web.php"
        items = laravel._parse_routes_file(web, FIXTURES)
        # 5 Route::* calls (get/, get/posts/{id}, post/posts/{id}, get/legacy, get/closure)
        self.assertEqual(len(items), 5)
        # Find the get / route
        idx = next(i for i in items if i["uri"] == "/")
        self.assertEqual(idx["controller"], "App\\Http\\Controllers\\HomeController")
        self.assertEqual(idx["method"], "index")
        self.assertEqual(idx["target_kind"], "controller")

    def test_parse_routes_resource_bare_class(self):
        api = FIXTURES / "routes" / "api.php"
        items = laravel._parse_routes_file(api, FIXTURES)
        resource = next(i for i in items if i["verb"] == "resource")
        self.assertEqual(resource["controller"], "App\\Http\\Controllers\\PostController")
        self.assertIsNone(resource["method"])  # resource → many actions
        self.assertEqual(resource["target_kind"], "controller")
        self.assertEqual(resource["uri"], "posts")

    def test_parse_routes_invokable_controller(self):
        api = FIXTURES / "routes" / "api.php"
        items = laravel._parse_routes_file(api, FIXTURES)
        invoke = next(i for i in items if i["uri"] == "/report")
        self.assertEqual(invoke["controller"], "App\\Http\\Controllers\\InvokeReportController")
        self.assertEqual(invoke["method"], "__invoke")
        self.assertEqual(invoke["target_kind"], "controller")

    def test_parse_routes_match_with_methods_array(self):
        api = FIXTURES / "routes" / "api.php"
        items = laravel._parse_routes_file(api, FIXTURES)
        match = next(i for i in items if i["verb"] == "match")
        # URI must NOT be "get" or "post" (those are inside the methods array).
        self.assertEqual(match["uri"], "/sync")
        self.assertEqual(match["controller"], "App\\Http\\Controllers\\UserController")
        self.assertEqual(match["method"], "sync")

    def test_parse_routes_legacy_string_target(self):
        web = FIXTURES / "routes" / "web.php"
        items = laravel._parse_routes_file(web, FIXTURES)
        legacy = next(i for i in items if i["uri"] == "/legacy")
        self.assertEqual(legacy["controller"], "App\\Http\\Controllers\\HomeController")
        self.assertEqual(legacy["method"], "legacy")
        self.assertEqual(legacy["target_kind"], "controller")

    def test_parse_routes_closure_target(self):
        web = FIXTURES / "routes" / "web.php"
        items = laravel._parse_routes_file(web, FIXTURES)
        closure = next(i for i in items if i["uri"] == "/closure")
        self.assertIsNone(closure["controller"])
        self.assertIsNone(closure["method"])
        self.assertEqual(closure["target_kind"], "closure")

    def test_resolve_controller_file_psr4(self):
        rel = laravel._resolve_controller_file(
            "App\\Http\\Controllers\\HomeController", FIXTURES,
        )
        self.assertEqual(rel, "app/Http/Controllers/HomeController.php")

    def test_resolve_controller_file_returns_none_for_unknown(self):
        rel = laravel._resolve_controller_file(
            "App\\Http\\Controllers\\NonexistentController", FIXTURES,
        )
        self.assertIsNone(rel)

    def test_resolve_controller_file_blocks_symlink_escape(self):
        """Hostile repo: app/Http/Controllers/Leak.php → /etc/passwd. Must return None."""
        import os
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "app" / "Http" / "Controllers").mkdir(parents=True)
            outside = Path(td).parent / "outside_target.php"
            outside.write_text("<?php // outside the project\n", encoding="utf-8")
            try:
                symlink = project / "app" / "Http" / "Controllers" / "Leak.php"
                os.symlink(outside, symlink)
                rel = laravel._resolve_controller_file(
                    "App\\Http\\Controllers\\Leak", project,
                )
                self.assertIsNone(rel, "symlink escape must be blocked")
            finally:
                outside.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# build_inventory smoke (requires php)
# ---------------------------------------------------------------------------


@unittest.skipUnless(_php_available(), "php CLI required for extractor invocation")
class BuildInventorySmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = laravel.build_inventory(FIXTURES, plugin_root=PLUGIN_ROOT)

    def test_status_ok(self):
        self.assertEqual(self.result.status, "ok")

    def test_attack_surface_has_routes(self):
        items = self.result.core["attack_surface"].items
        kinds = {i["kind"] for i in items}
        self.assertIn("http_route", kinds)
        # 5 from web.php + 5 from api.php (get, patch, resource, invokable, match) = 10
        http_routes = [i for i in items if i["kind"] == "http_route"]
        self.assertEqual(len(http_routes), 10)

    def test_attack_surface_has_command(self):
        items = self.result.core["attack_surface"].items
        commands = [i for i in items if i["kind"] == "cli_command"]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["class"], "App\\Console\\Commands\\CleanupCommand")

    def test_attack_surface_has_job_as_message_handler(self):
        items = self.result.core["attack_surface"].items
        jobs = [i for i in items if i["kind"] == "message_handler"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["class"], "App\\Jobs\\SendNewsletterJob")

    def test_attack_surface_has_listener(self):
        items = self.result.core["attack_surface"].items
        listeners = [i for i in items if i["kind"] == "event_listener"]
        self.assertEqual(len(listeners), 1)

    def test_data_access_has_models(self):
        items = self.result.core["data_access"].items
        files = {i["file"] for i in items}
        self.assertIn("app/Models/User.php", files)
        self.assertIn("app/Models/Post.php", files)

    def test_data_access_includes_repositories(self):
        items = self.result.core["data_access"].items
        repos = [i for i in items if i.get("kind") == "repository"]
        files = {i["file"] for i in repos}
        self.assertIn("app/Repositories/PostRepository.php", files)

    def test_authz_usage_collects_gate_and_authorize_calls(self):
        items = self.result.core["authz_usage"].items
        kinds = {i["kind"] for i in items}
        # PostController uses `$this->authorize(...)` plus a Gate facade call.
        self.assertIn("controller_authorize", kinds)

    def test_serialization_collects_unserialize_and_crypt_decrypt(self):
        items = self.result.core["serialization"].items
        files = {i["file"] for i in items}
        self.assertIn("app/Http/Controllers/PaymentController.php", files)
        kinds = {i["kind"] for i in items if i["file"].endswith("PaymentController.php")}
        self.assertTrue({"unserialize", "Crypt::decrypt"} & kinds,
                        f"expected serialization markers in PaymentController, got {kinds!r}")

    def test_file_operations_collects_file_get_contents_and_storage(self):
        items = self.result.core["file_operations"].items
        files = {i["file"] for i in items}
        self.assertIn("app/Http/Controllers/PaymentController.php", files)

    def test_http_clients_collects_http_facade(self):
        items = self.result.core["http_clients"].items
        files = {i["file"] for i in items}
        self.assertIn("app/Http/Controllers/PaymentController.php", files)

    def test_secrets_collects_stripe_live_key(self):
        payload = self.result.core["secrets"]
        self.assertEqual(payload.status, "pending_enrichment")
        candidates = payload.data["candidates"]
        self.assertTrue(any(c["regex_match"] == "stripe_live_key" for c in candidates),
                        f"sk_live_ secret not flagged: {candidates!r}")

    def test_fintech_markers_collects_composer_dep_and_bcmath(self):
        items = self.result.core["fintech_markers"].items
        kinds = {i["kind"] for i in items}
        self.assertIn("composer_dep", kinds)
        labels = {i.get("label") for i in items if i["kind"] == "composer_dep"}
        self.assertIn("stripe", labels)
        self.assertIn("grep_marker", kinds)

    def test_auth_layer_parsed(self):
        payload = self.result.core["auth_layer"]
        self.assertEqual(payload.status, "ok")
        self.assertEqual(payload.data["kind"], "laravel.auth")
        self.assertEqual(payload.data["default_guard"], "web")
        self.assertIn("session", payload.data["drivers"])
        self.assertIn("sanctum", payload.data["drivers"])

    def test_output_renderers_lists_blade_templates(self):
        items = self.result.core["output_renderers"].items
        files = {i["file"] for i in items}
        self.assertIn("resources/views/welcome.blade.php", files)
        self.assertIn("resources/views/posts/show.blade.php", files)

    def test_recon_bags_policies(self):
        items = self.result.recon_bags["stack"]["laravel"]["policies"].items
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["class"], "App\\Policies\\PostPolicy")
        self.assertEqual(items[0]["model"], "Post")

    def test_recon_bags_form_requests(self):
        items = self.result.recon_bags["stack"]["laravel"]["form_requests"].items
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["class"], "App\\Http\\Requests\\UpdatePostRequest")

    def test_recon_bags_service_providers(self):
        items = self.result.recon_bags["stack"]["laravel"]["service_providers"].items
        classes = {i["class"] for i in items}
        self.assertIn("App\\Providers\\AppServiceProvider", classes)
        self.assertIn("App\\Providers\\RouteServiceProvider", classes)

    def test_recon_bags_middleware_groups(self):
        payload = self.result.recon_bags["stack"]["laravel"]["middleware_groups"]
        self.assertEqual(payload.status, "ok")
        self.assertIn("web", payload.data["groups"])
        self.assertIn("api", payload.data["groups"])
        self.assertGreaterEqual(payload.data["global"], 1)
        self.assertIn("auth", payload.data["route"])
        self.assertIn("guest", payload.data["route"])

    def test_no_graphql_layer_when_no_lib(self):
        """Fixture has no GraphQL deps — graphql_layer must be absent."""
        self.assertNotIn("graphql_layer", self.result.recon_bags["stack"]["laravel"])

    def test_frontend_assets_is_list_shape(self):
        """Schema v2 requires frontend_assets to be a list-section (validate_context.py:275)."""
        payload = self.result.core["frontend_assets"]
        self.assertEqual(payload.status, "ok")
        self.assertIsInstance(payload.items, list)
        self.assertIsNone(payload.data)  # NOT scalar

    def test_frontend_assets_detects_vite(self):
        """Recipe should emit a vite item when vite.config.js is present."""
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "composer.json").write_text(
                json.dumps({"require": {"laravel/framework": "^10.0"}}),
                encoding="utf-8",
            )
            (project / "artisan").write_text("<?php", encoding="utf-8")
            (project / "config").mkdir()
            (project / "config" / "app.php").write_text("<?php return [];", encoding="utf-8")
            (project / "app" / "Models").mkdir(parents=True)
            (project / "vite.config.js").write_text("export default {}", encoding="utf-8")
            result = laravel.build_inventory(project, plugin_root=PLUGIN_ROOT)
            items = result.core["frontend_assets"].items
            bundlers = {i.get("bundler") for i in items if i.get("kind") == "bundler"}
            self.assertIn("vite", bundlers)


# ---------------------------------------------------------------------------
# diff_files post-pass
# ---------------------------------------------------------------------------


@unittest.skipUnless(_php_available(), "php CLI required for extractor invocation")
class DiffPostPassTests(unittest.TestCase):
    def test_touched_by_diff_marker_set_on_attack_surface(self):
        result = laravel.build_inventory(
            FIXTURES,
            diff_files={"app/Http/Controllers/PostController.php"},
            plugin_root=PLUGIN_ROOT,
        )
        items = result.core["attack_surface"].items
        # Routes whose `file` resolved to PostController should be marked.
        marked = [i for i in items if i.get("touched_by_diff")]
        self.assertGreater(len(marked), 0)
        for it in marked:
            self.assertEqual(it["file"], "app/Http/Controllers/PostController.php")


# ---------------------------------------------------------------------------
# exclude= propagation through build_inventory (3.1.1)
# ---------------------------------------------------------------------------


@unittest.skipUnless(_php_available(), "php CLI required for extractor invocation")
class ExcludePropagationTests(unittest.TestCase):
    """Synthetic legacy/ subtree with a Console command — without exclude it
    surfaces in attack_surface (control case); with exclude=("legacy",) it
    must not. Catches regressions where laravel.py forgets to forward
    exclude= through `_extract_classes` or `_build_attack_surface`.

    Note: laravel recipe expects commands under `app/Console/Commands/` (path
    convention), so we synthesize the legacy command under
    `app/Console/Commands/Legacy/CleanupLegacyCommand.php` and exclude
    `app/Console/Commands/Legacy` — exclude is path-prefix based, so any
    nesting works as long as the prefix matches.
    """

    LEGACY_COMMAND = (
        "<?php\n"
        "namespace App\\Console\\Commands\\Legacy;\n\n"
        "use Illuminate\\Console\\Command;\n\n"
        "final class CleanupLegacyCommand extends Command\n"
        "{\n"
        "    protected $signature = 'legacy:cleanup';\n"
        "}\n"
    )

    def _scratch_with_legacy_command(self, td: Path) -> Path:
        scratch = td / "proj"
        shutil.copytree(FIXTURES, scratch)
        legacy_dir = scratch / "app" / "Console" / "Commands" / "Legacy"
        legacy_dir.mkdir(parents=True)
        (legacy_dir / "CleanupLegacyCommand.php").write_text(self.LEGACY_COMMAND)
        return scratch

    def test_legacy_command_present_without_exclude(self):
        # Control case — must surface, otherwise the exclude assertion below
        # would pass for the wrong reason.
        with tempfile.TemporaryDirectory() as td:
            scratch = self._scratch_with_legacy_command(Path(td))
            result = laravel.build_inventory(scratch, plugin_root=PLUGIN_ROOT)
        items = result.core["attack_surface"].items
        legacy_cmds = [
            i for i in items
            if i.get("kind") == "cli_command"
            and i.get("file", "").startswith("app/Console/Commands/Legacy/")
        ]
        self.assertEqual(
            len(legacy_cmds), 1,
            msg=f"control case failed: legacy command must surface; saw {items!r}",
        )

    def test_legacy_command_dropped_with_exclude(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = self._scratch_with_legacy_command(Path(td))
            result = laravel.build_inventory(
                scratch,
                plugin_root=PLUGIN_ROOT,
                exclude=("app/Console/Commands/Legacy",),
            )
        items = result.core["attack_surface"].items
        for it in items:
            self.assertFalse(
                it.get("file", "").startswith("app/Console/Commands/Legacy/"),
                msg=f"exclude=('app/Console/Commands/Legacy',) leaked: {it!r}",
            )

    def test_legacy_model_dropped_in_data_access(self):
        # Different code path — _build_data_access scans app/Models/ via
        # classes_app (which goes through _extract_classes → exclude). A
        # legacy model placed under app/Models/Legacy/ must drop with exclude.
        with tempfile.TemporaryDirectory() as td:
            scratch = self._scratch_with_legacy_command(Path(td))
            legacy_models = scratch / "app" / "Models" / "Legacy"
            legacy_models.mkdir(parents=True)
            (legacy_models / "ArchivedUser.php").write_text(
                "<?php\n"
                "namespace App\\Models\\Legacy;\n\n"
                "use Illuminate\\Database\\Eloquent\\Model;\n\n"
                "class ArchivedUser extends Model {}\n"
            )
            result = laravel.build_inventory(
                scratch,
                plugin_root=PLUGIN_ROOT,
                exclude=("app/Models/Legacy",),
            )
        items = result.core["data_access"].items
        for it in items:
            self.assertFalse(
                it.get("file", "").startswith("app/Models/Legacy/"),
                msg=f"exclude=('app/Models/Legacy',) leaked into data_access: {it!r}",
            )


# ---------------------------------------------------------------------------
# Schema spec invariants
# ---------------------------------------------------------------------------


class ClassesExtendingTests(unittest.TestCase):
    """`_classes_extending` — FQN-match + transitive inheritance via parent_chain.
    Pure unit test, no PHP needed."""

    def test_direct_extends_matched(self):
        classes = [
            {"fqn": "App\\X", "extends": "Symfony\\Foo", "parent_chain": [], "is_abstract": False},
        ]
        out = laravel._classes_extending(classes, ("Symfony\\Foo",))
        self.assertEqual(len(out), 1)

    def test_transitive_extends_via_parent_chain(self):
        # `MyController extends ApiController extends Symfony\\Foo`.
        classes = [
            {
                "fqn": "App\\My",
                "extends": "App\\Api",
                "parent_chain": ["App\\Api", "Symfony\\Foo"],
                "is_abstract": False,
            },
        ]
        out = laravel._classes_extending(classes, ("Symfony\\Foo",))
        self.assertEqual(len(out), 1)

    def test_abstract_classes_filtered(self):
        classes = [
            {
                "fqn": "App\\Base",
                "extends": "Symfony\\Foo",
                "parent_chain": [],
                "is_abstract": True,
            },
        ]
        self.assertEqual(laravel._classes_extending(classes, ("Symfony\\Foo",)), [])

    def test_no_match_when_unrelated_parent(self):
        classes = [
            {"fqn": "App\\X", "extends": "App\\Other", "parent_chain": [],
             "is_abstract": False},
        ]
        self.assertEqual(laravel._classes_extending(classes, ("Symfony\\Foo",)), [])

    def test_suffix_fallback_with_forward_slash_parents(self):
        # _build_attack_surface passes forward-slash form to _classes_extending
        # while extractor emits backslash. Suffix-fallback bridges the two.
        classes = [
            {"fqn": "App\\Foo", "extends": "Illuminate\\Console\\Command",
             "parent_chain": [], "is_abstract": False},
        ]
        out = laravel._classes_extending(classes, ("Illuminate/Console/Command",))
        self.assertEqual(len(out), 1)


class CollectorRegressionTests(unittest.TestCase):
    """Regression tests for issues found in 3.3.0 triple review."""

    def test_grep_section_skips_comment_lines(self):
        # `// Crypt::decrypt($x)` and `* @example unserialize($data)` must NOT
        # surface as serialization markers — they're docs, not call sites.
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "composer.json").write_text(
                json.dumps({"require": {"laravel/framework": "^10.0"}}),
                encoding="utf-8",
            )
            (project / "artisan").write_text("<?php", encoding="utf-8")
            (project / "config").mkdir()
            (project / "config" / "app.php").write_text("<?php return [];", encoding="utf-8")
            (project / "app").mkdir()
            (project / "app" / "Models").mkdir()
            (project / "app" / "Demo.php").write_text(
                "<?php\n"
                "namespace App;\n"
                "class Demo {\n"
                "    /**\n"
                "     * @example unserialize($payload)\n"
                "     */\n"
                "    public function noop() {\n"
                "        // Crypt::decrypt('demo');\n"
                "        return 1;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            result = laravel.build_inventory(project, plugin_root=PLUGIN_ROOT)
            for it in result.core["serialization"].items:
                self.assertFalse(it["file"].endswith("Demo.php"),
                                 f"comment-line serialization match leaked: {it!r}")

    def test_authz_var_can_pattern(self):
        items = laravel.collect_authz_usage([], None)
        self.assertEqual(items, [])  # smoke
        # Synthetic file with `$user->can('edit', $post)`.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Ctl.php"
            f.write_text(
                "<?php\n"
                "class Ctl {\n"
                "    public function show($user, $post) {\n"
                "        return $user->can('view', $post);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            items = laravel.collect_authz_usage([("app/Ctl.php", f)], None)
        kinds = {it["kind"] for it in items}
        self.assertIn("var_can", kinds)

    def test_authz_middleware_array_pattern(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "routes.php"
            f.write_text(
                "<?php\n"
                "Route::get('/x', 'Foo@bar')->middleware(['can:edit', 'auth']);\n",
                encoding="utf-8",
            )
            items = laravel.collect_authz_usage([("routes/web.php", f)], None)
        kinds = {it["kind"] for it in items}
        self.assertIn("middleware_can", kinds)

    def test_fintech_composer_substring_matches_laravel_cashier(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "composer.json").write_text(
                json.dumps({"require": {
                    "laravel/framework": "^10.0",
                    "laravel/cashier": "^15.0",
                    "paypal/paypal-checkout-sdk": "^1.0",
                }}),
                encoding="utf-8",
            )
            items = laravel.collect_fintech_markers(project, [], None)
            labels = {(it.get("dep"), it.get("label")) for it in items
                      if it.get("kind") == "composer_dep"}
            self.assertIn(("laravel/cashier", "cashier"), labels)
            self.assertIn(("paypal/paypal-checkout-sdk", "paypal"), labels)

    def test_fintech_grep_skips_use_namespace_lines(self):
        # `use PayPal\Api\ApiContext;` must NOT count as a fintech call site —
        # only actual method invocations are useful for audit.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Svc.php"
            f.write_text(
                "<?php\n"
                "namespace App\\Services;\n"
                "use PayPal\\Api\\ApiContext;\n"
                "use Stripe\\StripeClient;\n"
                "class Svc {\n"
                "    public function pay() {\n"
                "        $client = new StripeClient('key');\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            items = laravel.collect_fintech_markers(
                Path(td), [("app/Svc.php", f)], None,
            )
        # `use ...` and `namespace ...` lines must be skipped.
        for it in items:
            if it["kind"] == "grep_marker":
                snippet = it.get("snippet", "")
                self.assertFalse(snippet.startswith("use "),
                                 f"use-line leaked into grep markers: {it!r}")
                self.assertFalse(snippet.startswith("namespace "),
                                 f"namespace-line leaked: {it!r}")

    def test_http_client_regex_does_not_match_bare_new_client(self):
        # `new Stripe\Client(...)` and `new App\Services\Client(...)` must NOT
        # surface as http_client. Only Guzzle namespace counts.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Svc.php"
            f.write_text(
                "<?php\n"
                "$a = new Client();\n"
                "$b = new \\App\\Services\\Client();\n"
                "$c = new \\GuzzleHttp\\Client();\n",
                encoding="utf-8",
            )
            items = laravel.collect_grep_section(
                [("app/Svc.php", f)], laravel._HTTP_CLIENT_RE, "http_client", None,
            )
        # Only the GuzzleHttp\Client line should match.
        lines = {it["line"] for it in items}
        self.assertEqual(lines, {4})

    def test_classes_implementing_filters_abstract(self):
        classes = [
            {"fqn": "App\\BaseJob", "implements": ["Illuminate\\Contracts\\Queue\\ShouldQueue"],
             "is_abstract": True},
            {"fqn": "App\\ConcreteJob", "implements": ["Illuminate\\Contracts\\Queue\\ShouldQueue"],
             "is_abstract": False},
        ]
        out = laravel._classes_implementing(classes, (
            "Illuminate/Contracts/Queue/ShouldQueue",
        ))
        fqns = {c["fqn"] for c in out}
        self.assertEqual(fqns, {"App\\ConcreteJob"})


class FrameworkSpecificSchemaTests(unittest.TestCase):
    def test_schema_keys(self):
        keys = set(laravel.RECON_BAGS_SCHEMA["stack"]["laravel"].keys())
        self.assertEqual(
            keys,
            {"policies", "service_providers", "middleware_groups",
             "form_requests", "graphql_layer",
             # 3.4.0 — Wave 2-E:
             "routes_authz_matrix", "sensitive_columns", "runtime"},
        )

    def test_graphql_layer_optional(self):
        spec = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]["graphql_layer"]
        self.assertEqual(spec.shape, "scalar")
        self.assertFalse(spec.required)


# ---------------------------------------------------------------------------
# Sanity probes
# ---------------------------------------------------------------------------


class SanityProbesTests(unittest.TestCase):
    def test_sanity_probes_returns_list(self):
        probes = laravel.sanity_probes()
        self.assertIsInstance(probes, list)
        self.assertGreater(len(probes), 0)
        # Probe sections must be paths the recipe actually emits.
        emitted_paths = {
            "attack_surface", "data_access",
            "recon_bags.stack.laravel.policies",
            "recon_bags.stack.laravel.service_providers",
            "recon_bags.stack.laravel.form_requests",
            # 3.4.0 — Wave 2-E:
            "recon_bags.stack.laravel.routes_authz_matrix",
            "recon_bags.stack.laravel.sensitive_columns",
        }
        for probe in probes:
            self.assertIn(probe.section_path, emitted_paths)


if __name__ == "__main__":
    unittest.main()
