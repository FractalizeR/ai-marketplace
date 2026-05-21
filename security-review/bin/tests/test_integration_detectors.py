"""Unit tests for integration detector modules (Stage 4).

Covers the lightweight composer+env+config-based detectors:
- recon.recipes.jwt_generic_detect.detect_jwt_generic
- recon.recipes.oauth_oidc_detect.detect_oauth_oidc

Plus end-to-end propagation through `InventoryResult.detected_integrations`
into `frontmatter.stack.integrations` (parallel to test_addon_detectors.py's
FrontmatterAddonsEndToEnd), and a resolver-layer test confirming that
`integrations/jwt-generic/auth.md` is picked up when the integration is
active in `ResolutionContext`.

The probes are intentionally cheap — they only inspect composer.json,
.env*, and a handful of config files — so the tests use ephemeral
directories with hand-written fixtures. The fixture-driven end-to-end
suite mirrors `FrontmatterAddonsEndToEnd` (`test_addon_detectors.py`).
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


_BIN = Path(__file__).resolve().parent.parent
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

from recon.recipes.jwt_generic_detect import detect_jwt_generic  # noqa: E402
from recon.recipes.oauth_oidc_detect import detect_oauth_oidc  # noqa: E402
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402


def _write_composer(root: Path, *, require: dict | None = None, require_dev: dict | None = None) -> None:
    data: dict = {"name": "fixture/inline", "type": "project"}
    if require is not None:
        data["require"] = require
    if require_dev is not None:
        data["require-dev"] = require_dev
    (root / "composer.json").write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# detect_jwt_generic — composer + env + config probes.
# ---------------------------------------------------------------------------


class DetectJwtGenericTests(unittest.TestCase):
    def test_returns_true_for_firebase_php_jwt(self):
        """`firebase/php-jwt` is the canonical generic-PHP JWT library."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"firebase/php-jwt": "^6.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_lcobucci_jwt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"lcobucci/jwt": "^5.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_web_token_jwt_framework(self):
        """`web-token/jwt-framework` — full JWS/JWE/JWK suite."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"web-token/jwt-framework": "^3.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_paragonie_paseto(self):
        """PASETO is treated as JWT-adjacent for Stage 4."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"paragonie/paseto": "^3.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_laravel_tymon_jwt_auth(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"tymon/jwt-auth": "^2.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_laravel_php_open_source_saver_jwt_auth(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"php-open-source-saver/jwt-auth": "^2.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_lexik_jwt_authentication_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"lexik/jwt-authentication-bundle": "^3.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_wildcard_jwt_package(self):
        """Broad wildcard catch: any `vendor/jwt-*` or `jwt-*/*` should fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"acme/jwt-toolkit": "^1.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_via_env_jwt_secret(self):
        """`.env` referencing JWT_SECRET is a strong signal without a package."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / ".env").write_text(
                "APP_ENV=dev\nJWT_SECRET=changeme\n", encoding="utf-8",
            )
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_via_env_jwt_passphrase(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / ".env").write_text(
                "APP_ENV=dev\nJWT_PASSPHRASE=secret\n", encoding="utf-8",
            )
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_via_env_jwt_private_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "JWT_PRIVATE_KEY=/path/to/private.pem\n", encoding="utf-8",
            )
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_via_lexik_jwt_config_only(self):
        """`config/packages/lexik_jwt_authentication.yaml` is a positive signal."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "config" / "packages").mkdir(parents=True)
            (root / "config" / "packages" / "lexik_jwt_authentication.yaml").write_text(
                "lexik_jwt_authentication:\n    secret_key: '%env(...)%'\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_via_laravel_config_jwt_php(self):
        """Tymon-style published config `config/jwt.php` (Laravel) is a positive signal."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/framework": "^11.0"})
            (root / "config").mkdir(parents=True)
            (root / "config" / "jwt.php").write_text(
                "<?php\nreturn [\n  'secret' => env('JWT_SECRET'),\n];\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_true_for_trailing_jwt_vendor(self):
        """Trailing-suffix wildcard: `mycorp/auth-jwt` should fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"acme/auth-jwt": "^1.0"})
            self.assertTrue(detect_jwt_generic(root))

    def test_returns_false_when_no_signal(self):
        """No composer, no env, no config — clean negative."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_jwt_generic(root))

    def test_returns_false_when_no_composer_json(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(detect_jwt_generic(Path(td)))

    def test_returns_false_on_malformed_composer_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "composer.json").write_text("{not valid json", encoding="utf-8")
            self.assertFalse(detect_jwt_generic(root))

    def test_env_substring_match_does_not_fire(self):
        """Regression guard: `MY_JWT_HELPER=x` should NOT match `JWT_SECRET=`.

        Detector uses anchored regex (start of line, optional `export`); a
        prefix substring must not yield a false positive.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / ".env").write_text(
                "MY_JWT_HELPER_PATH=foo\nNOT_A_JWT_SECRET=bar\n", encoding="utf-8",
            )
            self.assertFalse(detect_jwt_generic(root))


# ---------------------------------------------------------------------------
# detect_oauth_oidc — composer + env + config probes.
# ---------------------------------------------------------------------------


class DetectOauthOidcTests(unittest.TestCase):
    def test_returns_true_for_league_oauth2_client(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"league/oauth2-client": "^2.7"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_league_oauth2_server(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"league/oauth2-server": "^9.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_knpu_oauth2_client_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"knpuniversity/oauth2-client-bundle": "^5.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_omines_oauth2_client_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"omines/oauth2-client-bundle": "^1.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_hybridauth(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"hybridauth/hybridauth": "^3.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_laravel_socialite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/socialite": "^5.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_laravel_passport(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/passport": "^12.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_bshaffer_oauth2_server_php(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"bshaffer/oauth2-server-php": "^1.13"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_wildcard_league_provider(self):
        """League/oauth2-google, league/oauth2-github — provider-specific spreads."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"league/oauth2-google": "^4.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_for_wildcard_oidc_package(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"acme/oidc-helper": "^1.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_via_env_oauth_client_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / ".env").write_text(
                "APP_ENV=dev\nOAUTH_CLIENT_ID=abc\nOAUTH_CLIENT_SECRET=xyz\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_via_env_oidc_issuer(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "OIDC_ISSUER=https://example.com\n", encoding="utf-8",
            )
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_via_knpu_config_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "config" / "packages").mkdir(parents=True)
            (root / "config" / "packages" / "knpu_oauth2_client.yaml").write_text(
                "knpu_oauth2_client:\n    clients: {}\n", encoding="utf-8",
            )
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_via_socialite_services_php(self):
        """`config/services.php` with a `redirect =>` key implies Socialite."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/framework": "^11.0"})
            (root / "config").mkdir(parents=True)
            (root / "config" / "services.php").write_text(
                "<?php return [\n  'github' => [\n"
                "    'client_id' => env('GITHUB_ID'),\n"
                "    'redirect' => env('GITHUB_REDIRECT'),\n  ],\n];\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_true_via_socialite_full_scaffold(self):
        """Full Socialite scaffold: client_id + client_secret + redirect (any source)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/framework": "^11.0"})
            (root / "config").mkdir(parents=True)
            (root / "config" / "services.php").write_text(
                "<?php return [\n  'github' => [\n"
                "    'client_id' => 'literal-id',\n"
                "    'client_secret' => 'literal-secret',\n"
                "    'redirect' => 'https://example.test/callback',\n  ],\n];\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_false_for_bare_redirect_only(self):
        """Regression: `redirect` alone (Mailgun/Twilio style) must NOT fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/framework": "^11.0"})
            (root / "config").mkdir(parents=True)
            (root / "config" / "services.php").write_text(
                "<?php return [\n  'mailgun' => [\n"
                "    'domain' => 'mg.example.test',\n"
                "    'redirect' => 'https://example.test/notify',\n  ],\n];\n",
                encoding="utf-8",
            )
            self.assertFalse(detect_oauth_oidc(root))

    def test_returns_true_for_trailing_oauth2_vendor(self):
        """Vendor-prefix wildcard: `oauth2-toolkit/foo` should fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"oauth2-toolkit/foo": "^1.0"})
            self.assertTrue(detect_oauth_oidc(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_oauth_oidc(root))

    def test_returns_false_when_no_composer_json(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(detect_oauth_oidc(Path(td)))


# ---------------------------------------------------------------------------
# Integration ↔ addon independence.
# ---------------------------------------------------------------------------


class IntegrationsIndependentFromAddons(unittest.TestCase):
    """The presence/absence of an integration does not affect addon detection."""

    def test_jwt_and_oauth_independent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"firebase/php-jwt": "^6.0"})
            self.assertTrue(detect_jwt_generic(root))
            self.assertFalse(detect_oauth_oidc(root))

    def test_oauth_without_jwt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"league/oauth2-client": "^2.7"})
            self.assertFalse(detect_jwt_generic(root))
            self.assertTrue(detect_oauth_oidc(root))


# ---------------------------------------------------------------------------
# _stack_block propagates detected_integrations.
# ---------------------------------------------------------------------------


class StackBlockPropagatesIntegrations(unittest.TestCase):
    """`_stack_block(...)` must surface `detected_integrations` as `stack.integrations`."""

    def _fake_recipe(self):
        from recon.types import StackMatch

        class _Rec:
            RECIPE_NAME = "symfony"
            LANGUAGE = "php"

            @staticmethod
            def detect(_project_root):
                return StackMatch(
                    name="symfony", version="^7.0", confidence=1.0,
                    evidence=["composer.json"],
                )

        return _Rec()

    def test_integrations_emitted_sorted(self):
        import recon_inventory as ri
        with tempfile.TemporaryDirectory() as td:
            block = ri._stack_block(
                self._fake_recipe(),
                Path(td),
                detected_integrations=["oauth-oidc", "jwt-generic"],
            )
            self.assertEqual(block.get("integrations"), ["jwt-generic", "oauth-oidc"])

    def test_integrations_omitted_when_empty(self):
        import recon_inventory as ri
        with tempfile.TemporaryDirectory() as td:
            block = ri._stack_block(
                self._fake_recipe(), Path(td), detected_integrations=[],
            )
            self.assertNotIn("integrations", block)

    def test_integrations_omitted_when_argument_missing(self):
        import recon_inventory as ri
        with tempfile.TemporaryDirectory() as td:
            block = ri._stack_block(self._fake_recipe(), Path(td))
            self.assertNotIn("integrations", block)

    def test_integrations_coexist_with_addons(self):
        """A single project may declare both addons and integrations."""
        import recon_inventory as ri
        with tempfile.TemporaryDirectory() as td:
            block = ri._stack_block(
                self._fake_recipe(), Path(td),
                detected_addons=["easyadmin"],
                detected_integrations=["jwt-generic"],
            )
            self.assertEqual(block.get("addons"), ["easyadmin"])
            self.assertEqual(block.get("integrations"), ["jwt-generic"])


# ---------------------------------------------------------------------------
# End-to-end: inject composer dep into symfony_minimal, run recon, assert
# stack.integrations populated + validate_context passes.
# ---------------------------------------------------------------------------


class FrontmatterIntegrationsEndToEnd(unittest.TestCase):
    """End-to-end check: composer.json with JWT/OAuth dep → frontmatter integrations."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    def _extract_integrations(self, text: str) -> list[str]:
        """Pull `stack.integrations:` list out of frontmatter."""
        m = FRONTMATTER_RE.match(text)
        if not m:
            return []
        fm = parse_yaml_subset(m.group(1))
        stack = fm.get("stack") if isinstance(fm, dict) else None
        if not isinstance(stack, dict):
            return []
        integrations = stack.get("integrations")
        return list(integrations) if isinstance(integrations, list) else []

    def _run_with_injected_package(self, fixture: str, package: str, version: str) -> str:
        """Copy fixture, inject `package: version` into composer.json, run recon, return CONTEXT.md text."""
        import shutil as _shutil
        import subprocess as _subprocess
        if _shutil.which("php") is None:
            self.skipTest("php not on PATH")
        fix_path = self.fixtures_dir / fixture
        if not fix_path.is_dir():
            self.skipTest(f"fixture {fixture} not present")
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _shutil.copytree(fix_path, proj)
            composer_path = proj / "composer.json"
            data = json.loads(composer_path.read_text(encoding="utf-8"))
            data.setdefault("require", {})[package] = version
            composer_path.write_text(json.dumps(data), encoding="utf-8")

            review_root = Path(td) / "review"
            review_root.mkdir()
            proc = _subprocess.run(
                [
                    sys.executable,
                    str(_BIN / "recon_inventory.py"),
                    str(proj),
                    "--recipe", "symfony",
                    "--review-root", str(review_root),
                    "--no-console",
                ],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            ctx_path = review_root / "CONTEXT.md"
            text = ctx_path.read_text(encoding="utf-8")
            # Validate the emitted CONTEXT.md round-trips through the schema
            # validator — defense-in-depth for the new `stack.integrations`
            # path through the YAML emitter.
            from validate_context import validate_context_file  # noqa: E402
            res = validate_context_file(ctx_path)
            self.assertTrue(
                res.ok(),
                msg=f"validate_context failed: {res.errors}",
            )
            return text

    def test_firebase_php_jwt_injected_yields_jwt_generic(self):
        text = self._run_with_injected_package(
            "symfony_minimal", "firebase/php-jwt", "^6.0",
        )
        integrations = self._extract_integrations(text)
        self.assertIn("jwt-generic", integrations)
        self.assertNotIn("oauth-oidc", integrations)

    def test_league_oauth2_client_injected_yields_oauth_oidc(self):
        text = self._run_with_injected_package(
            "symfony_minimal", "league/oauth2-client", "^2.7",
        )
        integrations = self._extract_integrations(text)
        self.assertIn("oauth-oidc", integrations)
        self.assertNotIn("jwt-generic", integrations)

    def _extract_addons(self, text: str) -> list[str]:
        """Pull `stack.addons:` list out of frontmatter."""
        m = FRONTMATTER_RE.match(text)
        if not m:
            return []
        fm = parse_yaml_subset(m.group(1))
        stack = fm.get("stack") if isinstance(fm, dict) else None
        if not isinstance(stack, dict):
            return []
        addons = stack.get("addons")
        return list(addons) if isinstance(addons, list) else []

    def test_addon_and_integration_coexist(self):
        """Inject BOTH EasyAdmin (addon) AND firebase/php-jwt (integration);
        recon must surface both in frontmatter without one masking the other.
        """
        import shutil as _shutil
        import subprocess as _subprocess
        if _shutil.which("php") is None:
            self.skipTest("php not on PATH")
        fix_path = self.fixtures_dir / "symfony_minimal"
        if not fix_path.is_dir():
            self.skipTest("symfony_minimal fixture not present")
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _shutil.copytree(fix_path, proj)
            composer_path = proj / "composer.json"
            data = json.loads(composer_path.read_text(encoding="utf-8"))
            data.setdefault("require", {})["easycorp/easyadmin-bundle"] = "^4.0"
            data.setdefault("require", {})["firebase/php-jwt"] = "^6.0"
            composer_path.write_text(json.dumps(data), encoding="utf-8")

            review_root = Path(td) / "review"
            review_root.mkdir()
            proc = _subprocess.run(
                [
                    sys.executable,
                    str(_BIN / "recon_inventory.py"),
                    str(proj),
                    "--recipe", "symfony",
                    "--review-root", str(review_root),
                    "--no-console",
                ],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")
            addons = self._extract_addons(text)
            integrations = self._extract_integrations(text)
            self.assertIn("easyadmin", addons,
                          msg=f"easyadmin missing from addons={addons}")
            self.assertIn("jwt-generic", integrations,
                          msg=f"jwt-generic missing from integrations={integrations}")

    def test_minimal_fixture_has_no_integrations(self):
        import shutil as _shutil
        import subprocess as _subprocess
        if _shutil.which("php") is None:
            self.skipTest("php not on PATH")
        fix_path = self.fixtures_dir / "symfony_minimal"
        if not fix_path.is_dir():
            self.skipTest("symfony_minimal fixture not present")
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            review_root.mkdir()
            proc = _subprocess.run(
                [
                    sys.executable,
                    str(_BIN / "recon_inventory.py"),
                    str(fix_path),
                    "--recipe", "symfony",
                    "--review-root", str(review_root),
                    "--no-console",
                ],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")
            integrations = self._extract_integrations(text)
            self.assertEqual(integrations, [])


# ---------------------------------------------------------------------------
# Resolver: ctx.integrations -> integrations/{name}/{theme}.md is loaded.
# ---------------------------------------------------------------------------


class ResolverLoadsIntegrationChecklist(unittest.TestCase):
    """Stage 0 resolver must surface `integrations/jwt-generic/auth.md` when
    `ctx.integrations` contains `jwt-generic`.

    This is a regression guard: Stage 0 wired the resolver, Stage 4 lights up
    real content under `integrations/jwt-generic/`. If anyone breaks the
    filesystem path in `resolve_checklists`, this test catches it.
    """

    def test_jwt_generic_auth_loaded(self):
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="symfony",
            addons=(),
            integrations=("jwt-generic",),
        )
        files = resolve_checklists(("auth",), ctx, plugin_root)
        # Expect: core/auth.md, stacks/symfony/auth.md, integrations/jwt-generic/auth.md.
        # Order matters — least specific first.
        as_str = [str(p) for p in files]
        self.assertTrue(any(p.endswith("checklists/core/auth.md") for p in as_str),
                        msg=f"core/auth.md missing in chain: {as_str}")
        self.assertTrue(
            any(p.endswith("checklists/integrations/jwt-generic/auth.md") for p in as_str),
            msg=f"integrations/jwt-generic/auth.md missing in chain: {as_str}",
        )

    def test_jwt_generic_crypto_loaded(self):
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="symfony",
            addons=(),
            integrations=("jwt-generic",),
        )
        files = resolve_checklists(("crypto",), ctx, plugin_root)
        as_str = [str(p) for p in files]
        self.assertTrue(
            any(p.endswith("checklists/integrations/jwt-generic/crypto.md") for p in as_str),
            msg=f"integrations/jwt-generic/crypto.md missing in chain: {as_str}",
        )

    def test_oauth_oidc_auth_loaded(self):
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="laravel",
            addons=(),
            integrations=("oauth-oidc",),
        )
        files = resolve_checklists(("auth",), ctx, plugin_root)
        as_str = [str(p) for p in files]
        self.assertTrue(
            any(p.endswith("checklists/integrations/oauth-oidc/auth.md") for p in as_str),
            msg=f"integrations/oauth-oidc/auth.md missing in chain: {as_str}",
        )

    def test_integration_layer_independent_of_stack(self):
        """Integrations must apply even when stack ∈ {none, unknown}."""
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="none",
            addons=(),
            integrations=("jwt-generic",),
        )
        files = resolve_checklists(("auth",), ctx, plugin_root)
        as_str = [str(p) for p in files]
        # Stack layer skipped (stack=none), but integration MUST still load.
        self.assertTrue(
            any(p.endswith("checklists/integrations/jwt-generic/auth.md") for p in as_str),
            msg=f"jwt-generic/auth.md must load on stack=none: {as_str}",
        )

    def test_no_integration_no_load(self):
        """Empty integrations list ⇒ no integration files in the chain."""
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="symfony",
            addons=(),
            integrations=(),
        )
        files = resolve_checklists(("auth",), ctx, plugin_root)
        as_str = [str(p) for p in files]
        self.assertFalse(any("/integrations/" in p for p in as_str),
                         msg=f"no integration file should appear: {as_str}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
