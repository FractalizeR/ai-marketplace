"""Unit tests for provider-specific integration detectors (Stage 5).

Covers the lightweight composer+env+config-based detectors for:
- recon.recipes.auth0_detect.detect_auth0
- recon.recipes.aws_cognito_detect.detect_aws_cognito
- recon.recipes.okta_detect.detect_okta
- recon.recipes.keycloak_detect.detect_keycloak
- recon.recipes.firebase_auth_detect.detect_firebase_auth

Plus end-to-end propagation through `InventoryResult.detected_integrations`
into `frontmatter.stack.integrations` (parallel to Stage 4's
`FrontmatterIntegrationsEndToEnd`), and a resolver-layer test confirming
that `integrations/{provider}/auth.md` is picked up when the integration is
active in `ResolutionContext`.

The probes are intentionally cheap. Cognito and Okta also probe PHP source
files — the source-scan tests use ephemeral directories with hand-written
fixtures.
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

from recon.recipes.auth0_detect import detect_auth0  # noqa: E402
from recon.recipes.aws_cognito_detect import detect_aws_cognito  # noqa: E402
from recon.recipes.okta_detect import detect_okta  # noqa: E402
from recon.recipes.keycloak_detect import detect_keycloak  # noqa: E402
from recon.recipes.firebase_auth_detect import detect_firebase_auth  # noqa: E402
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402


def _write_composer(root: Path, *, require: dict | None = None, require_dev: dict | None = None) -> None:
    data: dict = {"name": "fixture/inline", "type": "project"}
    if require is not None:
        data["require"] = require
    if require_dev is not None:
        data["require-dev"] = require_dev
    (root / "composer.json").write_text(json.dumps(data), encoding="utf-8")


def _write_php_source(root: Path, rel: str, body: str) -> None:
    """Drop a PHP source file at root/rel with the given body."""
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# detect_auth0 — composer + env + config probes.
# ---------------------------------------------------------------------------


class DetectAuth0Tests(unittest.TestCase):
    def test_returns_true_for_auth0_auth0_php(self):
        """`auth0/auth0-php` is the official SDK."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"auth0/auth0-php": "^8.0"})
            self.assertTrue(detect_auth0(root))

    def test_returns_true_for_auth0_symfony(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"auth0/symfony": "^5.0"})
            self.assertTrue(detect_auth0(root))

    def test_returns_true_for_auth0_jwt_auth_bundle(self):
        """Symfony JWT bundle — verified to exist on packagist."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"auth0/jwt-auth-bundle": "^5.0"})
            self.assertTrue(detect_auth0(root))

    def test_returns_true_for_auth0_login(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"auth0/login": "^8.0"})
            self.assertTrue(detect_auth0(root))

    def test_returns_true_via_env_auth0_domain(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / ".env").write_text(
                "APP_ENV=dev\nAUTH0_DOMAIN=tenant.auth0.com\n", encoding="utf-8",
            )
            self.assertTrue(detect_auth0(root))

    def test_returns_true_via_laravel_config(self):
        """`config/auth0.php` (Laravel vendor:publish) is a positive signal."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/framework": "^11.0"})
            (root / "config").mkdir(parents=True)
            (root / "config" / "auth0.php").write_text(
                "<?php return ['default' => env('AUTH0_DOMAIN')];\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_auth0(root))

    def test_returns_true_via_symfony_config(self):
        """`config/packages/auth0.yaml` (Symfony bundle) is a positive signal."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "config" / "packages").mkdir(parents=True)
            (root / "config" / "packages" / "auth0.yaml").write_text(
                "auth0:\n    domain: '%env(AUTH0_DOMAIN)%'\n", encoding="utf-8",
            )
            self.assertTrue(detect_auth0(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_auth0(root))


# ---------------------------------------------------------------------------
# detect_aws_cognito — composer + env + source probes.
# ---------------------------------------------------------------------------


class DetectAwsCognitoTests(unittest.TestCase):
    def test_returns_true_for_async_aws_cognito_identity_provider(self):
        """`async-aws/cognito-identity-provider` — split-SDK Cognito client."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"async-aws/cognito-identity-provider": "^2.0"})
            self.assertTrue(detect_aws_cognito(root))

    def test_returns_true_for_ellaisys_aws_cognito(self):
        """`ellaisys/aws-cognito` — Laravel Cognito guard."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"ellaisys/aws-cognito": "^1.0"})
            self.assertTrue(detect_aws_cognito(root))

    def test_returns_true_for_socialiteproviders_cognito(self):
        """`socialiteproviders/cognito` — Laravel Socialite provider."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"socialiteproviders/cognito": "^4.0"})
            self.assertTrue(detect_aws_cognito(root))

    def test_returns_true_via_env_cognito_pool(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/framework": "^11.0"})
            (root / ".env").write_text(
                "COGNITO_USER_POOL_ID=us-east-1_ABC123\n", encoding="utf-8",
            )
            self.assertTrue(detect_aws_cognito(root))

    def test_returns_true_via_env_aws_cognito_pool(self):
        """The `AWS_COGNITO_POOL_ID` env name is also accepted."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "AWS_COGNITO_POOL_ID=us-east-1_ABC123\n", encoding="utf-8",
            )
            self.assertTrue(detect_aws_cognito(root))

    def test_returns_true_via_source_class_name(self):
        """`CognitoIdentityProviderClient` in PHP source fires detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"aws/aws-sdk-php": "^3.0"})
            _write_php_source(
                root, "src/Auth/CognitoService.php",
                "<?php\n"
                "use Aws\\CognitoIdentityProvider\\CognitoIdentityProviderClient;\n"
                "class CognitoService {}\n",
            )
            self.assertTrue(detect_aws_cognito(root))

    def test_returns_true_via_source_cognito_idp_url(self):
        """`cognito-idp.` URL substring in PHP source fires detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"firebase/php-jwt": "^6.0"})
            _write_php_source(
                root, "src/Auth/Validator.php",
                "<?php\n"
                "$iss = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_X';\n",
            )
            self.assertTrue(detect_aws_cognito(root))

    def test_returns_false_for_umbrella_aws_sdk_alone(self):
        """`aws/aws-sdk-php` alone is INTENTIONALLY not a signal (used for S3 etc)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"aws/aws-sdk-php": "^3.0"})
            # No Cognito source / env signals.
            _write_php_source(root, "src/S3Service.php",
                              "<?php\nuse Aws\\S3\\S3Client;\n")
            self.assertFalse(detect_aws_cognito(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_aws_cognito(root))


# ---------------------------------------------------------------------------
# detect_okta — composer + env + source probes.
# ---------------------------------------------------------------------------


class DetectOktaTests(unittest.TestCase):
    def test_returns_true_for_okta_jwt_verifier(self):
        """`okta/jwt-verifier` — official JWT verifier (real packagist name)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"okta/jwt-verifier": "^1.0"})
            self.assertTrue(detect_okta(root))

    def test_returns_true_for_okta_sdk(self):
        """`okta/sdk` — official SDK (real packagist name)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"okta/sdk": "^2.0"})
            self.assertTrue(detect_okta(root))

    def test_returns_true_for_socialiteproviders_okta(self):
        """`socialiteproviders/okta` — Laravel Socialite Okta provider."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"socialiteproviders/okta": "^4.0"})
            self.assertTrue(detect_okta(root))

    def test_returns_true_for_foxworth42_oauth2_okta(self):
        """`foxworth42/oauth2-okta` — league/oauth2-client Okta provider."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"foxworth42/oauth2-okta": "^1.0"})
            self.assertTrue(detect_okta(root))

    def test_returns_true_via_env_okta_domain(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text("OKTA_DOMAIN=dev-12345.okta.com\n", encoding="utf-8")
            self.assertTrue(detect_okta(root))

    def test_returns_true_via_env_okta_issuer(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "OKTA_ISSUER=https://dev-12345.okta.com/oauth2/default\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_okta(root))

    def test_returns_true_via_source_okta_com_url(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"firebase/php-jwt": "^6.0"})
            _write_php_source(
                root, "src/Auth/OktaValidator.php",
                "<?php\n$iss = 'https://dev-12345.okta.com/oauth2/default';\n",
            )
            self.assertTrue(detect_okta(root))

    def test_returns_true_via_source_oktapreview(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"firebase/php-jwt": "^6.0"})
            _write_php_source(
                root, "src/Auth/PreviewValidator.php",
                "<?php\n$iss = 'https://dev-12345.oktapreview.com/oauth2/default';\n",
            )
            self.assertTrue(detect_okta(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_okta(root))


# ---------------------------------------------------------------------------
# detect_keycloak — composer + env + (conjunctive) source probes.
# ---------------------------------------------------------------------------


class DetectKeycloakTests(unittest.TestCase):
    def test_returns_true_for_stevenmaguire_oauth2_keycloak(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"stevenmaguire/oauth2-keycloak": "^5.0"})
            self.assertTrue(detect_keycloak(root))

    def test_nbgrp_oidc_bundle_does_NOT_trigger_keycloak(self):
        """`nbgrp/oidc-bundle` is a GENERIC OIDC bundle (Auth0, Okta, Google,
        Keycloak, …). It belongs to the `oauth-oidc` integration, NOT to
        Keycloak — installing it does NOT prove the project talks to Keycloak.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"nbgrp/oidc-bundle": "^1.0"})
            self.assertFalse(detect_keycloak(root))

    def test_returns_true_for_keycloak_admin_client(self):
        """`mohammad-waleed/keycloak-admin-client` — real Keycloak admin REST client."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"mohammad-waleed/keycloak-admin-client": "^1.0"})
            self.assertTrue(detect_keycloak(root))

    def test_returns_true_for_robsontenorio_laravel_keycloak_guard(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"robsontenorio/laravel-keycloak-guard": "^2.0"})
            self.assertTrue(detect_keycloak(root))

    def test_returns_true_for_socialiteproviders_keycloak(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"socialiteproviders/keycloak": "^4.0"})
            self.assertTrue(detect_keycloak(root))

    def test_returns_true_via_env_keycloak_url(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text(
                "KEYCLOAK_URL=https://sso.example.com\nKEYCLOAK_REALM=myrealm\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_keycloak(root))

    def test_returns_true_via_conjunctive_url_substrings(self):
        """`/realms/` AND `/protocol/openid-connect/` together fire detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"firebase/php-jwt": "^6.0"})
            _write_php_source(
                root, "src/Auth/KeycloakValidator.php",
                "<?php\n"
                "$tokenUrl = 'https://sso.example.com/realms/myrealm"
                "/protocol/openid-connect/token';\n",
            )
            self.assertTrue(detect_keycloak(root))

    def test_returns_false_for_realms_only(self):
        """`/realms/` alone (no `/protocol/openid-connect/`) MUST NOT fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            _write_php_source(
                root, "src/Domain/Realms.php",
                "<?php\n// Domain code with the word /realms/ in a path string.\n"
                "$rel = '/realms/internal';\n",
            )
            self.assertFalse(detect_keycloak(root))

    def test_returns_false_for_openid_connect_only(self):
        """`/protocol/openid-connect/` alone MUST NOT fire (no Keycloak realm hint)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            _write_php_source(
                root, "src/Docs/Notes.php",
                "<?php\n"
                "// Compliance note mentioning /protocol/openid-connect/token endpoint shape.\n",
            )
            self.assertFalse(detect_keycloak(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_keycloak(root))


# ---------------------------------------------------------------------------
# detect_firebase_auth — composer + env + service-account JSON probes.
# ---------------------------------------------------------------------------


class DetectFirebaseAuthTests(unittest.TestCase):
    def test_returns_true_for_kreait_firebase_php(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"kreait/firebase-php": "^7.0"})
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_true_for_kreait_firebase_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"kreait/firebase-bundle": "^5.0"})
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_true_for_kreait_laravel_firebase(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"kreait/laravel-firebase": "^5.0"})
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_true_via_env_firebase_project_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text(
                "FIREBASE_PROJECT_ID=my-firebase-proj\n", encoding="utf-8",
            )
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_false_for_bare_google_application_credentials(self):
        """`GOOGLE_APPLICATION_CREDENTIALS` ALONE is too broad — any Google SDK
        uses it (Cloud Storage, BigQuery, …). Firebase-Auth detection must NOT
        fire without a Firebase-specific corroboration hint in the same file.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "GOOGLE_APPLICATION_CREDENTIALS=/srv/secrets/google.json\n",
                encoding="utf-8",
            )
            self.assertFalse(detect_firebase_auth(root))

    def test_returns_true_for_gac_with_firebase_hint(self):
        """When `GOOGLE_APPLICATION_CREDENTIALS` is present AND the env file
        also mentions `firebase` (in a comment, key, or value), detection fires.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "# Firebase Admin SDK credentials.\n"
                "GOOGLE_APPLICATION_CREDENTIALS=/srv/secrets/google.json\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_true_via_service_account_in_root(self):
        """`firebase-adminsdk-*.json` in repo root fires detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "firebase-adminsdk-abc123.json").write_text(
                '{"type":"service_account"}', encoding="utf-8",
            )
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_true_via_service_account_realistic_console_name(self):
        """The real Firebase console name `{project-id}-firebase-adminsdk-{key-id}.json`
        must fire — the regex must NOT anchor at the start of the filename.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "myproject-firebase-adminsdk-fbsvc-abc123.json").write_text(
                '{"type":"service_account"}', encoding="utf-8",
            )
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_true_via_service_account_in_config(self):
        """`config/firebase-adminsdk-*.json` fires detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "config").mkdir(parents=True)
            (root / "config" / "firebase-adminsdk-xyz.json").write_text(
                '{"type":"service_account"}', encoding="utf-8",
            )
            self.assertTrue(detect_firebase_auth(root))

    def test_returns_false_for_unrelated_json(self):
        """A JSON file that doesn't match the firebase-adminsdk pattern MUST NOT fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "service-account.json").write_text(
                '{"type":"service_account"}', encoding="utf-8",
            )
            self.assertFalse(detect_firebase_auth(root))

    def test_returns_false_for_generic_firebase_config_json(self):
        """A `firebase-config.json` file (no `firebase-adminsdk-…` substring) MUST NOT fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "firebase-config.json").write_text(
                '{"projectId":"x"}', encoding="utf-8",
            )
            self.assertFalse(detect_firebase_auth(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_firebase_auth(root))


# ---------------------------------------------------------------------------
# Provider independence — one provider's signal MUST NOT trigger the others.
# ---------------------------------------------------------------------------


class ProviderDetectorsIndependent(unittest.TestCase):
    def test_auth0_does_not_trigger_others(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"auth0/auth0-php": "^8.0"})
            self.assertTrue(detect_auth0(root))
            self.assertFalse(detect_aws_cognito(root))
            self.assertFalse(detect_okta(root))
            self.assertFalse(detect_keycloak(root))
            self.assertFalse(detect_firebase_auth(root))

    def test_okta_does_not_trigger_others(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"okta/jwt-verifier": "^1.0"})
            self.assertTrue(detect_okta(root))
            self.assertFalse(detect_auth0(root))
            self.assertFalse(detect_aws_cognito(root))
            self.assertFalse(detect_keycloak(root))
            self.assertFalse(detect_firebase_auth(root))


# ---------------------------------------------------------------------------
# End-to-end: inject composer dep into symfony_minimal, run recon, assert
# stack.integrations populated + validate_context passes. Mirror of Stage 4's
# `FrontmatterIntegrationsEndToEnd`.
# ---------------------------------------------------------------------------


class FrontmatterProviderIntegrationsEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    def _extract_integrations(self, text: str) -> list[str]:
        m = FRONTMATTER_RE.match(text)
        if not m:
            return []
        fm = parse_yaml_subset(m.group(1))
        stack = fm.get("stack") if isinstance(fm, dict) else None
        if not isinstance(stack, dict):
            return []
        integrations = stack.get("integrations")
        return list(integrations) if isinstance(integrations, list) else []

    def _run_with_injected_package(self, package: str, version: str) -> str:
        """Inject composer dep + run recon + validate. Return CONTEXT.md text."""
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
            from validate_context import validate_context_file  # noqa: E402
            res = validate_context_file(ctx_path)
            self.assertTrue(
                res.ok(),
                msg=f"validate_context failed: {res.errors}",
            )
            return text

    def test_auth0_php_injected_yields_auth0(self):
        text = self._run_with_injected_package("auth0/auth0-php", "^8.0")
        integrations = self._extract_integrations(text)
        self.assertIn("auth0", integrations)

    def test_cognito_split_sdk_injected_yields_aws_cognito(self):
        """Real packagist name: `async-aws/cognito-identity-provider`."""
        text = self._run_with_injected_package("async-aws/cognito-identity-provider", "^2.0")
        integrations = self._extract_integrations(text)
        self.assertIn("aws-cognito", integrations)

    def test_okta_jwt_verifier_injected_yields_okta(self):
        """Real packagist name: `okta/jwt-verifier` (no `-php` suffix)."""
        text = self._run_with_injected_package("okta/jwt-verifier", "^1.0")
        integrations = self._extract_integrations(text)
        self.assertIn("okta", integrations)

    def test_keycloak_socialite_injected_yields_keycloak(self):
        """Real packagist name: `socialiteproviders/keycloak`."""
        text = self._run_with_injected_package("socialiteproviders/keycloak", "^4.0")
        integrations = self._extract_integrations(text)
        self.assertIn("keycloak", integrations)

    def test_firebase_php_injected_yields_firebase_auth(self):
        text = self._run_with_injected_package("kreait/firebase-php", "^7.0")
        integrations = self._extract_integrations(text)
        self.assertIn("firebase-auth", integrations)


# ---------------------------------------------------------------------------
# Combo: provider AND generic jwt-generic must co-exist (refinement, not
# replacement). Verifies _meta.md's "Five-layer structure" invariant.
# ---------------------------------------------------------------------------


class ProviderAndGenericCoexist(unittest.TestCase):
    def test_auth0_and_jwt_generic_both_detected(self):
        """A project with `auth0/auth0-php` AND `firebase/php-jwt` should surface BOTH
        `auth0` and `jwt-generic` — the provider checklist refines the generic one.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(
                root,
                require={"auth0/auth0-php": "^8.0", "firebase/php-jwt": "^6.0"},
            )
            from recon.recipes.jwt_generic_detect import detect_jwt_generic
            self.assertTrue(detect_auth0(root))
            self.assertTrue(detect_jwt_generic(root))

    def test_resolver_loads_both_layers(self):
        """`ctx.integrations=('auth0', 'jwt-generic')` → both auth.md files in chain."""
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="symfony",
            addons=(),
            integrations=("auth0", "jwt-generic"),
        )
        files = resolve_checklists(("auth",), ctx, plugin_root)
        as_str = [str(p) for p in files]
        self.assertTrue(
            any(p.endswith("checklists/integrations/jwt-generic/auth.md") for p in as_str),
            msg=f"jwt-generic/auth.md missing in chain: {as_str}",
        )
        self.assertTrue(
            any(p.endswith("checklists/integrations/auth0/auth.md") for p in as_str),
            msg=f"auth0/auth.md missing in chain: {as_str}",
        )


# ---------------------------------------------------------------------------
# Resolver: ctx.integrations -> integrations/{provider}/auth.md loads.
# One combined test per provider — exhaustive coverage with minimal redundancy.
# ---------------------------------------------------------------------------


class ResolverLoadsProviderChecklist(unittest.TestCase):
    """For each provider, the resolver must load its `auth.md`."""

    def _resolved(self, integration: str) -> list[str]:
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="symfony",
            addons=(),
            integrations=(integration,),
        )
        files = resolve_checklists(("auth",), ctx, plugin_root)
        return [str(p) for p in files]

    def test_auth0_auth_loaded(self):
        files = self._resolved("auth0")
        self.assertTrue(
            any(p.endswith("checklists/integrations/auth0/auth.md") for p in files),
            msg=f"auth0/auth.md missing: {files}",
        )

    def test_aws_cognito_auth_loaded(self):
        files = self._resolved("aws-cognito")
        self.assertTrue(
            any(p.endswith("checklists/integrations/aws-cognito/auth.md") for p in files),
            msg=f"aws-cognito/auth.md missing: {files}",
        )

    def test_okta_auth_loaded(self):
        files = self._resolved("okta")
        self.assertTrue(
            any(p.endswith("checklists/integrations/okta/auth.md") for p in files),
            msg=f"okta/auth.md missing: {files}",
        )

    def test_keycloak_auth_loaded(self):
        files = self._resolved("keycloak")
        self.assertTrue(
            any(p.endswith("checklists/integrations/keycloak/auth.md") for p in files),
            msg=f"keycloak/auth.md missing: {files}",
        )

    def test_firebase_auth_auth_loaded(self):
        files = self._resolved("firebase-auth")
        self.assertTrue(
            any(p.endswith("checklists/integrations/firebase-auth/auth.md") for p in files),
            msg=f"firebase-auth/auth.md missing: {files}",
        )


# ---------------------------------------------------------------------------
# Source-scan hardening — symlinks into vendor/ cannot smuggle markers
# through the filter, and vendor-tree files do not exhaust the scan cap.
# Applies to all three source-scan probes (aws_cognito, okta, keycloak).
# ---------------------------------------------------------------------------


class SourceScanVendorHardening(unittest.TestCase):
    def _make_vendor_with_cognito_marker(self, root: Path) -> Path:
        vendor_dir = root / "vendor" / "aws"
        vendor_dir.mkdir(parents=True)
        target = vendor_dir / "Cognito.php"
        target.write_text(
            "<?php\nclass CognitoIdentityProviderClient {}\n", encoding="utf-8",
        )
        return target

    def test_cognito_symlink_into_vendor_does_not_fire(self):
        """`src/foo.php` -> `../vendor/.../Cognito.php` MUST NOT trigger a vendor marker.

        The resolved path-based vendor-skip is the guard.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            target = self._make_vendor_with_cognito_marker(root)
            src_dir = root / "src"
            src_dir.mkdir()
            link = src_dir / "Cognito.php"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            self.assertFalse(detect_aws_cognito(root))

    def test_cognito_scan_cap_not_exhausted_by_vendor_files(self):
        """The cap counter MUST only increment on non-vendor files — a project
        with many `src/vendor/*.php` files (or vendor symlinks) still reaches
        the real `src/Foo.php` that contains the Cognito marker.

        We create ~600 dummy `src/vendor/dummyN.php` files (> _SCAN_MAX_FILES=500)
        and a single `src/Real.php` with the marker. Real must still be
        detected.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            src_vendor = root / "src" / "vendor"
            src_vendor.mkdir(parents=True)
            for i in range(600):
                (src_vendor / f"dummy{i}.php").write_text(
                    "<?php\nclass D {}\n", encoding="utf-8",
                )
            (root / "src" / "Real.php").write_text(
                "<?php\nuse Aws\\CognitoIdentityProvider\\CognitoIdentityProviderClient;\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_aws_cognito(root))

    def test_okta_symlink_into_vendor_does_not_fire(self):
        """Same invariant for Okta — vendor markers are not smuggled through."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            vendor_dir = root / "vendor" / "okta"
            vendor_dir.mkdir(parents=True)
            target = vendor_dir / "Tenant.php"
            target.write_text(
                "<?php\n$iss = 'https://dev-12345.okta.com/oauth2/default';\n",
                encoding="utf-8",
            )
            src_dir = root / "src"
            src_dir.mkdir()
            link = src_dir / "Tenant.php"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            self.assertFalse(detect_okta(root))

    def test_keycloak_symlink_into_vendor_does_not_fire(self):
        """Same invariant for Keycloak — conjunctive markers in a vendor file
        reached via a symlink MUST NOT fire detection.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            vendor_dir = root / "vendor" / "keycloak"
            vendor_dir.mkdir(parents=True)
            target = vendor_dir / "Server.php"
            target.write_text(
                "<?php\n$u = 'https://sso/realms/r/protocol/openid-connect/token';\n",
                encoding="utf-8",
            )
            src_dir = root / "src"
            src_dir.mkdir()
            link = src_dir / "Server.php"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            self.assertFalse(detect_keycloak(root))


# ---------------------------------------------------------------------------
# Provider implication invariant — detecting a provider MUST force-include
# its generic layers (jwt-generic, oauth-oidc), even if the generic detectors
# wouldn't fire on their own. Mirrors `_shared.PROVIDER_IMPLIES_INTEGRATIONS`.
# ---------------------------------------------------------------------------


class ProviderImpliesGenericLayers(unittest.TestCase):
    def test_expand_provider_implications_auth0(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["auth0"])))
        self.assertEqual(out, ["auth0", "jwt-generic", "oauth-oidc"])

    def test_expand_provider_implications_aws_cognito(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["aws-cognito"])))
        self.assertEqual(out, ["aws-cognito", "jwt-generic", "oauth-oidc"])

    def test_expand_provider_implications_okta(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["okta"])))
        self.assertEqual(out, ["jwt-generic", "oauth-oidc", "okta"])

    def test_expand_provider_implications_keycloak(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["keycloak"])))
        self.assertEqual(out, ["jwt-generic", "keycloak", "oauth-oidc"])

    def test_expand_provider_implications_firebase_only_jwt(self):
        """Firebase implies jwt-generic but NOT oauth-oidc."""
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["firebase-auth"])))
        self.assertEqual(out, ["firebase-auth", "jwt-generic"])

    def test_expand_idempotent_when_already_present(self):
        """If generic layers were already detected, expand_provider_implications is a no-op
        on those entries (it doesn't duplicate).
        """
        from recon.recipes._shared import expand_provider_implications
        out = expand_provider_implications(["auth0", "jwt-generic"])
        # No duplicates introduced; oauth-oidc added.
        self.assertEqual(sorted(set(out)), ["auth0", "jwt-generic", "oauth-oidc"])
        # `out` itself MUST NOT contain duplicates of "jwt-generic".
        self.assertEqual(out.count("jwt-generic"), 1)

    def test_symfony_recipe_auth0_implies_generic_layers(self):
        """In the symfony recipe, a project with `auth0/auth0-php` alone (no other
        JWT library, no OAuth library) MUST yield integrations = ['auth0',
        'jwt-generic', 'oauth-oidc'] in InventoryResult.detected_integrations.

        Verifies that the implication is wired into `build_inventory`, not just
        the shared helper. Uses the `plugin_root=None` skeleton path so the
        test doesn't depend on the PHP extractor / php binary.
        """
        from recon.recipes.symfony import build_inventory as symfony_build
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"auth0/auth0-php": "^8.0"})
            # plugin_root=None → _empty_skeleton, which still runs detect
            # probes when project_root is passed.
            res = symfony_build(root)
            integrations = sorted(set(res.detected_integrations))
            self.assertIn("auth0", integrations)
            self.assertIn("jwt-generic", integrations)
            self.assertIn("oauth-oidc", integrations)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
