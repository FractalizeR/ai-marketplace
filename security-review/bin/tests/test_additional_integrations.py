"""Unit tests for Stage 7 additional integrations.

Covers vendor-neutral / vendor-specific detectors for:
- recon.recipes.stripe_detect.detect_stripe
- recon.recipes.aws_secrets_manager_detect.detect_aws_secrets_manager
- recon.recipes.vault_detect.detect_vault
- recon.recipes.saml_detect.detect_saml
- recon.recipes.webauthn_passkeys_detect.detect_webauthn_passkeys

Plus end-to-end propagation through `InventoryResult.detected_integrations`
into `frontmatter.stack.integrations` (parallel to Stage 5's pattern), and
resolver-layer tests confirming that `integrations/{integration}/{theme}.md`
is picked up when the integration is active in `ResolutionContext`.
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

from recon.recipes.stripe_detect import detect_stripe  # noqa: E402
from recon.recipes.aws_secrets_manager_detect import detect_aws_secrets_manager  # noqa: E402
from recon.recipes.vault_detect import detect_vault  # noqa: E402
from recon.recipes.saml_detect import detect_saml  # noqa: E402
from recon.recipes.webauthn_passkeys_detect import detect_webauthn_passkeys  # noqa: E402
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402


def _write_composer(root: Path, *, require: dict | None = None, require_dev: dict | None = None) -> None:
    data: dict = {"name": "fixture/inline", "type": "project"}
    if require is not None:
        data["require"] = require
    if require_dev is not None:
        data["require-dev"] = require_dev
    (root / "composer.json").write_text(json.dumps(data), encoding="utf-8")


def _write_php_source(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# detect_stripe — composer + env + source probes.
# ---------------------------------------------------------------------------


class DetectStripeTests(unittest.TestCase):
    def test_returns_true_for_stripe_stripe_php(self):
        """`stripe/stripe-php` is the official PHP SDK."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"stripe/stripe-php": "^13.0"})
            self.assertTrue(detect_stripe(root))

    def test_returns_true_for_laravel_cashier(self):
        """`laravel/cashier` is the official Laravel Cashier (Stripe) bridge."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"laravel/cashier": "^15.0"})
            self.assertTrue(detect_stripe(root))

    def test_returns_true_for_omnipay_stripe(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"omnipay/stripe": "^4.0"})
            self.assertTrue(detect_stripe(root))

    def test_returns_true_via_env_stripe_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text("STRIPE_SECRET=sk_test_abc\n", encoding="utf-8")
            self.assertTrue(detect_stripe(root))

    def test_returns_true_via_env_stripe_webhook_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "STRIPE_WEBHOOK_SECRET=whsec_xyz\n", encoding="utf-8",
            )
            self.assertTrue(detect_stripe(root))

    def test_returns_true_via_source_api_stripe_com(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"guzzlehttp/guzzle": "^7.0"})
            _write_php_source(
                root, "src/Payment/StripeClient.php",
                "<?php\n$url = 'https://api.stripe.com/v1/charges';\n",
            )
            self.assertTrue(detect_stripe(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_stripe(root))

    def test_source_scan_skips_vendor(self):
        """`api.stripe.com` in vendor/ MUST NOT trigger detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            vendor_dir = root / "vendor" / "stripe-mock"
            vendor_dir.mkdir(parents=True)
            (vendor_dir / "Stripe.php").write_text(
                "<?php\n$u = 'https://api.stripe.com';\n", encoding="utf-8",
            )
            src_dir = root / "src"
            src_dir.mkdir()
            link = src_dir / "Stripe.php"
            try:
                link.symlink_to(vendor_dir / "Stripe.php")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            self.assertFalse(detect_stripe(root))


# ---------------------------------------------------------------------------
# detect_aws_secrets_manager — env + source (with SDK gate) probes.
# ---------------------------------------------------------------------------


class DetectAwsSecretsManagerTests(unittest.TestCase):
    def test_returns_true_via_env_aws_secrets_manager_region(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"aws/aws-sdk-php": "^3.0"})
            (root / ".env").write_text(
                "AWS_SECRETS_MANAGER_REGION=us-east-1\n", encoding="utf-8",
            )
            self.assertTrue(detect_aws_secrets_manager(root))

    def test_returns_true_via_env_aws_secrets_manager_arn(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "AWS_SECRETS_MANAGER_ARN=arn:aws:secretsmanager:us-east-1:1:secret:foo-abc\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_aws_secrets_manager(root))

    def test_returns_true_via_source_strong_marker(self):
        """`SecretsManagerClient` class name fires regardless of SDK presence."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # No aws/aws-sdk-php in composer — strong marker fires on its own.
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            _write_php_source(
                root, "src/Secrets/Client.php",
                "<?php\nuse Aws\\SecretsManager\\SecretsManagerClient;\n",
            )
            self.assertTrue(detect_aws_secrets_manager(root))

    def test_returns_true_via_source_weak_marker_with_sdk(self):
        """`secretsmanager.` URL substring requires `aws/aws-sdk-php` in composer."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"aws/aws-sdk-php": "^3.0"})
            _write_php_source(
                root, "src/Foo.php",
                "<?php\n$u = 'https://secretsmanager.us-east-1.amazonaws.com';\n",
            )
            self.assertTrue(detect_aws_secrets_manager(root))

    def test_returns_false_for_weak_marker_without_sdk(self):
        """Weak marker without `aws/aws-sdk-php` in composer MUST NOT fire."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            _write_php_source(
                root, "src/Foo.php",
                "<?php\n$u = 'https://secretsmanager.us-east-1.amazonaws.com';\n",
            )
            self.assertFalse(detect_aws_secrets_manager(root))

    def test_returns_false_for_umbrella_sdk_alone(self):
        """`aws/aws-sdk-php` alone is INTENTIONALLY not a signal."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"aws/aws-sdk-php": "^3.0"})
            _write_php_source(root, "src/S3Service.php",
                              "<?php\nuse Aws\\S3\\S3Client;\n")
            self.assertFalse(detect_aws_secrets_manager(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_aws_secrets_manager(root))


# ---------------------------------------------------------------------------
# detect_vault — composer + env + source probes.
# ---------------------------------------------------------------------------


class DetectVaultTests(unittest.TestCase):
    def test_returns_true_for_csharpru_vault_php(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"csharpru/vault-php": "^4.0"})
            self.assertTrue(detect_vault(root))

    def test_returns_true_for_mittwald_vault_php(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"mittwald/vault-php": "^2.0"})
            self.assertTrue(detect_vault(root))

    def test_returns_true_for_jippi_vault_php_sdk(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"jippi/vault-php-sdk": "^1.0"})
            self.assertTrue(detect_vault(root))

    def test_returns_true_for_violuke_vault_php_sdk(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"violuke/vault-php-sdk": "^1.0"})
            self.assertTrue(detect_vault(root))

    def test_returns_true_via_env_vault_addr(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text(
                "VAULT_ADDR=https://vault.internal:8200\n", encoding="utf-8",
            )
            self.assertTrue(detect_vault(root))

    def test_returns_true_via_env_vault_token(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.local").write_text(
                "VAULT_TOKEN=hvs.abc\n", encoding="utf-8",
            )
            self.assertTrue(detect_vault(root))

    def test_returns_true_via_env_vault_namespace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "VAULT_NAMESPACE=team-platform\n", encoding="utf-8",
            )
            self.assertTrue(detect_vault(root))

    def test_returns_true_via_source_v1_secret_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"guzzlehttp/guzzle": "^7.0"})
            _write_php_source(
                root, "src/Vault/Client.php",
                "<?php\n$path = '/v1/secret/data/myapp/prod';\n",
            )
            self.assertTrue(detect_vault(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_vault(root))


# ---------------------------------------------------------------------------
# detect_saml — composer + env + metadata-file probes.
# ---------------------------------------------------------------------------


class DetectSamlTests(unittest.TestCase):
    def test_returns_true_for_onelogin_php_saml(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"onelogin/php-saml": "^4.0"})
            self.assertTrue(detect_saml(root))

    def test_returns_true_for_simplesamlphp_saml2(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"simplesamlphp/saml2": "^4.0"})
            self.assertTrue(detect_saml(root))

    def test_returns_true_for_simplesamlphp_simplesamlphp(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"simplesamlphp/simplesamlphp": "^2.0"})
            self.assertTrue(detect_saml(root))

    def test_returns_true_for_hslavich_oneloginsaml_bundle(self):
        """Legacy Symfony bundle — still seen in older projects."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"hslavich/oneloginsaml-bundle": "^2.0"})
            self.assertTrue(detect_saml(root))

    def test_returns_true_for_nbgrp_onelogin_saml_bundle(self):
        """Active fork of hslavich/oneloginsaml-bundle (canonical since 2022)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"nbgrp/onelogin-saml-bundle": "^3.0"})
            self.assertTrue(detect_saml(root))

    def test_returns_true_for_aacotroneo_laravel_saml2(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"aacotroneo/laravel-saml2": "^3.0"})
            self.assertTrue(detect_saml(root))

    def test_returns_true_for_24slides_laravel_saml2(self):
        """Active fork of aacotroneo/laravel-saml2."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"24slides/laravel-saml2": "^3.0"})
            self.assertTrue(detect_saml(root))

    def test_returns_true_via_env_saml_idp_metadata_url(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text(
                "SAML_IDP_METADATA_URL=https://idp.example.com/metadata.xml\n",
                encoding="utf-8",
            )
            self.assertTrue(detect_saml(root))

    def test_returns_true_via_metadata_xml_in_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "metadata.xml").write_text(
                "<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata'/>",
                encoding="utf-8",
            )
            self.assertTrue(detect_saml(root))

    def test_returns_true_via_idp_metadata_in_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "config").mkdir()
            (root / "config" / "idp_metadata.xml").write_text(
                "<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata'/>",
                encoding="utf-8",
            )
            self.assertTrue(detect_saml(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_saml(root))

    def test_returns_false_for_arbitrary_xml(self):
        """`metadata.xml` MUST live in repo root or `config/` — not elsewhere."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "src").mkdir()
            (root / "src" / "metadata.xml").write_text("<x/>", encoding="utf-8")
            self.assertFalse(detect_saml(root))

    def test_returns_false_for_metadata_xml_without_saml_namespace(self):
        """`metadata.xml` in root/config without the SAML OASIS namespace
        marker MUST NOT fire — disambiguates from Apache/Maven/NuGet/Composer
        descriptors sharing the filename."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            # Maven-style metadata.xml — no SAML namespace.
            (root / "metadata.xml").write_text(
                "<metadata><groupId>com.example</groupId></metadata>",
                encoding="utf-8",
            )
            self.assertFalse(detect_saml(root))

    def test_returns_true_for_metadata_xml_with_saml_assertion_namespace(self):
        """The `urn:oasis:names:tc:SAML:2.0:assertion` family member also matches
        the broader `urn:oasis:names:tc:SAML` substring."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            (root / "metadata.xml").write_text(
                "<EntityDescriptor xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'/>",
                encoding="utf-8",
            )
            self.assertTrue(detect_saml(root))


# ---------------------------------------------------------------------------
# detect_webauthn_passkeys — composer + env + source probes.
# ---------------------------------------------------------------------------


class DetectWebauthnPasskeysTests(unittest.TestCase):
    def test_returns_true_for_web_auth_webauthn_lib(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"web-auth/webauthn-lib": "^5.0"})
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_true_for_web_auth_webauthn_symfony_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"web-auth/webauthn-symfony-bundle": "^5.0"})
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_true_for_web_auth_webauthn_framework(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"web-auth/webauthn-framework": "^5.0"})
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_true_for_lbuchs_webauthn(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"lbuchs/webauthn": "^2.0"})
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_true_via_env_webauthn_rp_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text(
                "WEBAUTHN_RP_ID=example.com\n", encoding="utf-8",
            )
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_true_via_env_webauthn_rp_name(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env.example").write_text(
                "WEBAUTHN_RP_NAME='Example Inc'\n", encoding="utf-8",
            )
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_true_via_source_credential_options(self):
        """`Webauthn\\` (lowercase 'a') is the real PSR-4 namespace of
        `web-auth/webauthn-lib`."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            _write_php_source(
                root, "src/Auth/Passkey.php",
                "<?php\nuse Webauthn\\PublicKeyCredentialOptions;\n",
            )
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_true_via_source_lbuchs_entry_point(self):
        """`lbuchs\\WebAuthn\\WebAuthn` is the entry-point class of `lbuchs/webauthn`."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            _write_php_source(
                root, "src/Auth/Passkey.php",
                "<?php\nuse lbuchs\\WebAuthn\\WebAuthn;\n",
            )
            self.assertTrue(detect_webauthn_passkeys(root))

    def test_returns_false_when_no_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_webauthn_passkeys(root))


# ---------------------------------------------------------------------------
# Independence: detectors don't accidentally trigger each other.
# ---------------------------------------------------------------------------


class AdditionalDetectorsIndependent(unittest.TestCase):
    def test_stripe_does_not_trigger_others(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"stripe/stripe-php": "^13.0"})
            self.assertTrue(detect_stripe(root))
            self.assertFalse(detect_aws_secrets_manager(root))
            self.assertFalse(detect_vault(root))
            self.assertFalse(detect_saml(root))
            self.assertFalse(detect_webauthn_passkeys(root))

    def test_vault_does_not_trigger_others(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"csharpru/vault-php": "^4.0"})
            self.assertTrue(detect_vault(root))
            self.assertFalse(detect_stripe(root))
            self.assertFalse(detect_aws_secrets_manager(root))
            self.assertFalse(detect_saml(root))
            self.assertFalse(detect_webauthn_passkeys(root))

    def test_saml_does_not_trigger_others(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"onelogin/php-saml": "^4.0"})
            self.assertTrue(detect_saml(root))
            self.assertFalse(detect_stripe(root))
            self.assertFalse(detect_aws_secrets_manager(root))
            self.assertFalse(detect_vault(root))
            self.assertFalse(detect_webauthn_passkeys(root))

    def test_webauthn_does_not_trigger_others(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"web-auth/webauthn-lib": "^5.0"})
            self.assertTrue(detect_webauthn_passkeys(root))
            self.assertFalse(detect_stripe(root))
            self.assertFalse(detect_aws_secrets_manager(root))
            self.assertFalse(detect_vault(root))
            self.assertFalse(detect_saml(root))


# ---------------------------------------------------------------------------
# Stage 7 integrations do NOT trigger jwt-generic / oauth-oidc implication —
# they are orthogonal to the JWT/OAuth axis.
# ---------------------------------------------------------------------------


class AdditionalIntegrationsNoJwtImplication(unittest.TestCase):
    def test_stripe_does_not_imply_jwt_generic(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["stripe"])))
        self.assertEqual(out, ["stripe"])

    def test_vault_does_not_imply_jwt_generic(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["vault"])))
        self.assertEqual(out, ["vault"])

    def test_saml_does_not_imply_jwt_generic(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["saml"])))
        self.assertEqual(out, ["saml"])

    def test_webauthn_does_not_imply_jwt_generic(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["webauthn-passkeys"])))
        self.assertEqual(out, ["webauthn-passkeys"])

    def test_aws_secrets_manager_does_not_imply_jwt_generic(self):
        from recon.recipes._shared import expand_provider_implications
        out = sorted(set(expand_provider_implications(["aws-secrets-manager"])))
        self.assertEqual(out, ["aws-secrets-manager"])


# ---------------------------------------------------------------------------
# End-to-end: inject composer dep into symfony_minimal, run recon, assert
# stack.integrations populated + validate_context passes. Mirror of Stage 5
# `FrontmatterProviderIntegrationsEndToEnd`.
# ---------------------------------------------------------------------------


class FrontmatterAdditionalIntegrationsEndToEnd(unittest.TestCase):
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

    def test_stripe_php_injected_yields_stripe(self):
        text = self._run_with_injected_package("stripe/stripe-php", "^13.0")
        integrations = self._extract_integrations(text)
        self.assertIn("stripe", integrations)

    def test_vault_php_injected_yields_vault(self):
        text = self._run_with_injected_package("csharpru/vault-php", "^4.0")
        integrations = self._extract_integrations(text)
        self.assertIn("vault", integrations)

    def test_onelogin_php_saml_injected_yields_saml(self):
        text = self._run_with_injected_package("onelogin/php-saml", "^4.0")
        integrations = self._extract_integrations(text)
        self.assertIn("saml", integrations)

    def test_webauthn_lib_injected_yields_webauthn_passkeys(self):
        text = self._run_with_injected_package("web-auth/webauthn-lib", "^5.0")
        integrations = self._extract_integrations(text)
        self.assertIn("webauthn-passkeys", integrations)


# AWS Secrets Manager has no specialized composer package — its end-to-end
# path is tested via env var injection (composer alone is intentionally NOT
# a signal).


class FrontmatterAwsSecretsManagerEndToEnd(unittest.TestCase):
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

    def test_aws_secrets_manager_via_env_yields_integration(self):
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
            # Add an explicit Secrets Manager env var (no specialized
            # composer package exists for this integration).
            env_path = proj / ".env"
            existing = env_path.read_text(encoding="utf-8") if env_path.is_file() else ""
            env_path.write_text(
                existing + "\nAWS_SECRETS_MANAGER_REGION=us-east-1\n",
                encoding="utf-8",
            )

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
            self.assertTrue(res.ok(), msg=f"validate_context failed: {res.errors}")
            integrations = self._extract_integrations(text)
            self.assertIn("aws-secrets-manager", integrations)


# ---------------------------------------------------------------------------
# Resolver: ctx.integrations -> integrations/{integration}/{theme}.md loads.
# Combined into one class — one assertion per integration.
# ---------------------------------------------------------------------------


class ResolverLoadsAdditionalChecklists(unittest.TestCase):
    """For each Stage 7 integration, the resolver must load its theme file."""

    def _resolved(self, integration: str, theme: str) -> list[str]:
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        ctx = ResolutionContext(
            language="php",
            stack="symfony",
            addons=(),
            integrations=(integration,),
        )
        files = resolve_checklists((theme,), ctx, plugin_root)
        return [str(p) for p in files]

    def test_stripe_fintech_loaded(self):
        files = self._resolved("stripe", "fintech")
        self.assertTrue(
            any(p.endswith("checklists/integrations/stripe/fintech.md") for p in files),
            msg=f"stripe/fintech.md missing: {files}",
        )

    def test_aws_secrets_manager_crypto_loaded(self):
        files = self._resolved("aws-secrets-manager", "crypto")
        self.assertTrue(
            any(p.endswith(
                "checklists/integrations/aws-secrets-manager/crypto.md"
            ) for p in files),
            msg=f"aws-secrets-manager/crypto.md missing: {files}",
        )

    def test_vault_crypto_loaded(self):
        files = self._resolved("vault", "crypto")
        self.assertTrue(
            any(p.endswith("checklists/integrations/vault/crypto.md") for p in files),
            msg=f"vault/crypto.md missing: {files}",
        )

    def test_saml_auth_loaded(self):
        files = self._resolved("saml", "auth")
        self.assertTrue(
            any(p.endswith("checklists/integrations/saml/auth.md") for p in files),
            msg=f"saml/auth.md missing: {files}",
        )

    def test_webauthn_passkeys_auth_loaded(self):
        files = self._resolved("webauthn-passkeys", "auth")
        self.assertTrue(
            any(p.endswith(
                "checklists/integrations/webauthn-passkeys/auth.md"
            ) for p in files),
            msg=f"webauthn-passkeys/auth.md missing: {files}",
        )


# ---------------------------------------------------------------------------
# Combo: Stage 7 integration co-exists with Stage 5 provider — both layers
# load when both are detected.
# ---------------------------------------------------------------------------


class AdditionalAndProviderCoexist(unittest.TestCase):
    def test_stripe_and_auth0_resolve_in_chain(self):
        from plan_waves import resolve_checklists, ResolutionContext
        plugin_root = Path(__file__).resolve().parents[2]
        # Stripe and Auth0 cover different themes — verify each loads from
        # its respective integration directory.
        ctx = ResolutionContext(
            language="php",
            stack="symfony",
            addons=(),
            integrations=("auth0", "jwt-generic", "stripe"),
        )
        fintech_files = [str(p) for p in resolve_checklists(("fintech",), ctx, plugin_root)]
        auth_files = [str(p) for p in resolve_checklists(("auth",), ctx, plugin_root)]
        self.assertTrue(
            any(p.endswith("integrations/stripe/fintech.md") for p in fintech_files),
            msg=f"stripe/fintech.md missing: {fintech_files}",
        )
        self.assertTrue(
            any(p.endswith("integrations/auth0/auth.md") for p in auth_files),
            msg=f"auth0/auth.md missing: {auth_files}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
