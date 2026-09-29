"""Symfony config sections: normalized views, view parity against real
`debug:config` trees, and the per-section evidence policy.

Parity scope — every tree under `fixtures/symfony_debug_config/` was captured
with `php bin/console debug:config <alias> --format=json` on a fresh
`symfony/skeleton` (Symfony 8.1) + security-bundle, twig-bundle, messenger,
lock, rate-limiter, doctrine-bundle, with the fixture's config files dropped
into `config/packages/` (absolute skeleton paths rewritten to `/app`).

In scope (yaml file vs captured tree):
  - symfony_minimal     security.yaml, messenger.yaml, framework (no file) — minimal.*.json
  - symfony_dvwa        security.yaml, messenger.yaml, framework (no file) — dvwa.*.json
  - symfony_admin       security.yaml                                      — admin.security.json
  - symfony_routes_authz security.yaml                                     — routes_authz.security.json
  - symfony_sonata_admin security.yaml                                     — sonata_admin.security.json
  - symfony_flex        security.yaml (provider, switch_user: true, login_throttling,
                        remember_me with a %param% secret, logout: true, context,
                        explicit stateless: false), framework.yaml, messenger.yaml,
                        twig.yaml                                           — flex.*.json
  - inline `framework: trusted_proxies: [] / trusted_hosts: []`       — empty_trusted.framework.json
Tree only (no yaml side; drives the console variant of the evidence policy):
  - symfony_php_config  security.php + easy_security.php                    — php_config.security.json
Out of scope:
  - symfony_minimal / symfony_dvwa twig.yaml — TwigBundle 8 rejects the `autoescape` option.
  - symfony_admin easy_admin.yaml — EasyAdmin not installed; not an alias any view reads.
  - inline security.yaml snippets in test_recipe_symfony.py — parser edge cases
    (anchors/aliases, `<<` merge keys, partial rules, 2-space indent) that are unit
    input for the frozen parsers, not complete configs Symfony would accept.
  - symfony_hostile_console / symfony_sensitive_columns — carry no in-scope config.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent.parent
PLUGIN_ROOT = BIN_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"
VALIDATE = BIN_DIR / "validate_context.py"
FAKE_CONSOLE = THIS_DIR / "fake_console.py"
FIXTURES = THIS_DIR.parent / "fixtures"
TREES = FIXTURES / "symfony_debug_config"
FIX_FLEX = FIXTURES / "symfony_flex"
FIX_PHP = FIXTURES / "symfony_php_config"
FIX_MIN = FIXTURES / "symfony_minimal"

sys.path.insert(0, str(BIN_DIR))

from unittest import mock  # noqa: E402

from recon import sandbox  # noqa: E402
from recon.recipes import symfony as sf  # noqa: E402
from validate_context import FRONTMATTER_RE, parse_yaml_subset  # noqa: E402

SECRET_LITERALS = ("s3cr3t", "p4ssw0rd", "SYNTHETICflexKEY0123456789", "Pr0dDbPassw0rd")


def _tree(case: str, alias: str) -> dict:
    return json.loads((TREES / f"{case}.{alias}.json").read_text(encoding="utf-8"))[alias]


def _yaml(fixture: str, name: str) -> str:
    path = FIXTURES / fixture / "config" / "packages" / name
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _run_recon(project: Path, review_root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RECON), str(project), "--recipe", "symfony",
         "--review-root", str(review_root), *extra],
        capture_output=True, text=True, timeout=120,
    )


def _console_flag(case: str) -> str:
    return f"--console-cmd={sys.executable} {FAKE_CONSOLE} {case}"


def _validate(review_root: Path, project: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATE), "--review-root", str(review_root),
         "--sanity", "--project-root", str(project)],
        capture_output=True, text=True, timeout=60,
    )


def _section(text: str, section_id: str) -> dict:
    anchor = f"<!-- section_id: {section_id} -->"
    rest = text[text.index(anchor):]
    m = re.search(r"```yaml\s*\n(.*?)\n```", rest, re.DOTALL)
    return parse_yaml_subset(m.group(1))


def _bag(text: str, key: str) -> dict:
    return _section(text, "recon_bags")["stack"]["symfony"][key]


def _non_git_warnings(fm: dict) -> list[str]:
    # A non-git copy of the engine (tarball, bundle core) adds this one.
    return [w for w in fm["warnings"] if not w.startswith("git_rev_unavailable")]


def _frontmatter(text: str) -> dict:
    return parse_yaml_subset(FRONTMATTER_RE.match(text).group(1))


# ---------------------------------------------------------------------------
# View parity
# ---------------------------------------------------------------------------


SECURITY_PARITY = (
    ("minimal", "symfony_minimal"),
    ("dvwa", "symfony_dvwa"),
    ("admin", "symfony_admin"),
    ("routes_authz", "symfony_routes_authz"),
    ("sonata_admin", "symfony_sonata_admin"),
    ("flex", "symfony_flex"),
)
FRAMEWORK_PARITY = (
    ("minimal", "symfony_minimal"),
    ("dvwa", "symfony_dvwa"),
    ("flex", "symfony_flex"),
)


class ViewParity(unittest.TestCase):
    def test_security_view(self):
        for case, fixture in SECURITY_PARITY:
            with self.subTest(case=case):
                from_tree = sf.elide_defaults(sf.security_view_from_tree(_tree(case, "security")))
                from_yaml = sf.elide_defaults(sf.security_view_from_yaml_text(_yaml(fixture, "security.yaml")))
                self.assertEqual(from_tree, from_yaml)

    def test_security_kind_part_of_parity(self):
        expected = {"minimal": "stateless", "dvwa": "stateless", "admin": "session",
                    "routes_authz": "stateless", "sonata_admin": "session", "flex": "session"}
        for case, fixture in SECURITY_PARITY:
            with self.subTest(case=case):
                self.assertEqual(sf.security_view_from_tree(_tree(case, "security")).kind, expected[case])
                self.assertEqual(
                    sf.security_view_from_yaml_text(_yaml(fixture, "security.yaml")).kind, expected[case],
                )

    def test_messenger_view(self):
        for case, fixture in FRAMEWORK_PARITY:
            with self.subTest(case=case):
                from_tree = sf.elide_defaults(sf.messenger_view_from_tree(_tree(case, "framework")))
                from_yaml = sf.elide_defaults(sf.messenger_view_from_yaml_text(_yaml(fixture, "messenger.yaml")))
                self.assertEqual(from_tree.transports, from_yaml.transports)

    def test_trusted_config_view(self):
        for case, fixture in FRAMEWORK_PARITY:
            with self.subTest(case=case):
                from_tree = sf.elide_defaults(sf.trusted_config_view_from_tree(_tree(case, "framework")))
                from_yaml = sf.elide_defaults(sf.trusted_config_view_from_yaml_text(_yaml(fixture, "framework.yaml")))
                self.assertEqual(from_tree, from_yaml)

    def test_empty_trusted_lists_mean_unset(self):
        text = (
            "framework:\n"
            "    secret: '%env(APP_SECRET)%'\n"
            "    trusted_proxies: []\n"
            "    trusted_hosts: []\n"
            "    session: true\n"
        )
        from_tree = sf.elide_defaults(sf.trusted_config_view_from_tree(_tree("empty_trusted", "framework")))
        from_yaml = sf.elide_defaults(sf.trusted_config_view_from_yaml_text(text))
        self.assertEqual(from_tree, sf.TrustedConfigView({}))
        self.assertEqual(from_yaml, from_tree)

    def test_twig_view(self):
        from_tree = sf.twig_view_from_tree(_tree("flex", "twig"))
        # Flex twig.yaml sets no autoescape → the default applies on both sides.
        self.assertIsNone(sf.twig_view_from_yaml_text(_yaml("symfony_flex", "twig.yaml")))
        self.assertEqual(from_tree, sf.TwigView("name"))


class SecretSnippetMasking(unittest.TestCase):
    def test_credentials_masked_prefix_and_length_kept(self):
        cases = {
            "'password' => 'Pr0dDbPassw0rd'": "'password' => '<redacted:14>'",
            "stripe: sk_live_ABCDEFGHIJKLMNOPQRSTUVWX": "stripe: sk_live_<redacted:24>",
            "aws: AKIAABCDEFGHIJKLMNOP": "aws: AKIA<redacted:16>",
            "slack: xoxb-1234567890abc": "slack: xoxb-<redacted:13>",
            "password: hunter2xyz": "password: <redacted:10>",
            "'secret_key' => 'aB3dEf6hIj9kLm2nOp5q'": "'secret_key' => '<redacted:20>'",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(sf._mask_secret_snippet(line), expected)

    def test_every_credential_on_the_line_masked(self):
        self.assertEqual(
            sf._mask_secret_snippet("->setPassword('super-secret-pw')->setToken('sk_live_abcdefghij1234')"),
            "->setPassword('<redacted:15>')->setToken('sk_live_<redacted:14>')",
        )

    def test_dsn_userinfo_masked_whole(self):
        cases = {
            "dsn: 'redis://:pw123456@cache'": "dsn: '<redacted:23>'",
            "notifier: 'slack://xoxb-123456789012-abcdef@default'": "notifier: 'slack://xoxb-<redacted:19>@default'",
            "'mailgun+api://key-abc123:example.com@default'": "'mailgun+api://<redacted:22>@default'",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(sf._mask_secret_snippet(line), expected)

    def test_lookalike_keys_keep_their_values(self):
        line = ("'password_parameter' => '_password', 'csrf_token_id' => 'authenticate', "
                "'token_provider' => 'app.token_provider', 'password_path' => '/reset/confirm'")
        self.assertEqual(sf._mask_secret_snippet(line), line)
        for line in (
            "access_token: { token_handler: App\\Security\\Handler }",
            "'access_token' => 'app.access_token_handler'",
            "csrf_token: authenticate_form",
        ):
            with self.subTest(line=line):
                self.assertEqual(sf._mask_secret_snippet(line), line)

    def test_placeholder_must_be_the_whole_value(self):
        self.assertEqual(sf._mask_secret_snippet("'password' => 'todo-set-real-one-2024'"),
                         "'password' => '<redacted:22>'")
        self.assertEqual(sf._mask_secret_snippet("'secret' => 'example9f8e7d6c'"),
                         "'secret' => '<redacted:15>'")
        for line in ("'password' => 'todo'", "'password' => '-- changeme --'", "'token' => '...'"):
            with self.subTest(line=line):
                self.assertEqual(sf._mask_secret_snippet(line), line)

    def test_classifier_signals_stay_visible(self):
        for line in (
            "'password' => '%env(DATABASE_PASSWORD)%',",
            "'secret' => '%kernel.secret%',",
            "'api_key' => 'changeme-in-prod'",
            "'password' => 'xxxxxxxxxx'",
            "'token' => '<your-token-here>'",
            "'secret' => $this->params->get('app.secret'),",
            "'token' => SomeClass::TOKEN",
            "->setApiKey(getenv('KEY'))",
            "'dsn' => '%env(DATABASE_URL)%'",
            "$container->extension('doctrine', ['dbal' => ['url' => '%env(DATABASE_URL)%']]);",
        ):
            with self.subTest(line=line):
                self.assertEqual(sf._mask_secret_snippet(line), line)


class CanonicalFirewallRendering(unittest.TestCase):
    def test_rich_firewall_nested_nodes_render_as_presence_plus_listed_leaves(self):
        view = sf.elide_defaults(sf.security_view_from_tree(_tree("flex", "security")))
        main = next(fw for fw in view.firewalls if fw["name"] == "main")
        self.assertEqual(main, {
            "name": "main",
            "lazy": "true",
            "provider": "app_user_provider",
            "context": "shared_ctx",
            "form_login": "true",
            "login_throttling": "true",
            "login_throttling__max_attempts": "3",
            "remember_me": "true",
            "remember_me__lifetime": "604800",
            "logout": "true",
            "switch_user": "true",
        })

    def test_explicit_default_kept_on_yaml_side_until_elided(self):
        raw = sf.security_view_from_yaml_text(_yaml("symfony_flex", "security.yaml"))
        main = next(fw for fw in raw.firewalls if fw["name"] == "main")
        self.assertEqual(main["stateless"], "false")
        self.assertNotIn("stateless", next(
            fw for fw in sf.elide_defaults(raw).firewalls if fw["name"] == "main"
        ))

    def test_factory_children_no_longer_flattened_into_the_firewall(self):
        raw = sf.security_view_from_yaml_text(_yaml("symfony_flex", "security.yaml"))
        main = next(fw for fw in raw.firewalls if fw["name"] == "main")
        for leaked in ("login_path", "check_path", "csrf_token_id", "password_parameter",
                       "secret", "lifetime", "max_attempts"):
            self.assertNotIn(leaked, main)

    def test_nested_secret_never_in_either_view(self):
        for view in (sf.security_view_from_tree(_tree("flex", "security")),
                     sf.security_view_from_yaml_text(_yaml("symfony_flex", "security.yaml"))):
            dumped = json.dumps([view.firewalls, view.access_control])
            self.assertNotIn("s3cr3t", dumped)
            self.assertNotIn("remember_secret", dumped)

    def test_redaction_is_an_explicit_key_list(self):
        self.assertEqual(sf._redact("csrf_token_id", "authenticate"), "authenticate")
        self.assertEqual(sf._redact("password_parameter", "_pass"), "_pass")
        self.assertEqual(sf._redact("access_token", "handler_id"), "handler_id")
        self.assertEqual(sf._redact("remember_me.secret", "s3cr3t"), "<redacted>")
        self.assertEqual(sf._redact("secret", "%env(APP_SECRET)%"), "%env(APP_SECRET)%")
        self.assertEqual(sf._redact("password", "false"), "false")

    def test_list_values_render_one_way_on_both_sides(self):
        text = (
            "security:\n"
            "    access_control:\n"
            "        - { path: ^/a, roles: [ROLE_A] }\n"
            "        - { path: ^/b, roles: ['ROLE_B', \"ROLE_C\"] }\n"
            "        - { path: '[a-z]+', roles: ROLE_D }\n"
        )
        rules = sf.security_view_from_yaml_text(text).access_control
        self.assertEqual(rules[0]["roles"], "ROLE_A")
        self.assertEqual(rules[1]["roles"], "[ROLE_B, ROLE_C]")
        # Only list-valued keys are normalized; a path regex stays verbatim.
        self.assertEqual(rules[2]["path"], "[a-z]+")

    def test_kind_ignores_comments_mentioning_jwt(self):
        text = (
            "security:\n"
            "    # TODO: migrate to lexik jwt / oauth later\n"
            "    firewalls:\n"
            "        main:\n"
            "            lazy: true\n"
        )
        self.assertEqual(sf.security_view_from_yaml_text(text).kind, "session")

    def test_kind_from_factory_keys(self):
        jwt = "security:\n    firewalls:\n        api:\n            stateless: true\n            jwt: ~\n"
        self.assertEqual(sf.security_view_from_yaml_text(jwt).kind, "jwt")
        oauth = (
            "security:\n    firewalls:\n        main:\n"
            "            custom_authenticators:\n                - App\\Security\\GoogleOAuthAuthenticator\n"
        )
        self.assertEqual(sf.security_view_from_yaml_text(oauth).kind, "oauth")


# ---------------------------------------------------------------------------
# Evidence policy, end to end through recon_inventory.py
# ---------------------------------------------------------------------------


class _ReconRun(unittest.TestCase):
    fixture: Path
    extra: tuple[str, ...] = ()

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.review_root = Path(cls._tmp.name) / "review"
        proc = _run_recon(cls.fixture, cls.review_root, *cls.extra)
        assert proc.returncode == 0, proc.stderr
        cls.text = (cls.review_root / "CONTEXT.md").read_text(encoding="utf-8")
        cls.fm = _frontmatter(cls.text)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def assert_validates(self):
        proc = _validate(self.review_root, self.fixture)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)

    def assert_no_secret_literals(self):
        for literal in SECRET_LITERALS:
            self.assertNotIn(literal, self.text)


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class FlexFixtureNoConsole(_ReconRun):
    fixture = FIX_FLEX
    extra = ("--no-console",)

    def test_every_config_section_ok(self):
        self.assertEqual(_section(self.text, "auth_layer")["status"], "ok")
        for key in ("firewalls", "trusted_config", "messenger_transports",
                    "twig_overrides", "routes_authz_matrix"):
            with self.subTest(bag=key):
                self.assertEqual(_bag(self.text, key)["status"], "ok")

    def test_multi_file_framework_picks_only_the_subtree_file(self):
        self.assertEqual(_bag(self.text, "trusted_config")["source_files"],
                         ["config/packages/framework.yaml"])
        self.assertEqual(_bag(self.text, "messenger_transports")["source_files"],
                         ["config/packages/messenger.yaml"])

    def test_when_test_and_packages_test_ignored(self):
        self.assertEqual(_bag(self.text, "trusted_config")["data"]["trusted_proxies"], "10.0.0.0/8")
        self.assertEqual(_section(self.text, "secrets")["data"]["password_hasher"], "auto")

    def test_no_secret_literals(self):
        self.assert_no_secret_literals()

    def test_yaml_vendor_key_candidate_keeps_prefix_and_length(self):
        cands = _section(self.text, "secrets")["data"]["candidates"]
        hit = next(c for c in cands if c["regex_match"] == "stripe_live_key")
        self.assertEqual(hit["file"], "config/services.yaml")
        self.assertIn("sk_live_<redacted:26>", hit["snippet"])

    def test_validates_with_sanity(self):
        self.assert_validates()


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class FlexFixtureFakeConsole(_ReconRun):
    fixture = FIX_FLEX
    extra = (_console_flag("flex"),)

    def test_every_config_section_ok_from_the_tree(self):
        auth = _section(self.text, "auth_layer")
        self.assertEqual(auth["status"], "ok")
        self.assertIn("via debug:config security", auth["data"]["summary"])
        for key in ("firewalls", "trusted_config", "messenger_transports",
                    "twig_overrides", "routes_authz_matrix"):
            with self.subTest(bag=key):
                self.assertEqual(_bag(self.text, key)["status"], "ok")

    def test_sources_used_labels(self):
        self.assertEqual(_non_git_warnings(self.fm), [])
        self.assertEqual(self.fm["sources_used"].count("console:smoke"), 1)
        self.assertIn("console:debug_config", self.fm["sources_used"])
        self.assertEqual(self.fm["recon_confidence"]["ceiling"], "high")
        self.assertFalse(self.fm["environment"]["console_gap"])

    def test_no_secret_literals(self):
        # flex.security.json carries the resolved remember_me secret and
        # flex.framework.json the DSN password — neither may be emitted.
        self.assertIn("s3cr3t", (TREES / "flex.security.json").read_text())
        self.assertIn("p4ssw0rd", (TREES / "flex.framework.json").read_text())
        self.assert_no_secret_literals()

    def test_validates_with_sanity(self):
        self.assert_validates()


PHP_EVIDENCE = ["config/packages/easy_security.php", "config/packages/security.php"]


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class PhpConfigNoConsole(_ReconRun):
    fixture = FIX_PHP
    extra = ("--no-console",)

    def test_auth_layer_pending_with_evidence(self):
        auth = _section(self.text, "auth_layer")
        self.assertEqual(auth["status"], "pending_enrichment")
        self.assertEqual(auth["data"]["evidence_files"], PHP_EVIDENCE)
        self.assertEqual(auth["source_files"], PHP_EVIDENCE)
        self.assertIn("Never copy secret values", auth["enrichment_hint"])
        self.assertIn("<!-- enrichment_marker: auth_layer__pending__", self.text)

    def test_firewalls_bag_partial_never_pending(self):
        bag = _bag(self.text, "firewalls")
        self.assertEqual(bag["status"], "partial")
        self.assertIn("reason", bag)
        self.assertEqual(bag["data"]["evidence_files"], PHP_EVIDENCE)
        self.assertEqual(bag["source_files"], PHP_EVIDENCE)

    def test_matrix_items_flag_access_control_unknown(self):
        bag = _bag(self.text, "routes_authz_matrix")
        self.assertEqual(bag["status"], "partial")
        self.assertEqual(bag["reason"], "access_control_not_interpreted")
        self.assertTrue(bag["items"])
        for item in bag["items"]:
            self.assertIs(item["access_control_interpreted"], False)
            self.assertIsNone(item["firewall"])
            self.assertIsNone(item["matched_access_control"])
            self.assertFalse(any(ev["source"] == "access_control" for ev in item["authz_evidence"]))
        for rel in PHP_EVIDENCE:
            self.assertIn(rel, bag["source_files"])

    def test_secrets_routes_the_security_evidence(self):
        self.assertEqual(_section(self.text, "secrets")["source_files"], [".env", *PHP_EVIDENCE])

    def test_php_config_credential_is_a_masked_candidate(self):
        cands = _section(self.text, "secrets")["data"]["candidates"]
        hit = next(c for c in cands if c["file"] == "config/packages/doctrine.php")
        self.assertEqual(hit["regex_match"], "key_value_pair")
        self.assertIn("'password' => '<redacted:24>'", hit["snippet"])
        self.assert_no_secret_literals()

    def test_validates_with_sanity(self):
        self.assert_validates()

    def test_validates_after_sanctioned_partial_enrichment(self):
        # The recon agent's fallback for evidence it cannot interpret either:
        # flip the marker, write `partial` with every schema key, keep source_files.
        m = re.search(
            r"<!-- enrichment_marker: (auth_layer)__pending__(\w+) -->\n\n```yaml\n.*?```",
            self.text, re.DOTALL,
        )
        enriched = (
            f"<!-- enrichment_marker: {m.group(1)}__done__{m.group(2)} -->\n\n```yaml\n"
            "status: partial\nreason: php config read but provider unclear\n"
            "data:\n  kind: session\n  provider: unknown\n  mfa: false\n"
            "  summary: Session auth via security.php\n"
            "source_files:\n"
            + "".join(f"  - {rel}\n" for rel in PHP_EVIDENCE)
            + "```"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "CONTEXT.md").write_text(self.text.replace(m.group(0), enriched), encoding="utf-8")
            proc = _validate(root, self.fixture)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class PhpConfigFakeConsole(_ReconRun):
    fixture = FIX_PHP
    extra = (_console_flag("php_config"),)

    def test_auth_layer_ok_with_both_files(self):
        auth = _section(self.text, "auth_layer")
        self.assertEqual(auth["status"], "ok")
        self.assertEqual(auth["source_files"], PHP_EVIDENCE)
        self.assertEqual(auth["data"]["provider"], "app_user_provider")

    def test_firewalls_merged_across_files(self):
        bag = _bag(self.text, "firewalls")
        self.assertEqual(bag["status"], "ok")
        self.assertEqual(bag["source_files"], PHP_EVIDENCE)
        self.assertEqual([r["path"] for r in bag["data"]["access_control"]], ["^/admin", "^/account"])

    def test_no_warnings_from_the_console_run(self):
        self.assertEqual(_non_git_warnings(self.fm), [])

    def test_matrix_interpreted(self):
        bag = _bag(self.text, "routes_authz_matrix")
        self.assertEqual(bag["status"], "ok")
        items = {it["route_name"]: it for it in bag["items"]}
        self.assertEqual(items["admin_users"]["matched_access_control"], "^/admin")
        self.assertEqual(items["admin_users"]["firewall"], None)
        self.assertNotIn("access_control_interpreted", items["admin_users"])

    def test_validates_with_sanity(self):
        self.assert_validates()


# ---------------------------------------------------------------------------
# Policy units (no php)
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self, trees: dict, env: str = "dev"):
        self.trees = trees
        self.env = env
        self.asked: list[str] = []

    def extension_config(self, alias, *, quiet=False):
        self.asked.append((alias, quiet))
        return self.trees.get(alias)

    def kernel_environment(self):
        return self.env


class ProdOverridePolicy(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        pkg = self.root / "config" / "packages"
        pkg.mkdir(parents=True)
        (pkg / "security.yaml").write_text(
            "security:\n"
            "    firewalls:\n"
            "        main:\n"
            "            lazy: true\n"
            "\n"
            "when@prod:\n"
            "    security:\n"
            "        firewalls:\n"
            "            main:\n"
            "                stateless: true\n"
        )
        self.tree = {"firewalls": {"main": {"lazy": True}}, "access_control": []}

    def test_tree_from_non_prod_env_is_partial_with_warning(self):
        warnings: list[str] = []
        cfg = sf._resolve_security(self.root, _FakeSession({"security": self.tree}), warnings)
        auth, fw = sf.collect_auth_layer_and_firewalls(self.root, warnings, security=cfg)
        self.assertEqual(auth.status, "partial")
        self.assertEqual(fw.status, "partial")
        self.assertTrue(any(w.startswith("config_env_dev_only: security") for w in warnings))

    def test_tree_from_prod_env_is_ok(self):
        warnings: list[str] = []
        cfg = sf._resolve_security(self.root, _FakeSession({"security": self.tree}, env="prod"), warnings)
        auth, _ = sf.collect_auth_layer_and_firewalls(self.root, warnings, security=cfg)
        self.assertEqual(auth.status, "ok")
        self.assertEqual(warnings, [])

    def test_no_console_prod_override_is_not_interpreted(self):
        warnings: list[str] = []
        auth, fw = sf.collect_auth_layer_and_firewalls(self.root, warnings)
        self.assertEqual(auth.status, "pending_enrichment")
        self.assertEqual(fw.status, "partial")
        self.assertEqual(fw.data["evidence_files"], ["config/packages/security.yaml"])
        # The frozen parser still contributes what it read from the yaml evidence.
        self.assertEqual(fw.data["firewalls"], [{"name": "main", "lazy": "true"}])


_MAIN_FW_TREE = {"firewalls": {"main": {"lazy": True}}, "access_control": [
    {"path": "^/admin", "roles": ["ROLE_ADMIN"]},
]}


def _project(files: dict[str, str]) -> Path:
    td = tempfile.mkdtemp()
    root = Path(td)
    (root / "config" / "packages").mkdir(parents=True)
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)
    return root


class ConsoleNotGatedByEvidence(unittest.TestCase):
    def _root(self, files):
        root = _project(files)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    def test_alias_asked_without_any_config_file(self):
        # e.g. security configured in MicroKernel::configureContainer() in src/.
        root = self._root({})
        session = _FakeSession({"security": _MAIN_FW_TREE})
        warnings: list[str] = []
        cfg = sf._resolve_security(root, session, warnings)
        auth, fw = sf.collect_auth_layer_and_firewalls(root, warnings, security=cfg)
        self.assertIn(("security", True), session.asked)
        self.assertEqual(auth.status, "ok")
        self.assertEqual(auth.source_files, [])
        self.assertEqual(fw.status, "ok")
        self.assertEqual(warnings, ["config_source_files_not_located: security"])

    def test_alias_without_evidence_asked_quietly(self):
        root = self._root({})
        session = _FakeSession({})
        warnings: list[str] = []
        payload = sf.collect_twig_overrides(root, session=session, warnings=warnings)
        self.assertEqual(session.asked, [("twig", True)])
        self.assertEqual(payload.status, "ok")
        self.assertEqual(warnings, [])

    def test_quiet_extension_config_does_not_warn(self):
        from recon.recipes import _symfony_introspection as intro
        warnings: list[str] = []
        with mock.patch.object(sandbox, "try_console_smoke", return_value=(True, None)), \
             mock.patch.object(sandbox, "run_console_command",
                               return_value=(None, "console_command_failed: debug:config twig: rc=1")):
            session = intro.ConsoleSession(object(), [], warnings)
            self.assertIsNone(session.extension_config("twig", quiet=True))
        self.assertEqual(warnings, [])

    def test_docs_style_xml_and_load_from_extension_are_static_evidence(self):
        from recon.recipes import _symfony_introspection as intro
        root = self._root({
            "config/packages/security.xml": (
                '<?xml version="1.0" encoding="UTF-8" ?>\n'
                '<srv:container xmlns="http://symfony.com/schema/dic/security"\n'
                '    xmlns:srv="http://symfony.com/schema/dic/services">\n'
                '    <config>\n        <firewall name="main" lazy="true"/>\n    </config>\n'
                '</srv:container>\n'
            ),
            "config/packages/extra_security.php": (
                "<?php\n$container->loadFromExtension('security', [\n"
                "    'access_control' => [['path' => '^/admin', 'roles' => ['ROLE_ADMIN']]],\n]);\n"
            ),
        })
        ev = intro.find_config_evidence(root, "security", intro.SECURITY_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/extra_security.php", "config/packages/security.xml"])


class FoundButNotUnderstood(unittest.TestCase):
    """The console answered, but its tree lacks what static evidence declares."""

    def _root(self, files):
        root = _project({**files})
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    PROD_ONLY = (
        "when@prod:\n"
        "    security:\n"
        "        firewalls:\n"
        "            main:\n"
        "                lazy: true\n"
        "        access_control:\n"
        "            - { path: ^/admin, roles: ROLE_ADMIN }\n"
    )

    def test_prod_only_security_under_dev_console(self):
        root = self._root({"config/packages/security.yaml": self.PROD_ONLY})
        warnings: list[str] = []
        cfg = sf._resolve_security(root, _FakeSession({"security": {"firewalls": {}, "access_control": []}}), warnings)
        auth, fw = sf.collect_auth_layer_and_firewalls(root, warnings, security=cfg)
        self.assertEqual(auth.status, "pending_enrichment")
        self.assertEqual(auth.source_files, ["config/packages/security.yaml"])
        self.assertEqual(fw.status, "partial")
        self.assertEqual(fw.data["evidence_files"], ["config/packages/security.yaml"])
        self.assertIn("missing from the console's tree", fw.reason)
        self.assertFalse(cfg.interpreted)
        self.assertTrue(any(w.startswith("config_env_dev_only: security") for w in warnings))

    def test_prod_override_with_dev_tree_keeps_rules(self):
        root = self._root({"config/packages/security.yaml": (
            "security:\n    firewalls:\n        main:\n            lazy: true\n\n" + self.PROD_ONLY
        )})
        warnings: list[str] = []
        cfg = sf._resolve_security(root, _FakeSession({"security": _MAIN_FW_TREE}), warnings)
        _, fw = sf.collect_auth_layer_and_firewalls(root, warnings, security=cfg)
        self.assertEqual(fw.status, "partial")
        self.assertTrue(fw.reason.startswith("config_env_dev_only: security"))
        self.assertEqual([r["path"] for r in fw.data["access_control"]], ["^/admin"])
        self.assertTrue(cfg.interpreted)

    def test_empty_tree_under_env_gap_is_partial_not_none(self):
        root = self._root({"config/packages/framework.yaml": (
            "framework:\n    secret: x\nwhen@prod:\n    framework:\n        trusted_proxies: '10.0.0.0/8'\n"
        )})
        warnings: list[str] = []
        payload = sf.collect_trusted_config(
            root, session=_FakeSession({"framework": {"trusted_proxies": []}}), warnings=warnings,
        )
        self.assertEqual(payload.status, "partial")
        self.assertEqual(payload.data["evidence_files"], ["config/packages/framework.yaml"])
        self.assertTrue(payload.reason.startswith("config_env_dev_only: framework"))

    def _matrix_root(self, security_yaml: str) -> Path:
        root = self._root({"config/packages/security.yaml": security_yaml})
        shutil.copytree(FIXTURES / "symfony_routes_authz" / "src", root / "src")
        return root

    @unittest.skipUnless(shutil.which("php"), "php not on PATH")
    def test_matrix_keeps_tree_matches_under_env_gap(self):
        root = self._matrix_root(
            "security:\n    firewalls:\n        main:\n            lazy: true\n\n" + self.PROD_ONLY
        )
        tree = {"firewalls": {"admin": {"pattern": "^/admin"}}, "access_control": [
            {"path": "^/admin", "roles": ["ROLE_ADMIN"]},
        ]}
        cfg = sf._resolve_security(root, _FakeSession({"security": tree}), [])
        payload = sf._build_routes_authz_matrix(root, PLUGIN_ROOT, security=cfg)
        self.assertEqual(payload.status, "partial")
        self.assertTrue(payload.reason.startswith("config_env_dev_only: security"))
        items = {it["route_name"]: it for it in payload.items}
        self.assertEqual(items["admin_users_create"]["firewall"], "admin")
        self.assertEqual(items["admin_users_create"]["matched_access_control"], "^/admin")
        for item in payload.items:
            self.assertNotIn("access_control_interpreted", item)

    @unittest.skipUnless(shutil.which("php"), "php not on PATH")
    def test_matrix_flagged_when_tree_lacks_the_rules(self):
        root = self._matrix_root(self.PROD_ONLY)
        cfg = sf._resolve_security(root, _FakeSession({"security": {"firewalls": {}, "access_control": []}}), [])
        payload = sf._build_routes_authz_matrix(root, PLUGIN_ROOT, security=cfg)
        self.assertEqual(payload.status, "partial")
        self.assertTrue(payload.reason.startswith("access_control_not_interpreted (config_env_dev_only"))
        for item in payload.items:
            self.assertIs(item["access_control_interpreted"], False)
            self.assertIsNone(item["firewall"])
            self.assertIsNone(item["matched_access_control"])


class DevOverridePolicy(unittest.TestCase):
    def _root(self, files):
        root = _project({"config/packages/security.yaml": "security:\n    firewalls:\n        main:\n            lazy: true\n",
                         **files})
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    def _check(self, root, env, expect_status):
        warnings: list[str] = []
        cfg = sf._resolve_security(root, _FakeSession({"security": _MAIN_FW_TREE}, env=env), warnings)
        auth, _ = sf.collect_auth_layer_and_firewalls(root, warnings, security=cfg)
        self.assertEqual(auth.status, expect_status)
        return warnings

    def test_dev_dir_override_under_dev_console(self):
        root = self._root({"config/packages/dev/security.yaml":
                           "security:\n    firewalls:\n        main:\n            security: false\n"})
        warnings = self._check(root, "dev", "partial")
        self.assertTrue(any(w.startswith("config_env_dev_overrides: security") for w in warnings))
        # dev files never become production source_files.
        self.assertEqual(
            sf.find_config_evidence(root, "security", sf.SECURITY_SUBTREE_KEYS).files,
            ["config/packages/security.yaml"],
        )

    def test_when_dev_block_under_dev_console(self):
        root = self._root({"config/packages/security_dev.yaml":
                           "when@dev:\n    security:\n        firewalls:\n            main:\n                security: false\n"})
        self._check(root, "dev", "partial")

    def test_dev_override_irrelevant_under_prod_console(self):
        root = self._root({"config/packages/dev/security.yaml":
                           "security:\n    firewalls:\n        main:\n            security: false\n"})
        self.assertEqual(self._check(root, "prod", "ok"), [])


class ProdDirectoryPolicy(unittest.TestCase):
    def test_prod_dir_only_file_without_console_is_not_interpreted(self):
        # One interpretable yaml file: only the prod-directory rule makes it pending.
        root = _project({
            "config/packages/prod/security.yaml": "security:\n    firewalls:\n        main:\n            stateless: true\n",
        })
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        auth, fw = sf.collect_auth_layer_and_firewalls(root, [])
        self.assertEqual(auth.status, "pending_enrichment")
        self.assertEqual(fw.status, "partial")
        self.assertEqual(fw.data["evidence_files"], ["config/packages/prod/security.yaml"])


class RegisteredBundleEmptyTree(unittest.TestCase):
    def test_security_bundle_with_nothing_configured_is_unknown(self):
        root = _project({})
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        warnings: list[str] = []
        cfg = sf._resolve_security(root, _FakeSession({"security": {"firewalls": {}, "access_control": []}}), warnings)
        auth, fw = sf.collect_auth_layer_and_firewalls(root, warnings, security=cfg)
        self.assertEqual(auth.status, "unknown")
        self.assertEqual(fw.status, "unknown")
        self.assertEqual(warnings, [])


class TrustedTreeMismatch(unittest.TestCase):
    def _payload(self, files, tree):
        root = _project({**files})
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return sf.collect_trusted_config(root, session=_FakeSession({"framework": tree}), warnings=[])

    def test_non_default_value_missing_from_tree_is_not_understood(self):
        payload = self._payload(
            {"config/packages/framework.yaml": "framework:\n    trusted_proxies: '10.0.0.0/8'\n"},
            {"trusted_proxies": ["%env(default::SYMFONY_TRUSTED_PROXIES)%"]},
        )
        self.assertEqual(payload.status, "partial")
        self.assertIn("missing from the console's tree", payload.reason)

    def test_default_or_empty_values_are_none(self):
        default_tree = {
            "trusted_proxies": ["%env(default::SYMFONY_TRUSTED_PROXIES)%"],
            "trusted_hosts": ["%env(default::SYMFONY_TRUSTED_HOSTS)%"],
            "trusted_headers": ["%env(default::SYMFONY_TRUSTED_HEADERS)%"],
        }
        for name, body in (
            ("framework.yaml", "framework:\n    trusted_headers: ['x-forwarded-for', 'x-forwarded-port', 'x-forwarded-proto']\n"),
            ("framework.yaml", "framework:\n    trusted_proxies: '%env(default::SYMFONY_TRUSTED_PROXIES)%'\n"),
            ("framework.php", "<?php\n$container->extension('framework', ['trusted_proxies' => '']);\n"),
        ):
            with self.subTest(body=body):
                payload = self._payload({f"config/packages/{name}": body}, default_tree)
                self.assertEqual(payload.status, "none")
                self.assertEqual(payload.reason, "no trusted_proxies/hosts/headers configured")

    def test_php_messenger_without_transports_is_none(self):
        root = _project({"config/packages/messenger.php": (
            "<?php\n$container->extension('framework', ['messenger' => ['default_bus' => 'command.bus']]);\n"
        )})
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        payload = sf.collect_messenger_transports(
            root, session=_FakeSession({"framework": {"messenger": {"transports": []}}}), warnings=[],
        )
        self.assertEqual(payload.status, "none")


class EmptyBundlesPhpStillAsksConsole(unittest.TestCase):
    """Synthetic layout: `config/bundles.php` is a literal empty map while the
    real registry lives elsewhere (e.g. `config/api/bundles.php`)."""

    FILES = {
        "config/bundles.php": "<?php\n\nreturn [];\n",
        "config/api/bundles.php": (
            "<?php\nreturn [\n"
            "    Symfony\\Bundle\\FrameworkBundle\\FrameworkBundle::class => ['all' => true],\n"
            "    Symfony\\Bundle\\SecurityBundle\\SecurityBundle::class => ['all' => true],\n"
            "    Symfony\\Bundle\\TwigBundle\\TwigBundle::class => ['all' => true],\n"
            "];\n"
        ),
        "config/packages/security.yaml": "security:\n    firewalls:\n        main:\n            lazy: true\n",
    }

    def _root(self, files):
        root = _project(files)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    def test_every_alias_is_asked_and_the_tree_wins(self):
        root = self._root(self.FILES)
        session = _FakeSession({
            "security": _MAIN_FW_TREE,
            "framework": {"trusted_proxies": ["10.0.0.0/8"]},
            "twig": {"autoescape": "html"},
        })
        warnings: list[str] = []
        cfg = sf._resolve_security(root, session, warnings)
        sf.collect_trusted_config(root, session=session, warnings=warnings)
        sf.collect_twig_overrides(root, session=session, warnings=warnings)
        self.assertEqual({alias for alias, _ in session.asked}, {"security", "framework", "twig"})
        self.assertEqual(cfg.resolution.mode, "tree")
        _, fw = sf.collect_auth_layer_and_firewalls(root, warnings, security=cfg)
        self.assertEqual([f["name"] for f in fw.data["firewalls"]], ["main"])

    def test_non_literal_map_asks_the_same_aliases(self):
        files = dict(self.FILES)
        files["config/bundles.php"] = "<?php\nreturn array_merge(require __DIR__.'/api/bundles.php', []);\n"
        root = self._root(files)
        session = _FakeSession({"security": _MAIN_FW_TREE})
        sf._resolve_security(root, session, [])
        self.assertIn("security", {alias for alias, _ in session.asked})

    def test_failed_console_with_evidence_is_not_quiet(self):
        root = self._root(self.FILES)
        session = _FakeSession({})
        sf._resolve_security(root, session, [])
        self.assertEqual(session.asked, [("security", False)])


class DevOnlySource(unittest.TestCase):
    def test_dev_dir_files_are_source_under_dev_console(self):
        root = _project({
            "config/packages/dev/security.yaml": "security:\n    firewalls:\n        main:\n            lazy: true\n",
        })
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        warnings: list[str] = []
        cfg = sf._resolve_security(root, _FakeSession({"security": _MAIN_FW_TREE}, env="dev"), warnings)
        auth, fw = sf.collect_auth_layer_and_firewalls(root, warnings, security=cfg)
        self.assertEqual(auth.source_files, ["config/packages/dev/security.yaml"])
        self.assertEqual(fw.source_files, ["config/packages/dev/security.yaml"])
        self.assertEqual(auth.status, "partial")
        self.assertFalse(any(w.startswith("config_source_files_not_located") for w in warnings))
        self.assertTrue(any(w.startswith("config_env_dev_overrides: security") for w in warnings))


class NoneVersusUnknown(unittest.TestCase):
    def _root(self, files: dict[str, str]) -> Path:
        td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, td, ignore_errors=True)
        root = Path(td)
        for rel, body in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(body)
        return root

    def test_framework_configured_elsewhere_without_trusted_keys_is_none(self):
        root = self._root({"config/packages/cache.yaml": "framework:\n    cache: ~\n"})
        payload = sf.collect_trusted_config(root)
        self.assertEqual(payload.status, "none")

    def test_empty_trusted_values_are_none_not_a_list(self):
        root = self._root({"config/packages/framework.yaml": (
            "framework:\n    trusted_proxies: []\n    trusted_hosts: ''\n    trusted_headers: ~\n"
        )})
        payload = sf.collect_trusted_config(root)
        self.assertEqual(payload.status, "none")
        self.assertEqual(payload.reason, "no trusted_proxies/hosts/headers configured")

    def test_framework_php_with_trusted_keys_is_partial(self):
        root = self._root({"config/packages/framework.php": (
            "<?php\nuse Symfony\\Config\\FrameworkConfig;\n"
            "return static function (FrameworkConfig $framework): void {\n"
            "    $framework->trustedProxies('10.0.0.0/8');\n};\n"
        )})
        payload = sf.collect_trusted_config(root)
        self.assertEqual(payload.status, "partial")
        self.assertEqual(payload.data, {"evidence_files": ["config/packages/framework.php"]})
        self.assertEqual(payload.source_files, ["config/packages/framework.php"])


_GENERATED_REFERENCE = (
    "<?php\n\n"
    "// This file is auto-generated and is for apps only. Bundles SHOULD NOT rely on its content.\n\n"
    "namespace Symfony\\Component\\DependencyInjection\\Loader\\Configurator;\n\n"
    "/**\n"
    " * @psalm-type TwigConfig = array{autoescape_service?: string, strict_variables?: bool}\n"
    " * @psalm-type SecurityConfig = array{firewalls?: array, access_control?: list, providers?: array}\n"
    " * @psalm-type FrameworkConfig = array{trusted_proxies?: string, messenger?: array}\n"
    " */\n"
    "final class App\n{\n"
    "    public static function config(array $config): array\n    {\n"
    "        return ['twig' => [], 'security' => ['firewalls' => []], "
    "'framework' => ['trusted_proxies' => 'sk_live_SYNTHETICKEY12345', 'messenger' => []]];\n"
    "    }\n}\n"
)


class GeneratedReferenceIgnored(unittest.TestCase):
    """Symfony >= 7.4 writes config/reference.php (IDE array shapes for every
    extension). It is never loaded as config and must not count as evidence."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "config" / "packages").mkdir(parents=True)
        (self.root / "config" / "reference.php").write_text(_GENERATED_REFERENCE)
        (self.root / "config" / "packages" / "twig.yaml").write_text("twig:\n    file_name_pattern: '*.twig'\n")

    def test_not_evidence_for_any_alias(self):
        from recon.recipes import _symfony_introspection as intro
        for alias, keys in (("twig", intro.TWIG_SUBTREE_KEYS),
                            ("security", intro.SECURITY_SUBTREE_KEYS),
                            ("framework", intro.TRUSTED_SUBTREE_KEYS),
                            ("framework", intro.MESSENGER_SUBTREE_KEYS)):
            with self.subTest(alias=alias, keys=keys):
                self.assertNotIn("config/reference.php",
                                 intro.find_config_evidence(self.root, alias, keys).files)

    def test_twig_stays_ok_and_security_absent(self):
        twig = sf.collect_twig_overrides(self.root)
        self.assertEqual(twig.status, "ok")
        self.assertEqual(twig.source_files, ["config/packages/twig.yaml"])
        auth, _ = sf.collect_auth_layer_and_firewalls(self.root, [])
        self.assertEqual(auth.status, "unknown")

    def test_not_scanned_for_secret_candidates(self):
        self.assertNotIn("config/reference.php", [rel for rel, _ in sf._list_config_files(self.root)])

    def test_hand_written_reference_php_still_counts(self):
        (self.root / "config" / "reference.php").write_text(
            "<?php\nuse Symfony\\Config\\TwigConfig;\n"
            "return static function (TwigConfig $twig): void {\n    $twig->strictVariables(true);\n};\n"
        )
        from recon.recipes import _symfony_introspection as intro
        self.assertIn("config/reference.php",
                      intro.find_config_evidence(self.root, "twig", intro.TWIG_SUBTREE_KEYS).files)


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class SessionWiring(unittest.TestCase):
    def test_disabled_runner_adds_no_recipe_warning(self):
        result = sf.build_inventory(
            FIX_MIN, plugin_root=PLUGIN_ROOT,
            console_runner=sandbox.disabled_runner("console_disabled_by_flag", FIX_MIN),
        )
        self.assertNotIn("console_disabled_by_flag", result.warnings)
        self.assertFalse(any(s.startswith("console:") for s in result.sources_used))

    def test_smoke_runs_once_for_enrichment_and_config(self):
        runner = sandbox.custom_runner(f"{sys.executable} {FAKE_CONSOLE} flex", FIX_FLEX)
        result = sf.build_inventory(FIX_FLEX, plugin_root=PLUGIN_ROOT, console_runner=runner)
        # Raw recipe list, before recon_inventory's dedupe.
        self.assertEqual(result.sources_used.count("console:smoke"), 1)
        self.assertEqual(result.sources_used.count("console:debug_config"), 1)


if __name__ == "__main__":
    unittest.main()
