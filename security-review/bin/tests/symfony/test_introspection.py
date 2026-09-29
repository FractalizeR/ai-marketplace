"""`recon.recipes._symfony_introspection`: `ConsoleSession` (lazy single smoke +
cached `extension_config()` / `kernel_environment()` / `run()`),
`find_config_evidence()`, and the secret-redaction helpers.

No live console or php: `sandbox.try_console_smoke` / `sandbox.run_console_command`
are mocked at the module-attribute level, matching the seam already used by
`tests/test_recipe_symfony.py`.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent.parent
sys.path.insert(0, str(BIN_DIR))

from recon import sandbox  # noqa: E402
from recon.recipes import _symfony_introspection as intro  # noqa: E402


# ---------------------------------------------------------------------------
# ConsoleSession
# ---------------------------------------------------------------------------


class ConsoleSessionSmokeGating(unittest.TestCase):
    def test_smoke_failure_blocks_every_later_call_without_spawning(self):
        calls: list[list[str]] = []

        def fake_run(runner, args):
            calls.append(args)
            return "should never be reached", None

        sources: list[str] = []
        warnings: list[str] = []
        with mock.patch.object(sandbox, "try_console_smoke", return_value=(False, "console_smoke_failed: rc=1")), \
             mock.patch.object(sandbox, "run_console_command", side_effect=fake_run):
            session = intro.ConsoleSession(object(), sources, warnings)
            self.assertIsNone(session.extension_config("security"))
            self.assertIsNone(session.kernel_environment())
            self.assertIsNone(session.run(["debug:router", "--format=json"]))

        self.assertEqual(calls, [])  # zero spawns past the failed smoke
        self.assertNotIn("console:smoke", sources)
        self.assertFalse(any(s.startswith("console:") for s in sources))
        self.assertEqual(warnings, ["console_smoke_failed: rc=1"])

    def test_smoke_runs_exactly_once_across_multiple_calls(self):
        smoke = mock.Mock(return_value=(True, None))

        def fake_run(runner, args):
            return json.dumps({"security": {"firewalls": {}}}), None

        sources: list[str] = []
        warnings: list[str] = []
        with mock.patch.object(sandbox, "try_console_smoke", smoke), \
             mock.patch.object(sandbox, "run_console_command", side_effect=fake_run):
            session = intro.ConsoleSession(object(), sources, warnings)
            session.extension_config("security")
            session.extension_config("framework")
            session.kernel_environment()

        self.assertEqual(smoke.call_count, 1)
        self.assertEqual(sources.count("console:smoke"), 1)


class ConsoleSessionExtensionConfig(unittest.TestCase):
    def _session(self, run_side_effect, sources=None, warnings=None):
        sources = sources if sources is not None else []
        warnings = warnings if warnings is not None else []
        patchers = [
            mock.patch.object(sandbox, "try_console_smoke", return_value=(True, None)),
            mock.patch.object(sandbox, "run_console_command", side_effect=run_side_effect),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        return intro.ConsoleSession(object(), sources, warnings), sources, warnings

    def test_json_ok_unwraps_alias_key_and_labels_sources(self):
        def fake_run(runner, args):
            self.assertEqual(args, ["debug:config", "security", "--format=json"])
            return json.dumps({"security": {"firewalls": {"main": {}}}}), None

        session, sources, warnings = self._session(fake_run)
        tree = session.extension_config("security")
        self.assertEqual(tree, {"firewalls": {"main": {}}})
        self.assertEqual(sources, ["console:smoke", "console:debug_config"])
        self.assertEqual(warnings, [])

    def test_debug_config_label_appended_once_for_multiple_aliases(self):
        def fake_run(runner, args):
            alias = args[1]
            return json.dumps({alias: {"k": "v"}}), None

        session, sources, _ = self._session(fake_run)
        session.extension_config("security")
        session.extension_config("framework")
        self.assertEqual(sources.count("console:debug_config"), 1)

    def test_result_cached_per_alias_no_second_spawn(self):
        calls: list[str] = []

        def fake_run(runner, args):
            calls.append(args[1])
            return json.dumps({"security": {"a": 1}}), None

        session, _, _ = self._session(fake_run)
        session.extension_config("security")
        session.extension_config("security")
        self.assertEqual(calls, ["security"])

    # run_console_command keeps only the LAST stderr line, and Symfony prints the
    # command synopsis after an input error, so the warning never ends in the
    # "option does not exist" sentence on a real console.
    _SYNOPSIS_WARN = (
        "console_command_failed: debug:config security --format=json: "
        "debug:config [--resolve-env] [--] [<name> [<path>]]"
    )

    def test_pre_6_3_detected_by_version_when_only_synopsis_line_survives(self):
        def fake_run(runner, args):
            if args == ["--version"]:
                return "Symfony 5.4.12 (env: dev, debug: true)\n", None
            return None, self._SYNOPSIS_WARN

        session, _, warnings = self._session(fake_run)
        self.assertIsNone(session.extension_config("security"))
        self.assertIsNone(session.extension_config("framework"))
        self.assertTrue(session.json_unsupported)
        unsupported = [w for w in warnings if w.startswith("console_unsupported:")]
        self.assertEqual(len(unsupported), 1)
        self.assertIn("5.4.12", unsupported[0])
        self.assertIn(">= 6.3", unsupported[0])

    def test_v_prefixed_real_console_string_pre_6_3_is_detected(self):
        def fake_run(runner, args):
            if args == ["--version"]:
                return "Symfony v5.4.12 (env: dev, debug: true)\n", None
            return None, self._SYNOPSIS_WARN

        session, _, warnings = self._session(fake_run)
        self.assertIsNone(session.extension_config("security"))
        self.assertTrue(session.json_unsupported)
        unsupported = [w for w in warnings if w.startswith("console_unsupported:")]
        self.assertEqual(len(unsupported), 1)
        self.assertIn("console reports 5.4.12)", unsupported[0])

    def test_v_prefixed_real_console_string_modern_is_not_unsupported(self):
        def fake_run(runner, args):
            if args == ["--version"]:
                return "Symfony v8.1.5 (env: dev, debug: true)\n", None
            return None, self._SYNOPSIS_WARN

        session, _, warnings = self._session(fake_run)
        self.assertIsNone(session.extension_config("security"))
        self.assertFalse(session.json_unsupported)
        self.assertFalse([w for w in warnings if w.startswith("console_unsupported:")])

    def test_version_is_read_once_per_session(self):
        calls: list[list[str]] = []

        def fake_run(runner, args):
            calls.append(args)
            if args == ["--version"]:
                return "Symfony 6.2.0 (env: dev, debug: true)\n", None
            return None, self._SYNOPSIS_WARN

        session, _, _ = self._session(fake_run)
        session.extension_config("security")
        session.extension_config("framework")
        self.assertEqual(calls.count(["--version"]), 1)

    def test_modern_console_failing_for_another_reason_is_not_unsupported(self):
        def fake_run(runner, args):
            if args == ["--version"]:
                return "Symfony 7.1.3 (env: dev, debug: true)\n", None
            return None, self._SYNOPSIS_WARN

        session, _, warnings = self._session(fake_run)
        self.assertIsNone(session.extension_config("security"))
        self.assertFalse(session.json_unsupported)
        self.assertFalse([w for w in warnings if w.startswith("console_unsupported:")])

    def test_option_sentence_alone_still_marks_unsupported(self):
        def fake_run(runner, args):
            if args == ["--version"]:
                return "Symfony 5.4.12 (env: dev, debug: true)\n", None
            return None, 'console_command_failed: debug:config security --format=json: The "--format" option does not exist.'

        session, _, warnings = self._session(fake_run)
        session.extension_config("security")
        self.assertTrue(session.json_unsupported)

    def test_other_failures_do_not_mark_json_unsupported(self):
        def fake_run(runner, args):
            return None, "console_command_failed: debug:config security --format=json: boom"

        session, _, warnings = self._session(fake_run)
        session.extension_config("security")
        self.assertFalse(session.json_unsupported)
        self.assertEqual(len(warnings), 1)

    def test_unregistered_alias_returns_none_and_warns(self):
        def fake_run(runner, args):
            return None, "console_command_failed: debug:config nope: Extension alias \"nope\" does not exist"

        session, _, warnings = self._session(fake_run)
        self.assertIsNone(session.extension_config("nope"))
        self.assertEqual(len(warnings), 1)

    def test_unwrapped_json_falls_back_to_raw_dict(self):
        def fake_run(runner, args):
            return json.dumps({"firewalls": {"main": {}}}), None

        session, _, _ = self._session(fake_run)
        self.assertEqual(session.extension_config("security"), {"firewalls": {"main": {}}})

    def test_argv_never_contains_resolve_env(self):
        seen_args: list[list[str]] = []

        def fake_run(runner, args):
            seen_args.append(args)
            return json.dumps({"security": {}}), None

        session, _, _ = self._session(fake_run)
        session.extension_config("security")
        session.kernel_environment()
        session.run(["debug:router", "--format=json"])
        for args in seen_args:
            self.assertNotIn("--resolve-env", args)


class ConsoleSessionRun(unittest.TestCase):
    def test_run_is_a_passthrough_when_console_ok(self):
        def fake_run(runner, args):
            return "raw output", None

        sources: list[str] = []
        warnings: list[str] = []
        with mock.patch.object(sandbox, "try_console_smoke", return_value=(True, None)), \
             mock.patch.object(sandbox, "run_console_command", side_effect=fake_run):
            session = intro.ConsoleSession(object(), sources, warnings)
            self.assertEqual(session.run(["debug:router", "--format=json"]), "raw output")


class ConsoleSessionKernelEnvironment(unittest.TestCase):
    def test_json_string_value(self):
        def fake_run(runner, args):
            return json.dumps("prod"), None

        with mock.patch.object(sandbox, "try_console_smoke", return_value=(True, None)), \
             mock.patch.object(sandbox, "run_console_command", side_effect=fake_run):
            session = intro.ConsoleSession(object(), [], [])
            self.assertEqual(session.kernel_environment(), "prod")

    def test_json_dict_value(self):
        def fake_run(runner, args):
            return json.dumps({"kernel.environment": "dev"}), None

        with mock.patch.object(sandbox, "try_console_smoke", return_value=(True, None)), \
             mock.patch.object(sandbox, "run_console_command", side_effect=fake_run):
            session = intro.ConsoleSession(object(), [], [])
            self.assertEqual(session.kernel_environment(), "dev")

    def test_queried_once_per_session(self):
        calls: list[list[str]] = []

        def fake_run(runner, args):
            calls.append(args)
            return json.dumps({"kernel.environment": "dev"}), None

        with mock.patch.object(sandbox, "try_console_smoke", return_value=(True, None)), \
             mock.patch.object(sandbox, "run_console_command", side_effect=fake_run):
            session = intro.ConsoleSession(object(), [], [])
            self.assertEqual(session.kernel_environment(), "dev")
            self.assertEqual(session.kernel_environment(), "dev")
        self.assertEqual(len(calls), 1)

    def test_failure_cached_and_warned_once(self):
        calls: list[list[str]] = []

        def fake_run(runner, args):
            calls.append(args)
            return None, "console_command_failed: debug:container: rc=1"

        warnings: list[str] = []
        with mock.patch.object(sandbox, "try_console_smoke", return_value=(True, None)), \
             mock.patch.object(sandbox, "run_console_command", side_effect=fake_run):
            session = intro.ConsoleSession(object(), [], warnings)
            self.assertIsNone(session.kernel_environment())
            self.assertIsNone(session.kernel_environment())
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(warnings), 1)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class RedactSecretValue(unittest.TestCase):
    def test_secret_key_full_match_redacted(self):
        self.assertEqual(intro.redact_secret_value("password", "hunter2"), "<redacted>")
        self.assertEqual(intro.redact_secret_value("dsn", "mysql://u:p@host/db"), "<redacted>")

    def test_dot_suffix_redacted(self):
        self.assertEqual(intro.redact_secret_value("database.password", "hunter2"), "<redacted>")

    def test_empty_and_boolean_and_env_placeholder_not_redacted(self):
        self.assertEqual(intro.redact_secret_value("password", ""), "")
        self.assertEqual(intro.redact_secret_value("password", None), None)
        self.assertEqual(intro.redact_secret_value("password", True), True)
        self.assertEqual(intro.redact_secret_value("secret", "%env(APP_SECRET)%"), "%env(APP_SECRET)%")

    def test_lookalike_keys_kept(self):
        # Not a substring regex: these contain "token"/"password" but are not
        # in SECRET_KEYS and don't end in a ".<secret-key>" suffix.
        self.assertEqual(intro.redact_secret_value("csrf_token_id", "abc123"), "abc123")
        self.assertEqual(intro.redact_secret_value("password_parameter", "_password"), "_password")
        self.assertEqual(intro.redact_secret_value("access_token", "tok-xyz"), "tok-xyz")
        self.assertEqual(intro.redact_secret_value("token_provider", "some.service.id"), "some.service.id")


class RedactStderrSecrets(unittest.TestCase):
    def test_colon_form_redacted(self):
        out = intro.redact_stderr_secrets("connection failed: password: hunter2")
        self.assertIn("<redacted>", out)
        self.assertNotIn("hunter2", out)

    def test_eq_form_redacted(self):
        out = intro.redact_stderr_secrets("boot failed: MAILER_PASSWORD=hunter2 not set")
        self.assertIn("<redacted>", out)
        self.assertNotIn("hunter2", out)

    def test_url_userinfo_redacted(self):
        out = intro.redact_stderr_secrets("could not connect to mysql://dbuser:hunter2@127.0.0.1/app")
        self.assertIn("mysql://<redacted>@127.0.0.1/app", out)
        self.assertNotIn("hunter2", out)

    def test_url_userinfo_with_empty_user_redacted(self):
        out = intro.redact_stderr_secrets("cannot reach redis://:s3cretpw@redis:6379")
        self.assertEqual(out, "cannot reach redis://<redacted>@redis:6379")

    def test_token_only_and_key_domain_userinfo_fully_redacted(self):
        for dsn in ("slack://xoxb-123456789012-abcdef@default?channel=ops",
                    "sendgrid://SG.aaaa.bbbb@default",
                    "mailgun+api://key-abc123:example.com@default"):
            with self.subTest(dsn=dsn):
                out = intro.redact_stderr_secrets(f"Invalid DSN {dsn}")
                self.assertRegex(out, r"^Invalid DSN [a-z+]+://<redacted>@default")

    def test_json_key_value_redacted(self):
        out = intro.redact_stderr_secrets('config: {"password":"hunter2","user":"app"}')
        self.assertEqual(out, 'config: {"password":"<redacted>","user":"app"}')

    def test_quoted_multi_word_value_fully_redacted(self):
        out = intro.redact_stderr_secrets("password: 'my secret pw' rejected")
        self.assertEqual(out, "password: '<redacted>' rejected")

    def test_arrow_form_redacted(self):
        out = intro.redact_stderr_secrets("api_key => sk_live_123456789")
        self.assertEqual(out, "api_key => <redacted>")

    def test_already_masked_and_env_placeholder_kept(self):
        for s in ("'password' => '<redacted:7>'", "secret: %env(APP_SECRET)%", 'secret="%env(APP_SECRET)%"'):
            self.assertEqual(intro.redact_stderr_secrets(s), s)

    def test_lookalike_keys_kept_in_freetext_too(self):
        out = intro.redact_stderr_secrets("csrf_token_id: abc123, access_token: tok-xyz")
        self.assertIn("abc123", out)
        self.assertIn("tok-xyz", out)

    def test_none_and_empty_passthrough(self):
        self.assertIsNone(intro.redact_stderr_secrets(None))
        self.assertEqual(intro.redact_stderr_secrets(""), "")


# ---------------------------------------------------------------------------
# find_config_evidence
# ---------------------------------------------------------------------------


class FindConfigEvidenceFlexYaml(unittest.TestCase):
    """Flex-shaped tree: `framework:` top-level in several files (cache/lock),
    `when@test:` blocks everywhere, a `config/packages/test/` subtree — only
    files whose *scanned* (non test/dev) framework: block actually mentions a
    trusted_* key should count.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        packages = self.root / "config" / "packages"
        packages.mkdir(parents=True)

        (packages / "cache.yaml").write_text(
            "framework:\n"
            "    cache:\n"
            "        app: cache.adapter.filesystem\n"
        )
        (packages / "lock.yaml").write_text(
            "framework:\n"
            "    lock: ~\n"
        )
        (packages / "framework.yaml").write_text(
            "framework:\n"
            "    secret: '%env(APP_SECRET)%'\n"
            "    trusted_proxies: '%env(TRUSTED_PROXIES)%'\n"
            "\n"
            "when@test:\n"
            "    framework:\n"
            "        trusted_proxies: '10.0.0.0/8'\n"
        )
        (packages / "security.yaml").write_text(
            "security:\n"
            "    firewalls:\n"
            "        main:\n"
            "            lazy: true\n"
            "\n"
            "when@test:\n"
            "    security:\n"
            "        firewalls:\n"
            "            main:\n"
            "                lazy: false\n"
        )
        test_dir = packages / "test"
        test_dir.mkdir()
        (test_dir / "framework.yaml").write_text(
            "framework:\n"
            "    trusted_proxies: '127.0.0.1'\n"
        )

    def test_trusted_config_evidence_excludes_cache_and_lock(self):
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/framework.yaml"])
        self.assertFalse(ev.prod_override)

    def test_security_evidence_ignores_when_test_and_finds_unconditional(self):
        ev = intro.find_config_evidence(self.root, "security", intro.SECURITY_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/security.yaml"])
        self.assertFalse(ev.prod_override)

    def test_packages_test_subtree_never_counted(self):
        # The framework.yaml under config/packages/test/ is evidence-shaped
        # but must never surface — its only mention is confirmed to come
        # from the shared file, not the test-only one.
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertNotIn("config/packages/test/framework.yaml", ev.files)


class FindConfigEvidenceProdOverride(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        packages = self.root / "config" / "packages"
        packages.mkdir(parents=True)
        (packages / "framework.yaml").write_text(
            "framework:\n"
            "    secret: '%env(APP_SECRET)%'\n"
            "\n"
            "when@prod:\n"
            "    framework:\n"
            "        trusted_proxies: '10.0.0.0/8'\n"
        )

    def test_when_prod_block_sets_prod_override(self):
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/framework.yaml"])
        self.assertTrue(ev.prod_override)



class FindConfigEvidenceEnvDirectories(unittest.TestCase):
    """No `when@` block anywhere: only the directory rule can set the flags."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        packages = self.root / "config" / "packages"
        packages.mkdir(parents=True)
        (packages / "framework.yaml").write_text("framework:\n    trusted_proxies: '127.0.0.1'\n")

    def test_base_file_alone_sets_no_flag(self):
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertFalse(ev.prod_override)
        self.assertFalse(ev.dev_override)

    def test_prod_packages_dir_sets_prod_override(self):
        prod_dir = self.root / "config" / "packages" / "prod"
        prod_dir.mkdir()
        (prod_dir / "framework.yaml").write_text(
            "framework:\n    trusted_proxies: '10.0.0.0/8'\n"
        )
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertIn("config/packages/prod/framework.yaml", ev.files)
        self.assertTrue(ev.prod_override)

    def test_dev_packages_dir_sets_dev_override_only(self):
        dev_dir = self.root / "config" / "packages" / "dev"
        dev_dir.mkdir()
        (dev_dir / "framework.yaml").write_text("framework:\n    trusted_proxies: '0.0.0.0/0'\n")
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/framework.yaml"])
        self.assertTrue(ev.dev_override)
        self.assertFalse(ev.prod_override)

    def test_when_dev_block_sets_dev_override(self):
        (self.root / "config" / "packages" / "framework.yaml").write_text(
            "framework:\n    trusted_proxies: '127.0.0.1'\n"
            "when@dev:\n    framework:\n        trusted_proxies: '0.0.0.0/0'\n"
        )
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertTrue(ev.dev_override)
        self.assertFalse(ev.prod_override)


class FindConfigEvidenceEnvConditionalPhpXml(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "config" / "packages").mkdir(parents=True)

    def _ev(self, name, body):
        (self.root / "config" / "packages" / name).write_text(body)
        return intro.find_config_evidence(self.root, "security", intro.SECURITY_SUBTREE_KEYS)

    def test_php_and_xml_env_branches_set_no_env_flag(self):
        php = self._ev("security.php", (
            "<?php\nreturn static function (ContainerConfigurator $container): void {\n"
            "    if ('prod' === $container->env()) {\n"
            "        $container->extension('security', ['firewalls' => ['main' => ['lazy' => true]]]);\n"
            "    }\n    if ('dev' === $container->env()) {\n"
            "        $container->extension('security', ['firewalls' => ['main' => ['security' => false]]]);\n"
            "    }\n};\n"
        ))
        self.assertEqual(php.files, ["config/packages/security.php"])
        xml = self._ev("security.xml", (
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            '<container xmlns="http://symfony.com/schema/dic/services"\n'
            '    xmlns:security="http://symfony.com/schema/dic/security">\n'
            '    <when env="prod"><security:config><security:firewall name="main"/></security:config></when>\n'
            '</container>\n'
        ))
        self.assertIn("config/packages/security.xml", xml.files)
        for ev in (php, xml):
            self.assertFalse(ev.prod_override)
            self.assertFalse(ev.dev_override)

    def test_service_argument_with_alias_key_is_not_evidence(self):
        (self.root / "config" / "services.php").write_text(
            "<?php\nreturn static function (ContainerConfigurator $container): void {\n"
            "    $container->services()->set('app.x')->arg('$opts', ['security' => ['firewalls' => 'x']]);\n"
            "    if ('dev' === $container->env()) {\n        $container->services()->set('app.y');\n    }\n};\n"
        )
        ev = intro.find_config_evidence(self.root, "security", intro.SECURITY_SUBTREE_KEYS)
        self.assertEqual(ev.files, [])
        self.assertFalse(ev.dev_override)

    def test_dev_dir_files_listed_separately(self):
        dev = self.root / "config" / "packages" / "dev"
        dev.mkdir()
        (dev / "security.yaml").write_text("security:\n    firewalls:\n        main:\n            lazy: true\n")
        ev = intro.find_config_evidence(self.root, "security", intro.SECURITY_SUBTREE_KEYS)
        self.assertEqual(ev.files, [])
        self.assertEqual(ev.dev_files, ["config/packages/dev/security.yaml"])
        self.assertTrue(ev.dev_override)

    def test_unconditional_php_sets_nothing(self):
        ev = self._ev("security.php", (
            "<?php\n$container->extension('security', ['firewalls' => ['main' => ['lazy' => true]]]);\n"
        ))
        self.assertEqual(ev.files, ["config/packages/security.php"])
        self.assertFalse(ev.prod_override)
        self.assertFalse(ev.dev_override)


class FindConfigEvidencePhp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "config" / "packages").mkdir(parents=True)

    def test_security_php_singular_builder_method_counts(self):
        # Colleague's real case: security.php using ONLY ->firewall(), no
        # ->accessControl() at all. Must still be evidence for `firewalls`.
        (self.root / "config" / "packages" / "security.php").write_text(
            "<?php\n"
            "use Symfony\\Config\\SecurityConfig;\n"
            "return static function (SecurityConfig $security): void {\n"
            "    $security->firewall('main')->lazy(true);\n"
            "};\n"
        )
        ev = intro.find_config_evidence(self.root, "security", intro.SECURITY_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/security.php"])

    def test_framework_php_plural_method_counts(self):
        (self.root / "config" / "packages" / "framework.php").write_text(
            "<?php\n"
            "use Symfony\\Config\\FrameworkConfig;\n"
            "return static function (FrameworkConfig $framework): void {\n"
            "    $framework->trustedProxies('10.0.0.0/8', ['x-forwarded-for']);\n"
            "};\n"
        )
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/framework.php"])

    def test_php_file_without_subtree_key_not_evidence(self):
        # lock.php: FrameworkConfig present, but no trusted_* mentioned.
        (self.root / "config" / "packages" / "lock.php").write_text(
            "<?php\n"
            "use Symfony\\Config\\FrameworkConfig;\n"
            "return static function (FrameworkConfig $framework): void {\n"
            "    $framework->lock()->resource('default', 'flock');\n"
            "};\n"
        )
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertEqual(ev.files, [])


class FindConfigEvidenceXml(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "config" / "packages").mkdir(parents=True)

    def test_security_xml_firewall_element_counts(self):
        (self.root / "config" / "packages" / "security.xml").write_text(
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            '<container xmlns="http://symfony.com/schema/dic/services"\n'
            '    xmlns:security="http://symfony.com/schema/dic/security">\n'
            '    <security:config>\n'
            '        <security:firewall name="main" lazy="true"/>\n'
            '    </security:config>\n'
            '</container>\n'
        )
        ev = intro.find_config_evidence(self.root, "security", intro.SECURITY_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/security.xml"])

    def test_framework_xml_trusted_proxies_attribute_counts(self):
        (self.root / "config" / "packages" / "framework.xml").write_text(
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            '<container xmlns="http://symfony.com/schema/dic/services"\n'
            '    xmlns:framework="http://symfony.com/schema/dic/symfony">\n'
            '    <framework:config trusted-proxies="10.0.0.0/8"/>\n'
            '</container>\n'
        )
        ev = intro.find_config_evidence(self.root, "framework", intro.TRUSTED_SUBTREE_KEYS)
        self.assertEqual(ev.files, ["config/packages/framework.xml"])

    def test_xml_without_alias_namespace_not_evidence(self):
        (self.root / "config" / "packages" / "other.xml").write_text(
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            '<container xmlns="http://symfony.com/schema/dic/services">\n'
            '    <services/>\n'
            '</container>\n'
        )
        ev = intro.find_config_evidence(self.root, "security", intro.SECURITY_SUBTREE_KEYS)
        self.assertEqual(ev.files, [])


class FindConfigEvidenceAliasOnly(unittest.TestCase):
    """Empty subtree_keys (subtree_keys=()): declaring the alias is enough."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "config" / "packages").mkdir(parents=True)

    def test_default_flex_twig_yaml_is_evidence(self):
        (self.root / "config" / "packages" / "twig.yaml").write_text(
            "twig:\n"
            "    file_name_pattern: '*.twig'\n"
            "\n"
            "when@test:\n"
            "    twig:\n"
            "        strict_variables: true\n"
        )
        ev = intro.find_config_evidence(self.root, "twig", ())
        self.assertEqual(ev.files, ["config/packages/twig.yaml"])
        self.assertFalse(ev.prod_override)

    def test_when_test_only_declaration_is_not_evidence(self):
        (self.root / "config" / "packages" / "twig_test.yaml").write_text(
            "when@test:\n    twig:\n        strict_variables: true\n"
        )
        ev = intro.find_config_evidence(self.root, "twig", ())
        self.assertEqual(ev.files, [])

    def test_when_prod_declaration_sets_prod_override(self):
        (self.root / "config" / "packages" / "twig.yaml").write_text(
            "when@prod:\n    twig:\n        cache: true\n"
        )
        ev = intro.find_config_evidence(self.root, "twig", ())
        self.assertEqual(ev.files, ["config/packages/twig.yaml"])
        self.assertTrue(ev.prod_override)

    def test_php_and_xml_declarations_are_evidence(self):
        (self.root / "config" / "packages" / "twig.php").write_text(
            "<?php\nuse Symfony\\Config\\TwigConfig;\n"
            "return static function (TwigConfig $twig): void {\n"
            "    $twig->strictVariables(true);\n};\n"
        )
        (self.root / "config" / "packages" / "twig.xml").write_text(
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            '<container xmlns="http://symfony.com/schema/dic/services"\n'
            '    xmlns:twig="http://symfony.com/schema/dic/twig">\n'
            '    <twig:config strict-variables="true"/>\n'
            '</container>\n'
        )
        ev = intro.find_config_evidence(self.root, "twig", ())
        self.assertEqual(ev.files, ["config/packages/twig.php", "config/packages/twig.xml"])


class TwigEvidenceNeedsAutoescape(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "config" / "packages").mkdir(parents=True)

    def test_default_flex_twig_yaml_is_not_evidence(self):
        (self.root / "config" / "packages" / "twig.yaml").write_text(
            "twig:\n    file_name_pattern: '*.twig'\n"
        )
        ev = intro.find_config_evidence(self.root, "twig", intro.TWIG_SUBTREE_KEYS)
        self.assertEqual(ev.files, [])

    def test_file_setting_autoescape_is_evidence_in_any_format(self):
        pkg = self.root / "config" / "packages"
        (pkg / "twig.yaml").write_text("twig:\n    autoescape: false\n")
        (pkg / "twig.php").write_text(
            "<?php\nuse Symfony\\Config\\TwigConfig;\n"
            "return static function (TwigConfig $twig): void {\n    $twig->autoescape('html');\n};\n"
        )
        (pkg / "twig.xml").write_text(
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            '<container xmlns="http://symfony.com/schema/dic/services"\n'
            '    xmlns:twig="http://symfony.com/schema/dic/twig">\n'
            '    <twig:config autoescape="false"/>\n'
            '</container>\n'
        )
        ev = intro.find_config_evidence(self.root, "twig", intro.TWIG_SUBTREE_KEYS)
        self.assertEqual(
            ev.files, ["config/packages/twig.php", "config/packages/twig.xml", "config/packages/twig.yaml"],
        )


class FindConfigEvidenceMisc(unittest.TestCase):
    def test_no_config_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ev = intro.find_config_evidence(Path(d), "security", intro.SECURITY_SUBTREE_KEYS)
            self.assertEqual(ev.files, [])
            self.assertFalse(ev.prod_override)

    def test_bundles_php_never_counts_as_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "config").mkdir()
            (root / "config" / "bundles.php").write_text(
                "<?php\nreturn [\n    Symfony\\Bundle\\SecurityBundle\\SecurityBundle::class => ['all' => true],\n];\n"
            )
            ev = intro.find_config_evidence(root, "security", intro.SECURITY_SUBTREE_KEYS)
            self.assertEqual(ev.files, [])


class FindConfigEvidenceHiddenDirSkipped(unittest.TestCase):
    """P8: a hidden directory under config/ (e.g. an editor/tool dotfolder
    dropped there) is never walked — same always-on rule as the PHP extractor
    and the recipe's own `_list_*` walks, applied here to `config/**`.
    """

    def test_dot_prefixed_subdir_under_config_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            packages = root / "config" / "packages"
            packages.mkdir(parents=True)
            (packages / "security.yaml").write_text(
                "security:\n"
                "    firewalls:\n"
                "        main:\n"
                "            lazy: true\n"
            )
            hidden = root / "config" / ".idea"
            hidden.mkdir()
            (hidden / "security.yaml").write_text(
                "security:\n"
                "    firewalls:\n"
                "        main:\n"
                "            lazy: false\n"
            )
            ev = intro.find_config_evidence(root, "security", intro.SECURITY_SUBTREE_KEYS)
            self.assertEqual(ev.files, ["config/packages/security.yaml"])


if __name__ == "__main__":
    unittest.main()
