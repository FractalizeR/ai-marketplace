"""Unit tests for bin/recon/environment.py::probe_environment + CLI.

`shutil.which` and `subprocess.run` are mocked for the host-php parts so the
suite is deterministic regardless of the test machine. Filesystem markers are
created in real temp dirs.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent

sys.path.insert(0, str(BIN_DIR))
from recon.environment import (  # noqa: E402
    EnvProbe,
    RunnerSuggestion,
    main,
    probe_environment,
)

ENTRY = ["php", "bin/console"]


# ---------------------------------------------------------------------------
# Mock helpers.
# ---------------------------------------------------------------------------


def _php_version_completed(version: str = "8.5.1") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["php", "--version"],
        returncode=0,
        stdout=f"PHP {version} (cli) (built: Jan 1 2026 00:00:00) (NTS)\n"
        "Copyright (c) The PHP Group\n",
        stderr="",
    )


def _patch_host_php(present: bool, version: str = "8.5.1"):
    """Context manager bundling `which` + `subprocess.run` patches for host php."""

    class _Ctx:
        def __enter__(self):
            self._which = patch(
                "recon.environment.shutil.which",
                return_value=("/usr/bin/php" if present else None),
            )
            self._run = patch(
                "recon.environment.subprocess.run",
                return_value=_php_version_completed(version),
            )
            self._which.start()
            self._run.start()
            return self

        def __exit__(self, *exc):
            self._run.stop()
            self._which.stop()
            return False

    return _Ctx()


def _modes(probe: EnvProbe) -> list[str]:
    return [s.mode for s in probe.suggestions]


def _by_mode(probe: EnvProbe, mode: str) -> list[RunnerSuggestion]:
    return [s for s in probe.suggestions if s.mode == mode]


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


class NoContainerHostPresent(unittest.TestCase):
    def test_no_signals_host_present(self):
        with tempfile.TemporaryDirectory() as td:
            with _patch_host_php(present=True, version="8.3.7"):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertFalse(probe.containerized)
        self.assertEqual(probe.container_signals, [])
        self.assertTrue(probe.host_php_present)
        self.assertEqual(probe.host_php_version, "8.3.7")
        host = _by_mode(probe, "host")
        self.assertEqual(len(host), 1)
        self.assertEqual(host[0].cmd_template, "php bin/console")
        self.assertEqual(host[0].source, "host")
        self.assertIn("8.3.7", host[0].label)
        # Not containerized -> host first.
        self.assertEqual(_modes(probe)[0], "host")


class DockerComposeServices(unittest.TestCase):
    def test_compose_with_php_service(self):
        compose = (
            "version: '3.8'\n"
            "services:\n"
            "  db:\n"
            "    image: mysql:8\n"
            "  php:\n"
            "    build: .\n"
            "    image: myapp/php:8.5\n"
            "  redis:\n"
            "    image: redis:7\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(compose)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.containerized)
        self.assertIn("docker-compose.yml", probe.container_signals)
        self.assertEqual(probe.suggested_php_service, "php")
        container = _by_mode(probe, "container")
        self.assertTrue(container)
        primary = container[0]
        self.assertEqual(
            primary.cmd_template, "docker compose exec -T php php bin/console"
        )
        self.assertEqual(primary.source, "docker-compose:php")
        self.assertIn("-T", primary.cmd_template)
        # Containerized -> container first.
        self.assertEqual(_modes(probe)[0], "container")
        # Alternatives included (db, redis), suggested first.
        sources = [c.source for c in container]
        self.assertEqual(sources[0], "docker-compose:php")
        self.assertIn("docker-compose:db", sources)
        self.assertIn("docker-compose:redis", sources)

    def test_compose_build_app_service(self):
        # No php/fpm name, no php image -> falls to generic name 'app'.
        compose = (
            "services:\n"
            "  db:\n"
            "    image: postgres:16\n"
            "  app:\n"
            "    build:\n"
            "      context: .\n"
            "      dockerfile: Dockerfile\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "compose.yaml").write_text(compose)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertEqual(probe.suggested_php_service, "app")
        self.assertIn("compose.yaml", probe.container_signals)
        primary = _by_mode(probe, "container")[0]
        self.assertEqual(
            primary.cmd_template, "docker compose exec -T app php bin/console"
        )


class ComposeEdgeCases(unittest.TestCase):
    def test_empty_compose_file_no_crash_no_service(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text("")
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        # Containerized (file present) but no service identified -> no container suggestion.
        self.assertTrue(probe.containerized)
        self.assertIsNone(probe.suggested_php_service)
        self.assertEqual(_by_mode(probe, "container"), [])

    def test_leading_dash_service_name_ignored(self):
        # A name starting with '-' would be parsed by docker as a flag; the
        # scanner must not pick it. The valid 'php' service wins instead.
        compose = (
            "services:\n"
            "  -bad:\n"
            "    image: weird\n"
            "  php:\n"
            "    image: php:8.4-fpm\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(compose)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertEqual(probe.suggested_php_service, "php")
        sources = [c.source for c in _by_mode(probe, "container")]
        self.assertNotIn("docker-compose:-bad", sources)

    def test_first_php_image_service_wins(self):
        # Two services with a php image; heuristic (2) returns the FIRST match.
        compose = (
            "services:\n"
            "  worker:\n"
            "    image: company/php-worker:8.4\n"
            "  web:\n"
            "    image: company/php-web:8.4\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(compose)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertEqual(probe.suggested_php_service, "worker")

    def test_tab_indented_compose_tolerated(self):
        # YAML forbids tabs, but the scanner counts a tab as one indent unit and
        # must not crash; it should still find the service.
        compose = "services:\n\tphp:\n\t\timage: php:8.4\n"
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(compose)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.containerized)
        self.assertEqual(probe.suggested_php_service, "php")


class DockerfileOnly(unittest.TestCase):
    def test_dockerfile_no_compose_no_container_suggestion(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Dockerfile").write_text("FROM php:8.5-cli\n")
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.containerized)
        self.assertIn("Dockerfile", probe.container_signals)
        self.assertIsNone(probe.suggested_php_service)
        # No compose file -> no container suggestion buildable.
        self.assertEqual(_by_mode(probe, "container"), [])
        # Host still available.
        self.assertEqual(len(_by_mode(probe, "host")), 1)


class OtherContainerSignals(unittest.TestCase):
    def test_ddev_dir(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".ddev").mkdir()
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.containerized)
        self.assertIn(".ddev", probe.container_signals)

    def test_ddev_config_file_only(self):
        with tempfile.TemporaryDirectory() as td:
            ddev = Path(td) / ".ddev"
            ddev.mkdir()
            (ddev / "config.yaml").write_text("name: x\n")
            with _patch_host_php(present=False):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertIn(".ddev", probe.container_signals)

    def test_lando(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".lando.yml").write_text("name: x\n")
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.containerized)
        self.assertIn(".lando.yml", probe.container_signals)

    def test_devcontainer_dir(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".devcontainer").mkdir()
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertIn(".devcontainer", probe.container_signals)

    def test_devcontainer_json(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".devcontainer.json").write_text("{}\n")
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertIn(".devcontainer", probe.container_signals)

    def test_laravel_sail_require_dev(self):
        composer = json.dumps(
            {"require-dev": {"laravel/sail": "^1.0", "phpunit/phpunit": "^11"}}
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "composer.json").write_text(composer)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.containerized)
        self.assertIn("laravel/sail", probe.container_signals)

    def test_laravel_sail_require(self):
        composer = json.dumps({"require": {"laravel/sail": "^1.0"}})
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "composer.json").write_text(composer)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertIn("laravel/sail", probe.container_signals)


class MakefileTargets(unittest.TestCase):
    def test_console_target_with_cmd_var(self):
        makefile = (
            "console:\n"
            "\tdocker compose exec app php bin/console $(CMD)\n"
            "\n"
            "build:\n"
            "\tdocker compose build\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Makefile").write_text(makefile)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        mk = _by_mode(probe, "makefile")
        self.assertEqual(len(mk), 1)
        self.assertEqual(mk[0].cmd_template, "make console CMD={args}")
        self.assertEqual(mk[0].source, "makefile:console")
        self.assertIsNotNone(mk[0].detail)
        assert mk[0].detail is not None
        self.assertIn("docker compose exec app php bin/console $(CMD)", mk[0].detail)

    def test_console_target_without_passthrough_var(self):
        makefile = "shell:\n\tdocker compose exec app php bin/console list\n"
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Makefile").write_text(makefile)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        mk = _by_mode(probe, "makefile")
        self.assertEqual(len(mk), 1)
        self.assertEqual(mk[0].cmd_template, "make shell")
        assert mk[0].detail is not None
        # Body present + note about not accepting enrichment subcommands.
        self.assertIn("php bin/console list", mk[0].detail)
        self.assertIn("may not accept enrichment", mk[0].detail)

    def test_non_console_target_ignored(self):
        makefile = (
            "build:\n"
            "\tdocker compose build\n"
            "\n"
            "test:\n"
            "\tphpunit\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Makefile").write_text(makefile)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertEqual(_by_mode(probe, "makefile"), [])

    def test_assignment_not_treated_as_target(self):
        # `CMD :=` is an assignment, not a target; must not be parsed.
        makefile = (
            "CMD := list\n"
            "console:\n"
            "\tphp bin/console $(ARGS)\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Makefile").write_text(makefile)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        mk = _by_mode(probe, "makefile")
        self.assertEqual(len(mk), 1)
        self.assertEqual(mk[0].source, "makefile:console")
        self.assertEqual(mk[0].cmd_template, "make console ARGS={args}")


class HostPhpAbsent(unittest.TestCase):
    def test_no_host_suggestion_when_php_missing(self):
        with tempfile.TemporaryDirectory() as td:
            with _patch_host_php(present=False):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertFalse(probe.host_php_present)
        self.assertIsNone(probe.host_php_version)
        self.assertEqual(_by_mode(probe, "host"), [])

    def test_version_unparseable_yields_none(self):
        with tempfile.TemporaryDirectory() as td:
            with patch(
                "recon.environment.shutil.which", return_value="/usr/bin/php"
            ), patch(
                "recon.environment.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["php"], returncode=0, stdout="garbage output\n", stderr=""
                ),
            ):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.host_php_present)
        self.assertIsNone(probe.host_php_version)
        # Host suggestion still buildable; label shows "?".
        host = _by_mode(probe, "host")
        self.assertEqual(len(host), 1)
        self.assertIn("?", host[0].label)

    def test_php_version_subprocess_raises_tolerated(self):
        with tempfile.TemporaryDirectory() as td:
            with patch(
                "recon.environment.shutil.which", return_value="/usr/bin/php"
            ), patch(
                "recon.environment.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="php", timeout=5),
            ):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertTrue(probe.host_php_present)
        self.assertIsNone(probe.host_php_version)


class NoEntrypoint(unittest.TestCase):
    def test_facts_present_no_host_container_suggestions(self):
        compose = "services:\n  php:\n    image: php:8.5\n"
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(compose)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=None)
        # Facts present.
        self.assertTrue(probe.containerized)
        self.assertTrue(probe.host_php_present)
        self.assertEqual(probe.suggested_php_service, "php")
        # No host/container suggestions without an entrypoint.
        self.assertEqual(_by_mode(probe, "host"), [])
        self.assertEqual(_by_mode(probe, "container"), [])

    def test_makefile_suggestion_still_built_without_entrypoint(self):
        # Makefile templates embed their own command, so they don't need the entrypoint.
        makefile = "console:\n\tphp bin/console $(CMD)\n"
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Makefile").write_text(makefile)
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=None)
        mk = _by_mode(probe, "makefile")
        self.assertEqual(len(mk), 1)
        self.assertEqual(mk[0].cmd_template, "make console CMD={args}")


class MalformedInput(unittest.TestCase):
    def test_garbage_compose_no_exception(self):
        garbage = (
            "this: is\n"
            "   not   : really\n"
            "services:\n"
            "  &anchor web\n"
            "  - list-item\n"
            "      weird-indent: 1\n"
            "  php: &svc\n"
            "    image: php:8.5\n"
            "random trailing junk %%%\n"
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(garbage)
            with _patch_host_php(present=True):
                # Must not raise.
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertIsInstance(probe, EnvProbe)
        self.assertTrue(probe.containerized)

    def test_malformed_composer_json_no_exception(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "composer.json").write_text("{ this is not valid json ,,, ")
            with _patch_host_php(present=True):
                probe = probe_environment(Path(td), console_entrypoint=ENTRY)
        self.assertIsInstance(probe, EnvProbe)
        # laravel/sail signal must not appear from broken composer.
        self.assertNotIn("laravel/sail", probe.container_signals)

    def test_nonexistent_project_root(self):
        # A path that does not exist must yield a safe probe, not an exception.
        with _patch_host_php(present=True):
            probe = probe_environment(
                Path("/nonexistent/path/xyz123"), console_entrypoint=ENTRY
            )
        self.assertIsInstance(probe, EnvProbe)
        self.assertFalse(probe.containerized)


class CliInterface(unittest.TestCase):
    def test_cli_emits_valid_json(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(
                "services:\n  php:\n    image: php:8.5\n"
            )
            captured: dict = {}

            def fake_print(s):
                captured["out"] = s

            with _patch_host_php(present=True), patch(
                "builtins.print", side_effect=fake_print
            ):
                rc = main([td, "--console-entrypoint", "php bin/console"])
        self.assertEqual(rc, 0)
        payload = json.loads(captured["out"])
        self.assertIn("containerized", payload)
        self.assertIn("suggestions", payload)
        self.assertTrue(payload["containerized"])
        self.assertEqual(payload["suggested_php_service"], "php")
        # Suggestions serialize as dicts with the expected keys.
        self.assertTrue(payload["suggestions"])
        first = payload["suggestions"][0]
        for key in ("mode", "cmd_template", "label", "source", "detail"):
            self.assertIn(key, first)

    def test_cli_empty_entrypoint_omits_runnable_suggestions(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "docker-compose.yml").write_text(
                "services:\n  php:\n    image: php:8.5\n"
            )
            captured: dict = {}

            with _patch_host_php(present=True), patch(
                "builtins.print", side_effect=lambda s: captured.__setitem__("out", s)
            ):
                rc = main([td, "--console-entrypoint", ""])
        self.assertEqual(rc, 0)
        payload = json.loads(captured["out"])
        # Empty entrypoint -> no host/container suggestions.
        modes = [s["mode"] for s in payload["suggestions"]]
        self.assertNotIn("host", modes)
        self.assertNotIn("container", modes)


if __name__ == "__main__":
    unittest.main()
