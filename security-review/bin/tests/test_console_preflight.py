"""Tests for `recon_inventory.py --console-preflight`.

All scenarios drive the real CLI (subprocess), mirroring test_console_runner.py's
convention: a containerized fixture (docker-compose.yml present) makes
`decide_console_runner` pick the container-dominant gate, so no host `php` is
ever consulted, and `--console-cmd true`/`--console-cmd false` stand in for a
real console without spawning php/docker. No test spawns a real console.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"
FIX_GEN = THIS_DIR / "fixtures" / "generic_php"

sys.path.insert(0, str(BIN_DIR))
import recon_inventory as ri  # noqa: E402
from recon.environment import EnvProbe, RunnerSuggestion  # noqa: E402


def _run_cli(*args: str, env: dict | None = None, timeout: int = 30) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, str(RECON), *args],
        capture_output=True, text=True, timeout=timeout, env=full_env,
    )


def _make_containerized_symfony(root: Path) -> None:
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "console").write_text("#!/usr/bin/env php\n<?php\n")
    (root / "docker-compose.yml").write_text(
        "services:\n  php:\n    image: php:8.4-fpm\n  db:\n    image: mysql:8\n"
    )
    (root / "composer.json").write_text('{"require": {"symfony/framework-bundle": "^7.0"}}')


class ConsolePreflightCLI(unittest.TestCase):
    def test_containerized_without_cmd_is_not_ok_with_suggestions(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            proc = _run_cli(str(proj), "--console-preflight", "--recipe", "symfony")
            self.assertEqual(proc.returncode, 3, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(
                set(out.keys()), {"applicable", "ok", "mode", "reason", "suggestions"}
            )
            self.assertTrue(out["applicable"])
            self.assertFalse(out["ok"])
            self.assertEqual(out["mode"], "disabled")
            self.assertTrue(out["reason"].startswith("env_runner_unknown"))
            self.assertTrue(out["suggestions"], msg=out["suggestions"])
            self.assertEqual(out["suggestions"][0]["mode"], "container")

    def test_custom_cmd_smoke_failure_exits_3(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            proc = _run_cli(
                str(proj), "--console-preflight", "--recipe", "symfony",
                "--console-cmd", "false",
            )
            self.assertEqual(proc.returncode, 3, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertTrue(out["applicable"])
            self.assertFalse(out["ok"])
            self.assertEqual(out["mode"], "custom")
            self.assertTrue(out["reason"].startswith("console_smoke_failed"), msg=out["reason"])

    def test_smoke_failure_reason_is_redacted(self):
        # The last stderr line of a failed boot often echoes a DSN; `reason`
        # is printed to CI logs and transcripts.
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            leak = (
                "sh -c 'echo \"connect to mysql://app:Leak3dPw@db/app failed, "
                "password: Leak3dPw2\" >&2; exit 1'"
            )
            proc = _run_cli(
                str(proj), "--console-preflight", "--recipe", "symfony", "--console-cmd", leak,
            )
            self.assertEqual(proc.returncode, 3, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertIn("<redacted>", out["reason"])
            self.assertNotIn("Leak3dPw", proc.stdout)

    def test_custom_cmd_smoke_success_exits_0(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            proc = _run_cli(
                str(proj), "--console-preflight", "--recipe", "symfony",
                "--console-cmd", "true",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertTrue(out["applicable"])
            self.assertTrue(out["ok"])
            self.assertEqual(out["mode"], "custom")
            self.assertIsNone(out["reason"])

    def test_cmd_from_env_var_is_honored(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            proc = _run_cli(
                str(proj), "--console-preflight", "--recipe", "symfony",
                env={ri.CONSOLE_CMD_ENV: "true"},
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["mode"], "custom")
            self.assertTrue(out["ok"])

    def test_no_console_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            proc = _run_cli(
                str(proj), "--console-preflight", "--recipe", "symfony", "--no-console",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertFalse(out["applicable"])
            self.assertTrue(out["ok"])
            self.assertEqual(out["suggestions"], [])

    def test_generic_recipe_is_not_applicable(self):
        proc = _run_cli(str(FIX_GEN), "--console-preflight")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertFalse(out["applicable"])
        self.assertTrue(out["ok"])
        self.assertIsNone(out["reason"])

    def test_invalid_console_cmd_exits_3(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            proc = _run_cli(
                str(proj), "--console-preflight", "--recipe", "symfony",
                "--console-cmd", 'make console CMD="unclosed',
            )
            self.assertEqual(proc.returncode, 3, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertFalse(out["ok"])
            self.assertEqual(out["mode"], "disabled")
            self.assertTrue(out["reason"].startswith("invalid_console_cmd"), msg=out["reason"])

    def test_project_root_not_a_directory_is_usage_error(self):
        proc = _run_cli("/no/such/path", "--console-preflight")
        self.assertEqual(proc.returncode, 2, msg=proc.stdout)
        self.assertIn("not a directory", proc.stderr)

    def test_unknown_recipe_is_usage_error(self):
        with tempfile.TemporaryDirectory() as td:
            proc = _run_cli(td, "--console-preflight", "--recipe", "no-such-recipe")
            self.assertEqual(proc.returncode, 2, msg=proc.stdout)
            self.assertIn("unknown recipe", proc.stderr)


class ConsolePreflightUnit(unittest.TestCase):
    """Direct calls to `cmd_console_preflight`, mocking the environment probe
    and smoke helper — covers the host-runner branch without ever touching a
    real `php` binary.
    """

    def _probe(self, **kwargs) -> EnvProbe:
        defaults = dict(
            containerized=False, container_signals=[], host_php_present=True,
            host_php_version="8.3.0", suggested_php_service=None, suggestions=[],
            reason="test",
        )
        defaults.update(kwargs)
        return EnvProbe(**defaults)

    def test_ok_host(self):
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(ri._environment, "probe_environment", return_value=self._probe()), \
                mock.patch.object(ri._sandbox, "try_console_smoke", return_value=(True, None)) as smoke:
            buf = _capture_stdout(
                lambda: ri.cmd_console_preflight(Path(td), "symfony", False, None)
            )
            code, out = buf
            self.assertEqual(code, 0)
            self.assertEqual(out["mode"], "host")
            self.assertTrue(out["ok"])
            self.assertIsNone(out["reason"])
            smoke.assert_called_once()

    def test_no_console_never_calls_smoke(self):
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(ri._environment, "probe_environment", return_value=self._probe()), \
                mock.patch.object(ri._sandbox, "try_console_smoke") as smoke:
            code, out = _capture_stdout(
                lambda: ri.cmd_console_preflight(Path(td), "symfony", True, None)
            )
            self.assertEqual(code, 0)
            self.assertFalse(out["applicable"])
            smoke.assert_not_called()

    def test_suggestions_are_passed_through(self):
        suggestion = RunnerSuggestion(
            mode="host", cmd_template="php bin/console", label="Run on host",
            source="host",
        )
        probe = self._probe(suggestions=[suggestion])
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(ri._environment, "probe_environment", return_value=probe), \
                mock.patch.object(ri._sandbox, "try_console_smoke", return_value=(False, "console_smoke_failed: boom")):
            code, out = _capture_stdout(
                lambda: ri.cmd_console_preflight(Path(td), "symfony", False, None)
            )
            self.assertEqual(code, 3)
            self.assertEqual(len(out["suggestions"]), 1)
            self.assertEqual(out["suggestions"][0]["label"], "Run on host")


def _capture_stdout(fn):
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = fn()
    return code, json.loads(buf.getvalue())


if __name__ == "__main__":
    unittest.main()
