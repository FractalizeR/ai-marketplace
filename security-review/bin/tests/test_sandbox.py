"""Unit tests for bin/recon/sandbox.py console enrichment.

Covers the post-refactor ConsoleRunner-based API:
- `build_console_argv` — host append, container append, Makefile `{args}`
  placeholder, and empty args.
- `try_console_smoke` — multi-probe fallback, disabled short-circuit,
  timeout handling.
- `run_console_command` — rc0/nonzero/timeout/not-found/disabled paths.
- mode-aware default timeouts (container picks the CONTAINER constant).

Subprocess is mocked via `unittest.mock.patch` — no real PHP boot.
The extractor (`run_extractor`) is intentionally not exercised here.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent

sys.path.insert(0, str(BIN_DIR))
from recon.sandbox import (  # noqa: E402
    CONSOLE_COMMAND_TIMEOUT_CONTAINER,
    CONSOLE_COMMAND_TIMEOUT_HOST,
    CONSOLE_COMMAND_TIMEOUT_SECONDS,
    CONSOLE_SMOKE_TIMEOUT_CONTAINER,
    CONSOLE_SMOKE_TIMEOUT_HOST,
    CONSOLE_SMOKE_TIMEOUT_SECONDS,
    ConsoleRunner,
    build_console_argv,
    container_runner,
    custom_runner,
    disabled_runner,
    host_runner,
    run_console_command,
    try_console_smoke,
)


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["console"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


CWD = Path("/tmp/project")

HOST = host_runner("php bin/console", CWD)
CONTAINER = container_runner("docker compose exec -T php php bin/console", CWD)
MAKEFILE = custom_runner("make console CMD={args}", CWD)


# ---------------------------------------------------------------------------
# build_console_argv
# ---------------------------------------------------------------------------

class BuildConsoleArgvTests(unittest.TestCase):
    def test_host_append(self):
        argv = build_console_argv(HOST, ["debug:router", "--format=json"])
        self.assertEqual(argv, ["php", "bin/console", "debug:router", "--format=json"])

    def test_container_append(self):
        argv = build_console_argv(CONTAINER, ["list"])
        self.assertEqual(
            argv,
            ["docker", "compose", "exec", "-T", "php", "php", "bin/console", "list"],
        )

    def test_makefile_args_placeholder_glues_into_one_token(self):
        # Contract rule: replace "{args}" with shlex.quote(" ".join(args)) — the
        # space-joined args become ONE quoted shell token — then shlex.split the
        # whole string. With >=2 args, the joined string contains a space, so
        # shlex.quote wraps it and the final shlex.split keeps CMD=... glued.
        # This is the Makefile passthrough: `make console CMD=<one value>`.
        argv = build_console_argv(MAKEFILE, ["debug:router", "--format=json"])
        self.assertEqual(argv, ["make", "console", "CMD=debug:router --format=json"])

    def test_makefile_args_placeholder_glues_with_inner_space(self):
        # An arg that itself contains a space is still part of the single glued
        # value: shlex.quote("cache:clear --env=prod test") wraps the whole
        # joined string, so CMD= stays one token through the final shlex.split.
        argv = build_console_argv(MAKEFILE, ["cache:clear", "--env=prod test"])
        self.assertEqual(argv, ["make", "console", "CMD=cache:clear --env=prod test"])

    def test_empty_args_host(self):
        argv = build_console_argv(HOST, [])
        self.assertEqual(argv, ["php", "bin/console"])

    def test_empty_args_placeholder(self):
        # shlex.quote(" ".join([])) == shlex.quote("") == "''" → after the final
        # shlex.split, CMD= becomes a bare empty assignment token.
        argv = build_console_argv(MAKEFILE, [])
        self.assertEqual(argv, ["make", "console", "CMD="])

    def test_single_arg_no_space_stays_glued(self):
        # A single metachar-free arg joins to itself with no space, so
        # shlex.quote leaves it unquoted; CMD= stays one token regardless.
        argv = build_console_argv(custom_runner("make c CMD={args}", CWD), ["list"])
        self.assertEqual(argv, ["make", "c", "CMD=list"])

    def test_args_glued_into_single_make_value(self):
        # Multiple args (including one with an inner space) collapse into ONE
        # quoted CMD= value: shlex.quote("a b c") wraps the whole joined string.
        argv = build_console_argv(custom_runner("make c CMD={args}", CWD), ["a b", "c"])
        self.assertEqual(argv, ["make", "c", "CMD=a b c"])

    def test_none_template_raises(self):
        runner = ConsoleRunner(mode="custom", cmd_template=None, cwd=CWD)
        with self.assertRaises(ValueError):
            build_console_argv(runner, ["list"])


# ---------------------------------------------------------------------------
# try_console_smoke
# ---------------------------------------------------------------------------

class TryConsoleSmokeTests(unittest.TestCase):
    def test_first_probe_list_succeeds(self):
        with patch("recon.sandbox.subprocess.run") as mock_run:
            mock_run.return_value = _completed(returncode=0)
            ok, warning = try_console_smoke(HOST)
        self.assertTrue(ok)
        self.assertIsNone(warning)
        # debug:router must NOT be tried when list succeeds.
        self.assertEqual(mock_run.call_count, 1)
        argv0 = mock_run.call_args_list[0].args[0]
        self.assertIn("list", argv0)
        self.assertNotIn("debug:router", argv0)

    def test_falls_back_to_debug_router(self):
        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            if "list" in cmd and "debug:router" not in cmd:
                return _completed(returncode=1, stderr="kernel boot exploded")
            if "debug:router" in cmd:
                return _completed(returncode=0)
            raise AssertionError(f"unexpected cmd: {cmd}")

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            ok, warning = try_console_smoke(HOST)
        self.assertTrue(ok)
        self.assertIsNone(warning)
        self.assertEqual(len(calls), 2)
        self.assertIn("list", calls[0])
        self.assertIn("debug:router", calls[1])
        self.assertIn("--format=json", calls[1])

    def test_both_probes_fail(self):
        def fake_run(cmd, **kwargs):
            if "debug:router" in cmd:
                return _completed(returncode=1, stderr="unknown option --format")
            return _completed(returncode=1, stderr="autoload failure: missing class Foo")

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            ok, warning = try_console_smoke(HOST)
        self.assertFalse(ok)
        self.assertIsNotNone(warning)
        assert warning is not None
        self.assertTrue(warning.startswith("console_smoke_failed:"))
        # Last probe's stderr is summarized.
        self.assertIn("unknown option --format", warning)

    def test_disabled_runner_no_subprocess(self):
        runner = disabled_runner("console_disabled_by_flag", CWD)
        with patch("recon.sandbox.subprocess.run") as mock_run:
            ok, warning = try_console_smoke(runner)
        self.assertFalse(ok)
        self.assertEqual(warning, "console_disabled_by_flag")
        mock_run.assert_not_called()

    def test_disabled_runner_default_reason(self):
        runner = ConsoleRunner(mode="disabled", cmd_template=None, cwd=CWD)
        with patch("recon.sandbox.subprocess.run") as mock_run:
            ok, warning = try_console_smoke(runner)
        self.assertFalse(ok)
        self.assertEqual(warning, "console_disabled")
        mock_run.assert_not_called()

    def test_timeout_on_all_probes(self):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run) as mock_run:
            ok, warning = try_console_smoke(HOST)
        self.assertFalse(ok)
        self.assertIsNotNone(warning)
        assert warning is not None
        self.assertTrue(warning.startswith("console_smoke_failed:"))
        self.assertIn("timed out", warning)
        # Both default probes attempted (timeout is not infra — keep trying).
        self.assertEqual(mock_run.call_count, 2)

    def test_file_not_found_on_all_probes(self):
        with patch("recon.sandbox.subprocess.run", side_effect=FileNotFoundError("no php")) as mock_run:
            ok, warning = try_console_smoke(HOST)
        self.assertFalse(ok)
        assert warning is not None
        self.assertTrue(warning.startswith("console_smoke_failed:"))
        self.assertIn("command not found", warning)
        self.assertEqual(mock_run.call_count, 2)

    def test_long_stderr_truncated(self):
        long_err = "x" * 500

        def fake_run(cmd, **kwargs):
            return _completed(returncode=1, stderr=long_err)

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            ok, warning = try_console_smoke(HOST)
        self.assertFalse(ok)
        assert warning is not None
        self.assertLessEqual(warning.count("x"), 200)
        self.assertGreater(warning.count("x"), 0)

    def test_custom_probes_override(self):
        captured: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            captured.append(list(cmd))
            return _completed(returncode=0)

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            ok, warning = try_console_smoke(HOST, probes=[["about"]])
        self.assertTrue(ok)
        self.assertIsNone(warning)
        self.assertEqual(len(captured), 1)
        self.assertIn("about", captured[0])

    def test_container_default_smoke_timeout(self):
        captured_timeouts: list[int] = []

        def fake_run(cmd, **kwargs):
            captured_timeouts.append(kwargs["timeout"])
            return _completed(returncode=0)

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            try_console_smoke(CONTAINER)
        self.assertEqual(captured_timeouts[0], CONSOLE_SMOKE_TIMEOUT_CONTAINER)

    def test_host_default_smoke_timeout(self):
        captured_timeouts: list[int] = []

        def fake_run(cmd, **kwargs):
            captured_timeouts.append(kwargs["timeout"])
            return _completed(returncode=0)

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            try_console_smoke(HOST)
        self.assertEqual(captured_timeouts[0], CONSOLE_SMOKE_TIMEOUT_HOST)

    def test_explicit_timeout_overrides_mode(self):
        captured_timeouts: list[int] = []

        def fake_run(cmd, **kwargs):
            captured_timeouts.append(kwargs["timeout"])
            return _completed(returncode=0)

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            try_console_smoke(CONTAINER, timeout=5)
        self.assertEqual(captured_timeouts[0], 5)

    def test_runs_in_runner_cwd(self):
        captured_cwd: list = []

        def fake_run(cmd, **kwargs):
            captured_cwd.append(kwargs["cwd"])
            return _completed(returncode=0)

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            try_console_smoke(HOST)
        self.assertEqual(captured_cwd[0], CWD)


# ---------------------------------------------------------------------------
# run_console_command
# ---------------------------------------------------------------------------

class RunConsoleCommandTests(unittest.TestCase):
    def test_success_returns_stdout(self):
        with patch("recon.sandbox.subprocess.run") as mock_run:
            mock_run.return_value = _completed(returncode=0, stdout="ROUTES JSON")
            stdout, warning = run_console_command(HOST, ["debug:router", "--format=json"])
        self.assertEqual(stdout, "ROUTES JSON")
        self.assertIsNone(warning)
        argv = mock_run.call_args.args[0]
        self.assertEqual(argv, ["php", "bin/console", "debug:router", "--format=json"])

    def test_nonzero_returns_warning(self):
        with patch("recon.sandbox.subprocess.run") as mock_run:
            mock_run.return_value = _completed(returncode=2, stderr="boom: bad command")
            stdout, warning = run_console_command(HOST, ["debug:router"])
        self.assertIsNone(stdout)
        assert warning is not None
        self.assertTrue(warning.startswith("console_command_failed:"))
        self.assertIn("debug:router", warning)
        self.assertIn("boom: bad command", warning)

    def test_nonzero_no_stderr_uses_rc(self):
        with patch("recon.sandbox.subprocess.run") as mock_run:
            mock_run.return_value = _completed(returncode=3, stderr="")
            stdout, warning = run_console_command(HOST, ["debug:router"])
        self.assertIsNone(stdout)
        assert warning is not None
        self.assertIn("rc=3", warning)

    def test_nonzero_stderr_truncated(self):
        with patch("recon.sandbox.subprocess.run") as mock_run:
            mock_run.return_value = _completed(returncode=1, stderr="y" * 500)
            stdout, warning = run_console_command(HOST, ["debug:router"])
        self.assertIsNone(stdout)
        assert warning is not None
        self.assertLessEqual(warning.count("y"), 200)

    def test_timeout_returns_warning(self):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            stdout, warning = run_console_command(HOST, ["debug:router"])
        self.assertIsNone(stdout)
        assert warning is not None
        self.assertTrue(warning.startswith("console_command_failed:"))
        self.assertIn("timed out", warning)
        self.assertIn("debug:router", warning)

    def test_file_not_found_returns_warning(self):
        with patch("recon.sandbox.subprocess.run", side_effect=FileNotFoundError("no php")):
            stdout, warning = run_console_command(HOST, ["debug:router"])
        self.assertIsNone(stdout)
        assert warning is not None
        self.assertTrue(warning.startswith("console_command_failed:"))
        self.assertIn("command not found", warning)
        self.assertIn("php", warning)

    def test_disabled_runner_no_subprocess(self):
        runner = disabled_runner("console_disabled_by_flag", CWD)
        with patch("recon.sandbox.subprocess.run") as mock_run:
            stdout, warning = run_console_command(runner, ["debug:router"])
        self.assertIsNone(stdout)
        self.assertEqual(warning, "console_disabled_by_flag")
        mock_run.assert_not_called()

    def test_disabled_runner_default_reason(self):
        runner = ConsoleRunner(mode="disabled", cmd_template=None, cwd=CWD)
        with patch("recon.sandbox.subprocess.run") as mock_run:
            stdout, warning = run_console_command(runner, ["debug:router"])
        self.assertIsNone(stdout)
        self.assertEqual(warning, "console_disabled")
        mock_run.assert_not_called()

    def test_container_default_command_timeout(self):
        captured_timeouts: list[int] = []

        def fake_run(cmd, **kwargs):
            captured_timeouts.append(kwargs["timeout"])
            return _completed(returncode=0, stdout="ok")

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            run_console_command(CONTAINER, ["debug:router"])
        self.assertEqual(captured_timeouts[0], CONSOLE_COMMAND_TIMEOUT_CONTAINER)

    def test_host_default_command_timeout(self):
        captured_timeouts: list[int] = []

        def fake_run(cmd, **kwargs):
            captured_timeouts.append(kwargs["timeout"])
            return _completed(returncode=0, stdout="ok")

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            run_console_command(HOST, ["debug:router"])
        self.assertEqual(captured_timeouts[0], CONSOLE_COMMAND_TIMEOUT_HOST)

    def test_explicit_timeout_overrides_mode(self):
        captured_timeouts: list[int] = []

        def fake_run(cmd, **kwargs):
            captured_timeouts.append(kwargs["timeout"])
            return _completed(returncode=0, stdout="ok")

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            run_console_command(CONTAINER, ["debug:router"], timeout=7)
        self.assertEqual(captured_timeouts[0], 7)

    def test_runs_in_runner_cwd_with_container_argv(self):
        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["argv"] = list(cmd)
            captured["cwd"] = kwargs["cwd"]
            return _completed(returncode=0, stdout="ok")

        with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
            run_console_command(CONTAINER, ["list"])
        self.assertEqual(
            captured["argv"],
            ["docker", "compose", "exec", "-T", "php", "php", "bin/console", "list"],
        )
        self.assertEqual(captured["cwd"], CWD)


# ---------------------------------------------------------------------------
# Timeout-constant aliases.
# ---------------------------------------------------------------------------

class TimeoutAliasTests(unittest.TestCase):
    def test_legacy_aliases_map_to_host_values(self):
        self.assertEqual(CONSOLE_SMOKE_TIMEOUT_SECONDS, CONSOLE_SMOKE_TIMEOUT_HOST)
        self.assertEqual(CONSOLE_COMMAND_TIMEOUT_SECONDS, CONSOLE_COMMAND_TIMEOUT_HOST)


if __name__ == "__main__":
    unittest.main()
