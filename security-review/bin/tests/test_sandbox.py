"""Unit tests for bin/recon/sandbox.py::try_console_smoke.

Covers the two-step fallback chain introduced in v3.1.4:
1. `bin/console list` — first attempt.
2. `bin/console debug:router --format=json` — fallback when `list` fails.

Subprocess is mocked via `unittest.mock.patch` — no real PHP boot.
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
from recon.sandbox import try_console_smoke  # noqa: E402


def _make_project_with_console() -> tempfile.TemporaryDirectory:
    """Create a temp project with bin/console (empty file is fine — we mock subprocess).

    Caller is responsible for cleanup (use as context manager).
    """
    td = tempfile.TemporaryDirectory()
    bin_dir = Path(td.name) / "bin"
    bin_dir.mkdir()
    (bin_dir / "console").write_text("#!/usr/bin/env php\n<?php\n")
    return td


def _completed(returncode: int, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["php"], returncode=returncode, stdout="", stderr=stderr,
    )


class ConsoleSmokeFallback(unittest.TestCase):
    def test_smoke_succeeds_with_list(self):
        """When `bin/console list` returns 0, fallback to debug:router is skipped."""
        with _make_project_with_console() as td:
            project = Path(td)
            with patch("recon.sandbox.subprocess.run") as mock_run:
                mock_run.return_value = _completed(returncode=0)
                ok, warning = try_console_smoke(project)
            self.assertTrue(ok)
            self.assertIsNone(warning)
            # debug:router must NOT be called when list succeeds.
            self.assertEqual(mock_run.call_count, 1)
            # Sanity: the single call was for `list`, not debug:router.
            args0 = mock_run.call_args_list[0].args[0]
            self.assertIn("list", args0)
            self.assertNotIn("debug:router", args0)

    def test_smoke_falls_back_to_debug_router(self):
        """When `list` fails but `debug:router` succeeds, we return ok=True."""
        with _make_project_with_console() as td:
            project = Path(td)
            calls: list[list[str]] = []

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                # First call (list) fails; second call (debug:router) succeeds.
                if "list" in cmd and "debug:router" not in cmd:
                    return _completed(returncode=1, stderr="kernel boot exploded")
                if "debug:router" in cmd:
                    return _completed(returncode=0)
                raise AssertionError(f"unexpected cmd: {cmd}")

            with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
                ok, warning = try_console_smoke(project)
            self.assertTrue(ok)
            self.assertIsNone(warning)
            self.assertEqual(len(calls), 2)
            # First call was `list`.
            self.assertIn("list", calls[0])
            # Second call was `debug:router --format=json`.
            self.assertIn("debug:router", calls[1])
            self.assertIn("--format=json", calls[1])

    def test_smoke_double_failure(self):
        """Both probes failing → (False, warning) with both errors embedded."""
        with _make_project_with_console() as td:
            project = Path(td)

            def fake_run(cmd, **kwargs):
                if "debug:router" in cmd:
                    return _completed(returncode=1, stderr="unknown option --format")
                return _completed(returncode=1, stderr="autoload failure: missing class Foo")

            with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
                ok, warning = try_console_smoke(project)
            self.assertFalse(ok)
            self.assertIsNotNone(warning)
            assert warning is not None  # for type-checkers
            self.assertTrue(warning.startswith("console_smoke_failed:"))
            # Both errors are mentioned.
            self.assertIn("list+debug:router both failed", warning)
            self.assertIn("autoload failure", warning)
            self.assertIn("unknown option --format", warning)


    def test_smoke_does_not_retry_on_php_missing(self):
        """When `php` is not on PATH, the second probe must not be attempted.

        FileNotFoundError is environmental — retrying with another command
        will fail identically and only doubles wall time. Pinned regression
        for v3.1.4 review M1 (early-exit on infra failure).
        """
        with _make_project_with_console() as td:
            project = Path(td)
            calls: list[list[str]] = []

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                raise FileNotFoundError("no such file or directory: 'php'")

            with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
                ok, warning = try_console_smoke(project)
            self.assertFalse(ok)
            self.assertIsNotNone(warning)
            assert warning is not None
            # Exactly one call: list. debug:router was skipped.
            self.assertEqual(len(calls), 1)
            self.assertIn("list", calls[0])
            # Warning preserves the infra reason — no "list+debug:router both failed" framing.
            self.assertIn("php not on PATH", warning)
            self.assertNotIn("list+debug:router both failed", warning)

    def test_smoke_double_failure_truncates_long_stderr(self):
        """stderr lines longer than 200 chars must be truncated in the warning.

        Pinned regression for v3.1.4 review L4 (truncation coverage).
        """
        with _make_project_with_console() as td:
            project = Path(td)
            long_err = "x" * 500

            def fake_run(cmd, **kwargs):
                return _completed(returncode=1, stderr=long_err)

            with patch("recon.sandbox.subprocess.run", side_effect=fake_run):
                ok, warning = try_console_smoke(project)
            self.assertFalse(ok)
            self.assertIsNotNone(warning)
            assert warning is not None
            # 500 chars of "x" → truncated to 200 in each probe; total must be
            # well under 500 chars worth of x'es (200 + 200 = 400 max).
            x_count = warning.count("x")
            self.assertLessEqual(x_count, 400)
            # Sanity: at least one "x" survives (truncation didn't drop everything).
            self.assertGreater(x_count, 0)


if __name__ == "__main__":
    unittest.main()
