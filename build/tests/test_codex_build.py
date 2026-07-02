"""Codex build CLI: exit codes for check / write / gate-violation."""

import contextlib
import io
import unittest
from unittest import mock

import _common
from _common import PLUGIN_ROOT

import build as build_cli


def run_main(argv):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return build_cli.main(argv)


class CodexExitCodeTests(unittest.TestCase):
    def test_codex_check_clean_exit_0(self):
        rc = run_main(["--harness=codex", "--mode=check", "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 0)

    def test_codex_write_not_implemented_exit_2(self):
        # Bundling + manifest + atomic write are Phase 3B-pkg.
        rc = run_main(["--harness=codex", "--mode=write", "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 2)

    def test_codex_gate_violation_exit_1(self):
        with mock.patch.object(build_cli, "check_codex_output",
                               return_value=["forced violation"]):
            rc = run_main(["--harness=codex", "--mode=check",
                           "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 1)

    def test_codex_check_is_deterministic_across_two_cli_runs(self):
        self.assertEqual(
            run_main(["--harness=codex", "--mode=check", "--plugin-root", str(PLUGIN_ROOT)]),
            run_main(["--harness=codex", "--mode=check", "--plugin-root", str(PLUGIN_ROOT)]),
        )


if __name__ == "__main__":
    unittest.main()
