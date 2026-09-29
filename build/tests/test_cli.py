"""CLI exit codes and the discovery set."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

import _common
from _common import ARTIFACTS, PLUGIN_ROOT

import build as build_cli


def run_main(argv):
    """Invoke the CLI with stdout/stderr captured (tests assert exit codes,
    not the diagnostic stream)."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return build_cli.main(argv)


class DiscoveryTests(unittest.TestCase):
    def test_discovery_set_is_the_authoritative_artifacts(self):
        found = build_cli.discover_artifacts(PLUGIN_ROOT)
        self.assertEqual({p.name for p in found},
                         {p.name for p in ARTIFACTS})

    def test_empty_plugin_root_raises(self):
        tmp = Path(tempfile.mkdtemp(prefix="frempty_"))
        try:
            (tmp / "commands").mkdir()
            (tmp / "agents").mkdir()
            with self.assertRaises(FileNotFoundError):
                build_cli.discover_artifacts(tmp)
        finally:
            shutil.rmtree(tmp)


class ExitCodeTests(unittest.TestCase):
    def test_codex_check_exit_0(self):
        rc = run_main(["--harness=codex", "--mode=check",
                             "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 0)

    def test_codex_write_exit_0(self):
        tmp = Path(tempfile.mkdtemp(prefix="frcodex_"))
        try:
            rc = run_main(["--harness=codex", "--mode=write", "--out", str(tmp / "codex"),
                           "--plugin-root", str(PLUGIN_ROOT)])
            self.assertEqual(rc, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_bad_plugin_root_exit_2(self):
        tmp = Path(tempfile.mkdtemp(prefix="frempty_"))
        try:
            (tmp / "commands").mkdir()
            (tmp / "agents").mkdir()
            rc = run_main(["--harness=codex", "--mode=check",
                                 "--plugin-root", str(tmp)])
            self.assertEqual(rc, 2)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
