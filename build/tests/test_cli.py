"""CLI exit codes, --write idempotency, discovery set, stubs."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _common
from _common import ARTIFACTS, PLUGIN_ROOT

import adapters
import build as build_cli


def run_main(argv):
    """Invoke the CLI with stdout/stderr captured (tests assert exit codes,
    not the diagnostic stream)."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return build_cli.main(argv)


def _make_temp_plugin() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="frbuild_"))
    for sub in ("commands", "agents"):
        (tmp / sub).mkdir()
    for path in ARTIFACTS:
        shutil.copy2(path, tmp / path.parent.name / path.name)
    return tmp


class DiscoveryTests(unittest.TestCase):
    def test_discovery_set_is_the_five_artifacts(self):
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
    def test_claude_check_clean_exit_0(self):
        rc = run_main(["--harness=claude", "--mode=check",
                             "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 0)

    def test_codex_check_exit_0(self):
        # Phase 3A: CodexAdapter is no longer a stub — check-mode passes the
        # structural gates (superseded the old `codex → exit 2` stub assertion).
        rc = run_main(["--harness=codex", "--mode=check",
                             "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 0)

    def test_codex_write_exit_0(self):
        # Phase 3B-pkg: codex --mode=write materializes the bundle (was exit 2 in 3A).
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
            rc = run_main(["--harness=claude", "--mode=check",
                                 "--plugin-root", str(tmp)])
            self.assertEqual(rc, 2)
        finally:
            shutil.rmtree(tmp)

    def test_drift_detected_exit_1(self):
        # Force the CORE_ROOT canonical renderer to diverge → rebuild != on-disk.
        artifact = PLUGIN_ROOT / "commands" / "security-project.md"
        with mock.patch.object(adapters, "CLAUDE_CORE_ROOT", "@@DRIFT@@"):
            rc = run_main(["--harness=claude", "--mode=check",
                                 "--artifact", str(artifact),
                                 "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 1)


class WriteIdempotencyTests(unittest.TestCase):
    def test_write_is_noop_on_identical_artifacts(self):
        tmp = _make_temp_plugin()
        try:
            before = {p: p.read_bytes()
                      for p in tmp.rglob("*.md")}
            rc1 = run_main(["--harness=claude", "--mode=write",
                                  "--plugin-root", str(tmp)])
            rc2 = run_main(["--harness=claude", "--mode=write",
                                  "--plugin-root", str(tmp)])
            self.assertEqual((rc1, rc2), (0, 0))
            after = {p: p.read_bytes() for p in tmp.rglob("*.md")}
            self.assertEqual(before, after)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
