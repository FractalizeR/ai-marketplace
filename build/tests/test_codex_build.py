"""Codex build CLI: exit codes for check / write / gate-violation."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _common
from _common import PLUGIN_ROOT

import build as build_cli


def run_main(argv):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return build_cli.main(argv)


def capture_main(argv):
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        rc = build_cli.main(argv)
    return rc, err.getvalue()


class CodexExitCodeTests(unittest.TestCase):
    def test_codex_check_clean_exit_0(self):
        rc = run_main(["--harness=codex", "--mode=check", "--plugin-root", str(PLUGIN_ROOT)])
        self.assertEqual(rc, 0)

    def test_codex_write_exit_0_into_tmp(self):
        # 3B-pkg: write now materializes the bundle (was exit 2 in 3A-core).
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "codex"
            rc = run_main(["--harness=codex", "--mode=write", "--out", str(out),
                           "--plugin-root", str(PLUGIN_ROOT)])
            self.assertEqual(rc, 0)
            self.assertTrue((out / ".fr-codex-bundle").is_file())

    def test_codex_write_rejects_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "codex"
            rc = run_main(["--harness=codex", "--mode=write", "--out", str(out),
                           "--artifact", str(PLUGIN_ROOT / "agents" / "security.md")])
            self.assertEqual(rc, 2)
            self.assertFalse(out.exists())

    def test_codex_write_fail_closed_on_bad_config(self):
        # A broken authored plugin.json must fail write closed (no bundle emitted).
        with tempfile.TemporaryDirectory() as d:
            broken = Path(d) / "harness"
            broken.mkdir()
            for name in ("plugin.json", "marketplace.json", "adapter.json", "INSTALL.md"):
                (broken / name).write_text(
                    (build_cli._HARNESS_CODEX / name).read_text(encoding="utf-8"),
                    encoding="utf-8")
            (broken / "plugin.json").write_text('{"name": "fr-security-review"}',
                                                encoding="utf-8")
            out = Path(d) / "codex"
            with mock.patch.object(build_cli, "_HARNESS_CODEX", broken):
                rc = run_main(["--harness=codex", "--mode=write", "--out", str(out)])
            self.assertEqual(rc, 1)
            self.assertFalse(out.exists())

    def test_codex_check_flags_bad_config(self):
        # M1: config validation runs in check mode too (not only write).
        with tempfile.TemporaryDirectory() as d:
            broken = Path(d) / "harness"
            broken.mkdir()
            for name in ("plugin.json", "marketplace.json", "adapter.json", "INSTALL.md"):
                (broken / name).write_text(
                    (build_cli._HARNESS_CODEX / name).read_text(encoding="utf-8"),
                    encoding="utf-8")
            (broken / "plugin.json").write_text('{"name": "fr-security-review"}',
                                                encoding="utf-8")
            with mock.patch.object(build_cli, "_HARNESS_CODEX", broken):
                rc = run_main(["--harness=codex", "--mode=check"])
            self.assertEqual(rc, 1)

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


class CodexOutPathTests(unittest.TestCase):
    def test_command_goes_to_skill_dir(self):
        plugin_out = Path("/p")
        cmd = PLUGIN_ROOT / "commands" / "security-project.md"
        self.assertEqual(build_cli.codex_out_path(cmd, plugin_out),
                         plugin_out / "skills" / "security-project" / "SKILL.md")

    def test_agent_goes_under_core_agents(self):
        plugin_out = Path("/p")
        agent = PLUGIN_ROOT / "agents" / "security.md"
        self.assertEqual(build_cli.codex_out_path(agent, plugin_out),
                         plugin_out / "core" / "agents" / "security.md")


class ClaudeOutNoteTests(unittest.TestCase):
    def test_note_only_when_out_explicit(self):
        # L3-DS: the "--out ignored" note must NOT print on a plain claude run.
        _, err = capture_main(["--harness=claude", "--mode=check"])
        self.assertNotIn("--out is ignored", err)

    def test_note_prints_when_out_given_to_claude(self):
        with tempfile.TemporaryDirectory() as d:
            _, err = capture_main(["--harness=claude", "--mode=check", "--out", d])
            self.assertIn("--out is ignored", err)


if __name__ == "__main__":
    unittest.main()
