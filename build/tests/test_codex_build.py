"""Codex build CLI: exit codes for check / write / gate-violation."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _common
from _common import PLUGIN_ROOT

import build as build_cli
from derive import REQUIRED_TEMPLATES


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


class HarnessFlagTests(unittest.TestCase):
    def test_claude_harness_no_longer_accepted(self):
        with self.assertRaises(SystemExit) as cm:
            run_main(["--harness=claude", "--mode=check"])
        self.assertEqual(cm.exception.code, 2)

    def test_harness_flag_defaults_to_codex(self):
        self.assertEqual(run_main(["--mode=check"]), 0)


class RefreshHashesCliTests(unittest.TestCase):
    def _copy_templates(self, d):
        root = Path(d) / "sections"
        shutil.copytree(build_cli._TEMPLATES, root)
        return root

    def test_stale_template_fails_check_then_refresh_fixes_it(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._copy_templates(d)
            tpl = root / "security-project" / "6-optional-interactive-checkpoint.md"
            body = tpl.read_text(encoding="utf-8").split("\n", 1)[1]
            tpl.write_text("<!-- source-sha256: " + "0" * 64 + " -->\n" + body,
                           encoding="utf-8")
            with mock.patch.object(build_cli, "_TEMPLATES", root):
                rc, err = capture_main(["--mode=check"])
                self.assertEqual(rc, 1)
                self.assertIn("6-optional-interactive-checkpoint.md is stale", err)
                self.assertEqual(run_main(["--mode=refresh-hashes"]), 0)
                self.assertEqual(run_main(["--mode=check"]), 0)
            self.assertTrue(tpl.read_text(encoding="utf-8").endswith(body))

    def test_refresh_is_noop_when_current(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._copy_templates(d)
            before = {p: p.read_bytes() for p in root.rglob("*.md")}
            with mock.patch.object(build_cli, "_TEMPLATES", root):
                self.assertEqual(run_main(["--mode=refresh-hashes"]), 0)
            self.assertEqual(before, {p: p.read_bytes() for p in root.rglob("*.md")})

    def test_refresh_rejects_foreign_plugin_root(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run_main(["--mode=refresh-hashes", "--plugin-root", d]), 2)

    def test_orphan_template_fails_check_and_refresh(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._copy_templates(d)
            (root / "security-project" / "99-renamed-heading.md").write_text(
                "x\n", encoding="utf-8")
            with mock.patch.object(build_cli, "_TEMPLATES", root):
                rc, err = capture_main(["--mode=check"])
                self.assertEqual(rc, 1)
                self.assertIn("matches no section", err)
                self.assertEqual(run_main(["--mode=refresh-hashes"]), 1)


class RequiredTemplateTests(unittest.TestCase):
    """A section without a Task directive or a labeled AskUserQuestion block
    leaks nothing when its template is gone, so the manifest is the only net."""

    def _check_without(self, mutate):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "sections"
            shutil.copytree(build_cli._TEMPLATES, root)
            mutate(root)
            with mock.patch.object(build_cli, "_TEMPLATES", root):
                return capture_main(["--mode=check"])

    def test_manifest_matches_the_authored_templates(self):
        authored = {p.stem for p in (build_cli._TEMPLATES / "security-project").glob("*.md")}
        self.assertEqual(set(REQUIRED_TEMPLATES["security-project"]), authored)

    def test_every_required_template_is_enforced(self):
        for anchor in sorted(REQUIRED_TEMPLATES["security-project"]):
            with self.subTest(anchor=anchor):
                rc, err = self._check_without(
                    lambda root: (root / "security-project" / f"{anchor}.md").unlink())
                self.assertEqual(rc, 1)
                self.assertIn(f"required template security-project/{anchor}.md is missing", err)

    def test_template_dir_for_unknown_artifact_fails(self):
        def add_orphan_dir(root):
            (root / "security-changes").mkdir()
            (root / "security-changes" / "x.md").write_text("x\n", encoding="utf-8")
        rc, err = self._check_without(add_orphan_dir)
        self.assertEqual(rc, 1)
        self.assertIn("security-changes", err)
        self.assertIn("matches no artifact", err)


if __name__ == "__main__":
    unittest.main()
