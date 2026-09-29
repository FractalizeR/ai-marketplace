"""scripts/frsr: help without side effects, removed modes, model-tier validation.

The launcher is exercised as a substituted copy in a tmp dir pointing at a FAKE
bundle — never the repo's gitignored dist/ and never a real `codex`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "frsr"


class FrsrTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="frsr_test_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = self.tmp / "repo"
        core = self.repo / "dist/codex/plugins/fr-security-review/core"
        (core / "bin/shared").mkdir(parents=True)
        (core / "bin/shared/model_resolver.py").write_text("# stub\n")
        self.launcher = self.tmp / "frsr"
        self.launcher.write_text(SCRIPT.read_text().replace("@@REPO@@", str(self.repo)))
        self.launcher.chmod(0o755)
        self.project = self.tmp / "project"
        self.project.mkdir()

    def run_frsr(self, *args):
        proc = subprocess.run(
            ["bash", str(self.launcher), *args], cwd=self.project,
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
            env={**os.environ, "PATH": "/usr/bin:/bin"},
        )
        return proc.returncode, proc.stdout, proc.stderr

    def assert_project_empty(self):
        self.assertEqual(list(self.project.iterdir()), [])

    def test_help_first_position(self):
        rc, out, _ = self.run_frsr("--help")
        self.assertEqual(rc, 0)
        self.assertIn("Usage:", out)
        self.assertIn("--models high=<id>,fast=<id>", out)
        self.assert_project_empty()

    def test_help_after_subcommand_and_harness(self):
        rc, out, _ = self.run_frsr("project", "--harness", "codex", "--help")
        self.assertEqual(rc, 0)
        self.assertIn("Usage:", out)
        self.assertNotIn("Prepared Codex command", out)
        self.assert_project_empty()

    def test_help_short_flag_mid_arguments(self):
        rc, out, _ = self.run_frsr("--models", "high=a,fast=b", "-h", "--go")
        self.assertEqual(rc, 0)
        self.assertIn("Usage:", out)
        self.assert_project_empty()

    def test_help_does_not_need_a_bundle(self):
        shutil.rmtree(self.repo)
        rc, out, _ = self.run_frsr("--help")
        self.assertEqual(rc, 0)
        self.assertIn("Usage:", out)

    def test_help_text_lists_every_documented_flag(self):
        _, out, _ = self.run_frsr("--help")
        for flag in ("--harness", "--review-root", "--project-root", "--models",
                     "--console-cmd", "--go", "--dry-run", "--help"):
            self.assertIn(flag, out)

    def test_help_after_double_dash_is_forwarded_not_help(self):
        rc, out, _ = self.run_frsr("--models", "high=a,fast=b", "--", "--help")
        self.assertEqual(rc, 0)
        self.assertNotIn("Usage:", out)
        self.assertIn("--help", out)

    def test_changes_mode_removed(self):
        rc, _, err = self.run_frsr("changes")
        self.assertEqual(rc, 2)
        self.assertIn("'changes' mode was removed in 5.0", err)
        self.assert_project_empty()

    def test_opencode_harness_removed(self):
        rc, _, err = self.run_frsr("project", "--harness", "opencode", "--models", "high=a,fast=b")
        self.assertEqual(rc, 2)
        self.assertIn("OpenCode harness was removed in 5.0", err)
        self.assert_project_empty()

    def test_unknown_harness(self):
        rc, _, err = self.run_frsr("--harness", "nope", "--models", "high=a,fast=b")
        self.assertEqual(rc, 2)
        self.assertIn("unknown harness 'nope'", err)

    def test_missing_models_and_no_saved_map(self):
        rc, _, err = self.run_frsr("project")
        self.assertEqual(rc, 2)
        self.assertIn("--models high=<id>,fast=<id>", err)
        self.assertIn("codex debug models", err)
        self.assert_project_empty()

    def test_partial_models_rejected(self):
        for spec, missing in (("high=a", "fast"), ("fast=b", "high"), ("high=,fast=b", "high")):
            rc, _, err = self.run_frsr("project", "--models", spec)
            self.assertEqual(rc, 2, spec)
            self.assertIn(f"missing {missing}", err)
        self.assert_project_empty()

    def test_unknown_option_is_an_error(self):
        rc, _, err = self.run_frsr("project", "--quick", "--models", "high=a,fast=b")
        self.assertEqual(rc, 2)
        self.assertIn("unknown option '--quick'", err)
        self.assertIn("after '--'", err)

    def test_missing_bundle(self):
        shutil.rmtree(self.repo)
        rc, _, err = self.run_frsr("project", "--models", "high=a,fast=b")
        self.assertEqual(rc, 2)
        self.assertIn("bundle not built", err)
        self.assert_project_empty()

    def test_preview_prints_command_and_writes_nothing(self):
        rc, out, _ = self.run_frsr("--models", "high=big,fast=small", "--", "--quick")
        self.assertEqual(rc, 0)
        self.assertIn("Prepared Codex command", out)
        self.assertIn("-m big", out)
        self.assertIn("skills/security-project/SKILL.md", out)
        self.assertIn("--quick", out)
        self.assert_project_empty()

    def test_saved_map_is_used_for_orchestrator_model(self):
        review = self.project / "security-review-codex"
        review.mkdir()
        (review / ".model_map.json").write_text('{"high": "saved-big", "fast": "saved-small"}')
        rc, out, _ = self.run_frsr("project")
        self.assertEqual(rc, 0)
        self.assertIn("orchestrator model=saved-big", out)

    def test_incomplete_saved_map_counts_as_missing(self):
        review = self.project / "security-review-codex"
        review.mkdir()
        (review / ".model_map.json").write_text('{"high": "only-high"}')
        rc, _, err = self.run_frsr("project")
        self.assertEqual(rc, 2)
        self.assertIn("model tiers are not set", err)

    def test_saved_map_with_guessed_provenance_counts_as_missing(self):
        review = self.project / "security-review-codex"
        review.mkdir()
        (review / ".model_map.json").write_text(
            '{"high": "x", "fast": "x", "provenance": "collapsed"}')
        rc, _, err = self.run_frsr("project")
        self.assertEqual(rc, 2)
        self.assertIn("model tiers are not set", err)

    def test_go_saves_map_with_real_resolver_then_execs_codex(self):
        engine = SCRIPT.parent.parent / "security-review/bin/shared"
        shared = self.repo / "dist/codex/plugins/fr-security-review/core/bin/shared"
        for name in ("model_resolver.py", "contracts.py"):
            shutil.copy(engine / name, shared / name)
        fakebin = self.tmp / "fakebin"
        fakebin.mkdir()
        record = self.tmp / "codex_argv"
        codex = fakebin / "codex"
        codex.write_text(f'#!/bin/sh\nprintf \'%s\\n\' "$@" > {record}\n')
        codex.chmod(0o755)
        proc = subprocess.run(
            ["bash", str(self.launcher), "--go", "--models", "high=big,fast=small"],
            cwd=self.project, capture_output=True, text=True, stdin=subprocess.DEVNULL,
            env={**os.environ, "PATH": f"{fakebin}:/usr/bin:/bin"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        saved = (self.project / "security-review-codex/.model_map.json").read_text()
        self.assertIn('"high": "big"', saved)
        self.assertNotIn("provenance", saved)
        argv = record.read_text().splitlines()
        self.assertEqual(argv[:3], ["exec", "-m", "big"])

    def test_review_root_source_dir_refused_before_any_write(self):
        (self.project / "src").mkdir()
        rc, _, err = self.run_frsr("--go", "--models", "high=a,fast=b", "--review-root", "src")
        self.assertEqual(rc, 2)
        self.assertIn("refused", err)
        self.assertEqual(list((self.project / "src").iterdir()), [])

    def test_review_root_equal_to_project_root_refused(self):
        rc, _, err = self.run_frsr("--models", "high=a,fast=b", "--review-root", str(self.project))
        self.assertEqual(rc, 2)
        self.assertIn("project root", err)
        self.assert_project_empty()

    def test_review_root_inside_project_without_prefix_refused(self):
        rc, _, err = self.run_frsr("--models", "high=a,fast=b", "--review-root", "audit-out")
        self.assertEqual(rc, 2)
        self.assertIn("does not start with", err)

    def test_review_root_that_is_a_file_refused(self):
        (self.project / "security-review-x").write_text("x")
        rc, _, err = self.run_frsr("--models", "high=a,fast=b", "--review-root", "security-review-x")
        self.assertEqual(rc, 2)
        self.assertIn("not a directory", err)

    def test_review_root_outside_project_with_prefix_allowed(self):
        out = self.tmp / "elsewhere" / "security-review-ok"
        rc, _, err = self.run_frsr("--models", "high=a,fast=b", "--review-root", str(out))
        self.assertEqual(rc, 0, err)


if __name__ == "__main__":
    unittest.main()
