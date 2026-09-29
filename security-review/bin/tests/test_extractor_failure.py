"""Extractor failures stay loud, a timeout fails the rest of the run fast, and
a source root symlinked into a dot-directory is still parsed.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
PLUGIN_ROOT = BIN_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"
VALIDATE = BIN_DIR / "validate_context.py"
FIX_MIN = THIS_DIR / "fixtures" / "symfony_minimal"
FIX_ROUTES = THIS_DIR / "fixtures" / "symfony_routes_authz"

sys.path.insert(0, str(BIN_DIR))

from recon import sandbox  # noqa: E402
from recon.recipes import symfony as sf  # noqa: E402
from validate_context import FRONTMATTER_RE, _extractor_failures, parse_yaml_subset  # noqa: E402


def _run(args: list[str], env: dict | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env.update(env or {})
    return subprocess.run(
        [sys.executable, *args], capture_output=True, text=True, timeout=timeout, env=full_env,
    )


def _recon_and_sanity(project: Path, review_root: Path, env: dict) -> tuple[str, subprocess.CompletedProcess]:
    proc = _run([str(RECON), str(project), "--recipe", "symfony",
                 "--review-root", str(review_root), "--no-console"], env)
    assert proc.returncode == 0, proc.stderr
    text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")
    sanity = _run([str(VALIDATE), "--review-root", str(review_root), "--sanity",
                   "--project-root", str(project)], env)
    return text, sanity


def _level(text: str) -> str:
    return parse_yaml_subset(FRONTMATTER_RE.match(text).group(1))["recon_confidence"]["level"]


class ExtractorFailFastScope(unittest.TestCase):
    def _call(self):
        return sandbox.run_extractor(PLUGIN_ROOT, FIX_MIN, "routes", FIX_MIN, timeout=1)

    def test_timeout_skips_later_calls_without_spawning(self):
        with mock.patch.object(sandbox.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("php", 1)) as run:
            with sandbox.extractor_run_scope():
                first = self._call()
                second = self._call()
        self.assertIn("timed out after 1s", first[1])
        self.assertEqual(second, (None, sandbox.EXTRACTOR_SKIPPED_AFTER_TIMEOUT))
        self.assertEqual(run.call_count, 1)

    def test_non_timeout_failure_does_not_trip_the_latch(self):
        failed = subprocess.CompletedProcess(["php"], 1, stdout="", stderr="boom")
        with mock.patch.object(sandbox.subprocess, "run", return_value=failed) as run:
            with sandbox.extractor_run_scope():
                self._call()
                second = self._call()
        self.assertIn("exit=1", second[1])
        self.assertEqual(run.call_count, 2)

    def test_no_latch_outside_a_scope(self):
        with mock.patch.object(sandbox.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("php", 1)) as run:
            self._call()
            self._call()
        self.assertEqual(run.call_count, 2)


class ExtractorFailuresInValidator(unittest.TestCase):
    def test_any_section_any_recipe(self):
        text = (
            "## Attack Surface\n<!-- section_id: attack_surface -->\n\n```yaml\n"
            "status: partial\nreason: \"extractor_failed: routes: boom\"\nitems: []\n```\n\n"
            "## Recon Bags\n<!-- section_id: recon_bags -->\n\n```yaml\n"
            "stack:\n  laravel:\n    routes_authz_matrix:\n      status: partial\n"
            "      reason: \"extractor_failed: routes: boom\"\n      items: []\n"
            "    policies:\n      status: ok\n      items: []\n```\n"
        )
        self.assertEqual(_extractor_failures(text), [
            ("attack_surface", "extractor_failed: routes: boom"),
            ("recon_bags.stack.laravel.routes_authz_matrix", "extractor_failed: routes: boom"),
        ])


class _ShimPath(unittest.TestCase):
    """PATH holding only a scratch dir: no real `php`, optionally a fake one."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.project = self.tmp / "proj"
        shutil.copytree(FIX_MIN, self.project)

    def fake_php(self, body: str) -> None:
        php = self.bin / "php"
        php.write_text("#!/bin/sh\n" + body)
        php.chmod(php.stat().st_mode | stat.S_IEXEC)


class NoPhpOnPath(_ShimPath):
    def test_sanity_warns_with_the_extractor_cause(self):
        text, sanity = _recon_and_sanity(self.project, self.tmp / "review", {"PATH": str(self.bin)})
        self.assertEqual(sanity.returncode, 0, sanity.stdout + sanity.stderr)
        self.assertIn(
            "WARNING: sanity[extractor]: attack_surface not collected — "
            "extractor_failed: routes: php executable not found on PATH",
            sanity.stderr,
        )
        self.assertEqual(_level(text), "low")

    def test_gaps_file_carries_the_extractor_failed_sections_and_their_files(self):
        _, _ = _recon_and_sanity(self.project, self.tmp / "review", {"PATH": str(self.bin)})
        out = self.tmp / "recon_gaps.json"
        sanity = _run([str(VALIDATE), "--review-root", str(self.tmp / "review"), "--sanity",
                       "--project-root", str(self.project), "--gaps-out", str(out)],
                      {"PATH": str(self.bin)})
        self.assertEqual(sanity.returncode, 0, sanity.stderr)
        items = json.loads(out.read_text())["items"]
        failed = {i["section_path"]: i for i in items if i["kind"] == "extractor_failed"}
        self.assertIn("attack_surface", failed)
        self.assertIn("recon_bags.stack.symfony.forms", failed)  # probe-less: SOURCE_ROOTS glob
        self.assertTrue(failed["recon_bags.stack.symfony.forms"]["files"])
        self.assertTrue(all(i["files"] == sorted(i["files"]) for i in items))
        self.assertEqual(items, sorted(items, key=lambda i: (i["kind"], i["section_path"], i["label"])))


class TimeoutFailsFast(_ShimPath):
    def test_one_timeout_then_every_other_kind_skipped(self):
        # Answers the host `php --version` probe; hangs on any extractor call.
        self.fake_php('case "$1" in --version) echo "PHP 8.4.0 (cli)";; *) /bin/sleep 30;; esac\n')
        env = {"PATH": str(self.bin), "FR_SECURITY_EXTRACTOR_TIMEOUT": "1"}
        started = time.monotonic()
        text, sanity = _recon_and_sanity(self.project, self.tmp / "review", env)
        # ~11 extractor calls: without fail-fast that is >= 11 s of timeouts alone.
        self.assertLess(time.monotonic() - started, 8)
        self.assertGreaterEqual(text.count("skipped after earlier timeout"), 5)
        self.assertIn("extractor_failed: routes: extract_php_metadata --kind=routes timed out after 1s", text)
        self.assertIn("extractor_failed: class: skipped after earlier timeout", text)
        self.assertEqual(sanity.returncode, 0, sanity.stderr)
        self.assertIn("timed out after 1s", sanity.stderr)
        self.assertEqual(_level(text), "low")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class HealthyRunUnchanged(unittest.TestCase):
    def test_no_extractor_errors_and_level_medium(self):
        with tempfile.TemporaryDirectory() as td:
            text, sanity = _recon_and_sanity(FIX_MIN, Path(td) / "review", {})
        self.assertEqual(sanity.returncode, 0, sanity.stderr)
        self.assertNotIn("sanity[extractor]", sanity.stderr)
        self.assertEqual(_level(text), "medium")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class SourceRootSymlinkedIntoDotDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.project = Path(self._tmp.name) / "proj"
        shutil.copytree(FIX_ROUTES, self.project)
        (self.project / ".build").mkdir()
        (self.project / "src").rename(self.project / ".build" / "src")
        try:
            (self.project / "src").symlink_to(".build/src", target_is_directory=True)
        except (OSError, NotImplementedError) as e:
            self.skipTest(f"symlink unsupported: {e}")

    def test_extractor_follows_the_link(self):
        data, warn = sandbox.run_extractor(PLUGIN_ROOT, self.project, "routes", self.project)
        self.assertIsNone(warn)
        self.assertEqual(len(data["items"]), 4)

    def test_python_walk_keeps_the_files(self):
        files = [rel for rel, _ in sf._list_php_files(self.project)]
        self.assertEqual(len(files), 2)

    def test_sanity_passes(self):
        text, sanity = _recon_and_sanity(self.project, Path(self._tmp.name) / "review", {})
        self.assertEqual(sanity.returncode, 0, sanity.stderr)

    def test_link_cycle_and_escape_not_walked(self):
        (self.project / ".build" / "src" / "loop").symlink_to(".", target_is_directory=True)
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        (outside / "Evil.php").write_text(
            "<?php\nclass Evil { #[\\Symfony\\Component\\Routing\\Attribute\\Route('/evil', name: 'evil')] "
            "public function x() {} }\n"
        )
        (self.project / "src" / "escape").symlink_to(outside, target_is_directory=True)
        data, warn = sandbox.run_extractor(PLUGIN_ROOT, self.project, "routes", self.project, timeout=20)
        self.assertIsNone(warn)
        self.assertEqual(len(data["items"]), 4)
        # The escaping directory is never entered (not merely filtered per file).
        proc = subprocess.run(
            ["php", str(BIN_DIR / "recon" / "extract_php_metadata.php"), "--kind=routes",
             f"--project-root={self.project.resolve()}", str(self.project.resolve())],
            capture_output=True, text=True, timeout=20,
        )
        self.assertNotIn("outside project", proc.stderr)


if __name__ == "__main__":
    unittest.main()
