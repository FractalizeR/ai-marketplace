"""Tests for compute_fingerprint.py — fr-security-review."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Allow running from bin/tests/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import compute_fingerprint as cf  # noqa: E402


def _init_git_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)


def _commit_all(root: Path, msg: str = "c") -> None:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", msg], cwd=root, check=True)


class ProjectFingerprintTests(unittest.TestCase):
    def test_same_content_same_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "composer.json").write_text('{"name":"foo"}')
            h1 = cf.compute_project_fingerprint(root)
            h2 = cf.compute_project_fingerprint(root)
            self.assertEqual(h1, h2)

    def test_changing_composer_json_changes_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "composer.json").write_text('{"name":"foo"}')
            h1 = cf.compute_project_fingerprint(root)
            (root / "composer.json").write_text('{"name":"bar"}')
            h2 = cf.compute_project_fingerprint(root)
            self.assertNotEqual(h1, h2)

    def test_changing_composer_lock_changes_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "composer.json").write_text("{}")
            (root / "composer.lock").write_text('{"packages":[]}')
            h1 = cf.compute_project_fingerprint(root)
            (root / "composer.lock").write_text('{"packages":[{"name":"new"}]}')
            h2 = cf.compute_project_fingerprint(root)
            self.assertNotEqual(h1, h2)

    def test_missing_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # No files at all — should still produce deterministic hash.
            h = cf.compute_project_fingerprint(root)
            self.assertEqual(len(h), 64)
            # Same empty dir → same hash.
            self.assertEqual(h, cf.compute_project_fingerprint(root))

    def test_globs_yaml_captured(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "config" / "packages").mkdir(parents=True)
            (root / "config" / "packages" / "security.yaml").write_text("foo: 1")
            h1 = cf.compute_project_fingerprint(root)
            (root / "config" / "packages" / "security.yaml").write_text("foo: 2")
            h2 = cf.compute_project_fingerprint(root)
            self.assertNotEqual(h1, h2)

    def test_globs_multiple_yamls_order_independent(self):
        """Changing one of several yaml files must affect hash, ordering deterministic."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "config" / "packages").mkdir(parents=True)
            (root / "config" / "packages" / "a.yaml").write_text("a: 1")
            (root / "config" / "packages" / "b.yaml").write_text("b: 1")
            h1 = cf.compute_project_fingerprint(root)
            # Re-run without changes — identical.
            h2 = cf.compute_project_fingerprint(root)
            self.assertEqual(h1, h2)
            (root / "config" / "packages" / "a.yaml").write_text("a: 2")
            h3 = cf.compute_project_fingerprint(root)
            self.assertNotEqual(h1, h3)

    def test_frontend_files_captured(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "importmap.php").write_text("<?php return [];")
            h1 = cf.compute_project_fingerprint(root)
            (root / "importmap.php").write_text("<?php return ['foo'];")
            h2 = cf.compute_project_fingerprint(root)
            self.assertNotEqual(h1, h2)


class CodeFingerprintTests(unittest.TestCase):
    def test_no_git_no_scope_is_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            h = cf.compute_code_fingerprint(root)
            self.assertEqual(len(h), 64)
            self.assertEqual(h, cf.compute_code_fingerprint(root))

    def test_tracked_content_change_changes_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _init_git_repo(root)
            (root / "src").mkdir()
            (root / "src" / "Foo.php").write_text("<?php class Foo {}")
            _commit_all(root, "init")
            h1 = cf.compute_code_fingerprint(root)
            h2 = cf.compute_code_fingerprint(root)
            self.assertEqual(h1, h2, "clean repo re-run must match")

            # Modify and commit.
            (root / "src" / "Foo.php").write_text("<?php class Foo { public $x; }")
            _commit_all(root, "change")
            h3 = cf.compute_code_fingerprint(root)
            self.assertNotEqual(h1, h3)

    def test_dirty_uncommitted_changes_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _init_git_repo(root)
            (root / "src").mkdir()
            (root / "src" / "Foo.php").write_text("<?php class Foo {}")
            _commit_all(root, "init")
            h_clean = cf.compute_code_fingerprint(root)
            # Modify without commit.
            (root / "src" / "Foo.php").write_text("<?php class Foo { public $y; }")
            h_dirty = cf.compute_code_fingerprint(root)
            self.assertNotEqual(h_clean, h_dirty)

    def test_untracked_file_changes_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _init_git_repo(root)
            (root / "src").mkdir()
            (root / "src" / "Foo.php").write_text("<?php")
            _commit_all(root, "init")
            h_before = cf.compute_code_fingerprint(root)
            (root / "src" / "Bar.php").write_text("<?php class Bar {}")
            h_after = cf.compute_code_fingerprint(root)
            self.assertNotEqual(h_before, h_after)

    def test_idempotent_reruns(self):
        """Same state → same hash no matter how many times."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _init_git_repo(root)
            (root / "src").mkdir()
            (root / "src" / "X.php").write_text("<?php")
            _commit_all(root, "init")
            hashes = {cf.compute_code_fingerprint(root) for _ in range(5)}
            self.assertEqual(len(hashes), 1)


class CliTests(unittest.TestCase):
    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "composer.json").write_text("{}")
            result = subprocess.run(
                [sys.executable, str(Path(cf.__file__)), str(root), "--json"],
                capture_output=True,
                text=True,
                check=True,
            )
            import json as _json
            payload = _json.loads(result.stdout)
            self.assertIn("project_fingerprint", payload)
            self.assertIn("code_fingerprint", payload)
            self.assertEqual(len(payload["project_fingerprint"]), 64)
            self.assertEqual(len(payload["code_fingerprint"]), 64)


if __name__ == "__main__":
    unittest.main()
