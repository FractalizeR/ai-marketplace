"""scripts/leakcheck.sh: missing-local-file no-op, empty-pattern regression,
denylist (dist/, the local pattern file itself), --staged scoping, and
case-insensitive detection.

Runs the real script as a subprocess against throwaway temp git repos — never
the real repo's working tree, and never depends on a developer's real
.leakcheck.local (which is gitignored and may or may not exist).
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import _common

SCRIPT = _common.REPO_ROOT / "scripts" / "leakcheck.sh"


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _make_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="frleak_"))
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Leakcheck Test")
    return repo


def _write(repo: Path, rel: str, content: str) -> Path:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _run(repo: Path, *args):
    return subprocess.run([str(SCRIPT), *args], cwd=repo,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True)


class LeakcheckTests(unittest.TestCase):
    def setUp(self):
        self.repo = _make_repo()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)

    def test_missing_local_file_exits_0(self):
        _write(self.repo, "README.md", "hello world\n")
        _git(self.repo, "add", "README.md")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 0)

    def test_empty_local_file_exits_0(self):
        _write(self.repo, ".leakcheck.local", "")
        _write(self.repo, "README.md", "hello world\n")
        _git(self.repo, "add", "README.md")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 0)

    def test_comments_only_local_file_exits_0(self):
        # Regression: a pattern file with nothing but comments/blanks must not
        # fall through to `grep -f` with an effectively empty pattern set,
        # which matches every line of every file.
        _write(self.repo, ".leakcheck.local", "# just a comment\n\n   \n")
        _write(self.repo, "README.md", "hello world\n")
        _git(self.repo, "add", "README.md")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 0)

    def test_planted_leak_is_detected_with_file_and_line(self):
        _write(self.repo, ".leakcheck.local", "acme-internal-widget-svc\n")
        _write(self.repo, "notes/deploy.md",
               "line one is clean\nsecond line mentions acme-internal-widget-svc here\n")
        _git(self.repo, "add", "notes/deploy.md")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 1)
        self.assertIn("notes/deploy.md:2:", result.stdout)
        self.assertIn("acme-internal-widget-svc", result.stdout)

    def test_leak_removed_exits_0_again(self):
        _write(self.repo, ".leakcheck.local", "acme-internal-widget-svc\n")
        target = _write(self.repo, "notes/deploy.md",
                         "mentions acme-internal-widget-svc\n")
        _git(self.repo, "add", "notes/deploy.md")
        self.assertEqual(_run(self.repo, "--all").returncode, 1)

        target.write_text("clean now\n", encoding="utf-8")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 0)

    def test_dist_is_excluded_even_when_tracked(self):
        _write(self.repo, ".leakcheck.local", "acme-internal-widget-svc\n")
        _write(self.repo, "dist/bundle.md", "acme-internal-widget-svc\n")
        _git(self.repo, "add", "dist/bundle.md")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 0)

    def test_leakcheck_local_itself_is_excluded_even_when_tracked(self):
        # .leakcheck.local trivially contains its own patterns; if it were
        # forcibly tracked it must still not flag itself.
        _write(self.repo, ".leakcheck.local", "acme-internal-widget-svc\n")
        _git(self.repo, "add", "-f", ".leakcheck.local")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 0)

    def test_case_insensitive_match(self):
        _write(self.repo, ".leakcheck.local", "acme-internal-widget-svc\n")
        _write(self.repo, "notes/deploy.md", "ACME-INTERNAL-WIDGET-SVC\n")
        _git(self.repo, "add", "notes/deploy.md")

        result = _run(self.repo, "--all")

        self.assertEqual(result.returncode, 1)
        self.assertIn("notes/deploy.md:1:", result.stdout)

    def test_staged_scopes_to_index_changes_only(self):
        _write(self.repo, ".leakcheck.local", "acme-internal-widget-svc\n")
        # Committed, unmodified tracked file that already contains the leak —
        # not part of this commit's staged changes.
        already_tracked = _write(self.repo, "old.md",
                                  "acme-internal-widget-svc\n")
        _git(self.repo, "add", "old.md")
        _git(self.repo, "commit", "-q", "-m", "seed")

        # --all sees the whole tracked tree, including the old file.
        self.assertEqual(_run(self.repo, "--all").returncode, 1)

        # New file staged for commit, clean of any leak.
        _write(self.repo, "new.md", "nothing to see here\n")
        _git(self.repo, "add", "new.md")

        result = _run(self.repo, "--staged")

        self.assertEqual(result.returncode, 0)
        self.assertNotIn(str(already_tracked.name), result.stdout)

    def test_staged_detects_leak_in_newly_staged_file(self):
        _write(self.repo, ".leakcheck.local", "acme-internal-widget-svc\n")
        _write(self.repo, "clean.md", "nothing here\n")
        _git(self.repo, "add", "clean.md")
        _git(self.repo, "commit", "-q", "-m", "seed")

        _write(self.repo, "new.md", "leaks acme-internal-widget-svc here\n")
        _git(self.repo, "add", "new.md")

        result = _run(self.repo, "--staged")

        self.assertEqual(result.returncode, 1)
        self.assertIn("new.md:1:", result.stdout)


if __name__ == "__main__":
    unittest.main()
