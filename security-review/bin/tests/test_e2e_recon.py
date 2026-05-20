"""S7 DoD #3, #4 — E2E recon smoke tests on 2 fixtures.

Covers the recon stage (utility-only, no LLM enrichment) end-to-end:

- `symfony_minimal` with `--no-console`: full recipe pipeline writes a valid
  schema-v2 CONTEXT.md, recon_confidence ceiling=medium (S-1 silent floor),
  validator passes. With console enrichment the ceiling could rise to high,
  but in CI we exercise the static-only path.
- `generic_php`: detect picks `generic_php`, recipe runs best-effort, ceiling
  stays medium regardless of console availability.

These tests deliberately drive the public CLI (recon_inventory.py) so they
exercise the same surface that `/fr-security-review:security-project` runs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"
VALIDATE = BIN_DIR / "validate_context.py"

FIX_SYMFONY_MINIMAL = THIS_DIR / "fixtures" / "symfony_minimal"
FIX_LARAVEL_MINIMAL = THIS_DIR / "fixtures" / "laravel_minimal"
FIX_GENERIC_PHP = THIS_DIR / "fixtures" / "generic_php"

sys.path.insert(0, str(BIN_DIR))
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402


def _run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _read_frontmatter(review_root: Path) -> dict:
    text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    assert m, f"no frontmatter in {review_root}/CONTEXT.md"
    return parse_yaml_subset(m.group(1))


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class SymfonyMinimalRecon(unittest.TestCase):
    """`symfony_minimal --no-console` smoke run via the CLI."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = Path(cls.tmp.name) / "review"
        proc = _run(
            str(RECON), str(FIX_SYMFONY_MINIMAL),
            "--recipe", "symfony",
            "--review-root", str(cls.review_root),
            "--no-console",
        )
        cls.proc = proc

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    def test_recon_succeeds(self):
        self.assertEqual(self.proc.returncode, 0, msg=self.proc.stderr)

    def test_context_file_written(self):
        ctx = self.review_root / "CONTEXT.md"
        self.assertTrue(ctx.is_file())
        # Recon must also drop a `.gitignore` ("*") so the review-root never
        # leaks into the project's git index.
        self.assertEqual(
            (self.review_root / ".gitignore").read_text(encoding="utf-8"),
            "*\n",
        )

    def test_frontmatter_recipe_and_stack(self):
        fm = _read_frontmatter(self.review_root)
        self.assertEqual(fm["recipe_used"], "symfony")
        self.assertEqual(fm["stack"]["framework"], "symfony")
        self.assertEqual(fm["schema_version"], 2)

    def test_no_console_caps_ceiling_at_medium(self):
        fm = _read_frontmatter(self.review_root)
        self.assertEqual(fm["recon_confidence"]["ceiling"], "medium")
        self.assertIn("console_disabled_by_flag", fm["warnings"])

    def test_validator_accepts_emitted_context(self):
        proc = _run(
            str(RECON),
            "--review-root", str(self.review_root),
            "--validate",
        )
        # Validator may emit warnings for pending_enrichment markers, but the
        # exit code must be 0 (errors == []).
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class GenericPhpRecon(unittest.TestCase):
    """`generic_php` recipe runs best-effort and never claims `high`."""

    def test_detect_picks_generic_php(self):
        proc = _run(str(RECON), str(FIX_GENERIC_PHP), "--detect")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["recipe"], "generic_php")
        self.assertEqual(out["stack"]["name"], "generic_php")

    def test_inventory_runs_and_caps_at_medium(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run(
                str(RECON), str(FIX_GENERIC_PHP),
                "--recipe", "generic_php",
                "--review-root", str(review_root),
                "--no-console",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            fm = _read_frontmatter(review_root)
        self.assertEqual(fm["recipe_used"], "generic_php")
        # generic_php always declares framework=none (recipe stack block).
        self.assertEqual(fm["stack"]["framework"], "none")
        # rev 3.3 ceiling policy — no console means ceiling=medium and so
        # level cannot rise above medium even on a fully-resolved inventory.
        self.assertEqual(fm["recon_confidence"]["ceiling"], "medium")
        self.assertIn(fm["recon_confidence"]["level"], {"low", "medium"})

    def test_validator_accepts_generic_php_context(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            recipe_proc = _run(
                str(RECON), str(FIX_GENERIC_PHP),
                "--recipe", "generic_php",
                "--review-root", str(review_root),
                "--no-console",
            )
            self.assertEqual(recipe_proc.returncode, 0, msg=recipe_proc.stderr)
            validate_proc = _run(
                str(RECON),
                "--review-root", str(review_root),
                "--validate",
            )
        self.assertEqual(validate_proc.returncode, 0, msg=validate_proc.stderr)


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class LaravelMinimalRecon(unittest.TestCase):
    """`laravel_minimal --no-console` smoke run via the CLI."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = Path(cls.tmp.name) / "review"
        proc = _run(
            str(RECON), str(FIX_LARAVEL_MINIMAL),
            "--recipe", "laravel",
            "--review-root", str(cls.review_root),
            "--no-console",
        )
        cls.proc = proc

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    def test_recon_succeeds(self):
        self.assertEqual(self.proc.returncode, 0, msg=self.proc.stderr)

    def test_context_file_written_with_gitignore(self):
        ctx = self.review_root / "CONTEXT.md"
        self.assertTrue(ctx.is_file())
        self.assertEqual(
            (self.review_root / ".gitignore").read_text(encoding="utf-8"),
            "*\n",
        )

    def test_frontmatter_recipe_and_stack(self):
        fm = _read_frontmatter(self.review_root)
        self.assertEqual(fm["recipe_used"], "laravel")
        self.assertEqual(fm["stack"]["framework"], "laravel")
        self.assertEqual(fm["schema_version"], 2)

    def test_detect_picks_laravel(self):
        proc = _run(str(RECON), str(FIX_LARAVEL_MINIMAL), "--detect")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["recipe"], "laravel")
        self.assertEqual(out["stack"]["name"], "laravel")

    def test_validator_accepts_emitted_context(self):
        proc = _run(
            str(RECON),
            "--review-root", str(self.review_root),
            "--validate",
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)


if __name__ == "__main__":
    unittest.main()
