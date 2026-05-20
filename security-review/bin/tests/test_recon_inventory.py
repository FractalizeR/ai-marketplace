"""Integration tests for bin/recon_inventory.py.

Covers:
- --detect on Symfony / generic_php / bare-dir.
- --recipe + --review-root: CONTEXT.md content, .gitignore creation, idempotency.
- --no-console flag: warning + ceiling.
- Path safety (project_root containment).
- Subprocess sandbox wrapper for extract_php_metadata.php.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
PLUGIN_ROOT = BIN_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"

FIX_MIN = THIS_DIR / "fixtures" / "symfony_minimal"
FIX_GEN = THIS_DIR / "fixtures" / "generic_php"

sys.path.insert(0, str(BIN_DIR))
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402
from recon.types import assert_inside_project, PathOutsideProjectRoot  # noqa: E402


def _run_cli(*args: str, cwd: Path | None = None, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RECON), *args],
        capture_output=True, text=True, timeout=timeout, cwd=cwd,
    )


def _read_context(review_root: Path) -> tuple[dict, str]:
    """Return (frontmatter_dict, body_text)."""
    text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    assert m, f"no frontmatter in {review_root}/CONTEXT.md"
    fm = parse_yaml_subset(m.group(1))
    body = text[m.end():]
    return fm, body


class Detect(unittest.TestCase):
    def test_symfony_fixture_detected(self):
        proc = _run_cli(str(FIX_MIN), "--detect")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["recipe"], "symfony")
        self.assertGreaterEqual(out["stack"]["confidence"], 0.7)

    def test_generic_php_fixture_detected(self):
        proc = _run_cli(str(FIX_GEN), "--detect")
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out["recipe"], "generic_php")

    def test_bare_dir_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            proc = _run_cli(td, "--detect")
            self.assertEqual(proc.returncode, 1)
            out = json.loads(proc.stdout)
            self.assertEqual(out["stack"]["name"], "unknown")

    def test_nonexistent_path_exits_2(self):
        proc = _run_cli("/nonexistent/path/zzz", "--detect")
        self.assertEqual(proc.returncode, 2)


class Inventory(unittest.TestCase):
    def test_creates_context_and_gitignore(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertTrue((review_root / "CONTEXT.md").is_file())
            self.assertTrue((review_root / ".gitignore").is_file())
            self.assertEqual((review_root / ".gitignore").read_text(), "*\n")

    def test_idempotent_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            for _ in range(3):
                proc = _run_cli(
                    str(FIX_MIN), "--recipe", "symfony",
                    "--review-root", str(review_root), "--no-console",
                )
                self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            # No accumulating files.
            self.assertEqual(
                sorted(p.name for p in review_root.iterdir()),
                [".gitignore", "CONTEXT.md"],
            )

    def test_user_gitignore_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            review_root.mkdir()
            (review_root / ".gitignore").write_text("# user-edited\nfoo\n")
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            self.assertEqual(
                (review_root / ".gitignore").read_text(),
                "# user-edited\nfoo\n",
            )

    def test_no_console_warning_present(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            fm, _ = _read_context(review_root)
            self.assertIn("console_disabled_by_flag", fm["warnings"])

    def test_exclude_flag_records_user_paths_in_warnings(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
                "--exclude=legacy,src/ThirdParty",
            )
            fm, _ = _read_context(review_root)
            user_excludes = [
                w for w in fm["warnings"] if w.startswith("exclude_paths_user:")
            ]
            self.assertEqual(len(user_excludes), 1, msg=fm["warnings"])
            self.assertIn("legacy", user_excludes[0])
            self.assertIn("src/ThirdParty", user_excludes[0])

    def test_exclude_absent_no_user_warning(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            fm, _ = _read_context(review_root)
            user_excludes = [
                w for w in fm["warnings"] if w.startswith("exclude_paths_user:")
            ]
            self.assertEqual(user_excludes, [])

    def test_no_console_clamps_ceiling_to_medium(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            fm, _ = _read_context(review_root)
            self.assertEqual(fm["recon_confidence"]["ceiling"], "medium")
            self.assertIn(fm["recon_confidence"]["level"], ("medium", "low"))

    def test_frontmatter_has_required_keys(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            fm, _ = _read_context(review_root)
            for key in (
                "schema_version", "generated_at", "git_rev",
                "project_fingerprint", "code_fingerprint",
                "scope", "stack", "recipe_used", "tool_versions",
                "sources_used", "missing_sections", "recon_confidence",
            ):
                self.assertIn(key, fm, f"missing frontmatter key: {key}")
            self.assertEqual(fm["schema_version"], 2)
            self.assertEqual(fm["recipe_used"], "symfony")
            self.assertEqual(fm["stack"]["framework"], "symfony")

    def test_section_anchors_present(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            text = (review_root / "CONTEXT.md").read_text()
            for sid in (
                "attack_surface", "data_access", "auth_layer", "authz_usage",
                "output_renderers", "serialization", "file_operations",
                "http_clients", "secrets", "fintech_markers", "frontend_assets",
                "framework_specific",
            ):
                self.assertIn(f"<!-- section_id: {sid} -->", text, f"missing anchor {sid}")

    def test_framework_specific_omitted_for_generic_php(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_GEN), "--recipe", "generic_php",
                "--review-root", str(review_root), "--no-console",
            )
            text = (review_root / "CONTEXT.md").read_text()
            self.assertNotIn("<!-- section_id: framework_specific -->", text)

    def test_unknown_recipe_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            proc = _run_cli(
                str(FIX_MIN), "--recipe", "no_such_recipe",
                "--review-root", str(Path(td)/"r"), "--no-console",
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("unknown recipe", proc.stderr)

    def test_review_root_relative_to_project(self):
        # When review-root is relative, it resolves under project_root.
        with tempfile.TemporaryDirectory() as td:
            # Copy fixture into td so we don't pollute the real fixture.
            scratch = Path(td) / "proj"
            shutil.copytree(FIX_MIN, scratch)
            proc = _run_cli(
                str(scratch), "--recipe", "symfony",
                "--review-root", "rev-out", "--no-console",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertTrue((scratch / "rev-out" / "CONTEXT.md").is_file())

    def test_yaml_section_payloads_round_trip(self):
        # Each fenced yaml inside a section must parse via parse_yaml_subset.
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_cli(
                str(FIX_MIN), "--recipe", "symfony",
                "--review-root", str(review_root), "--no-console",
            )
            text = (review_root / "CONTEXT.md").read_text()
            for fence in re.finditer(r"```yaml\n(.*?)\n```", text, re.DOTALL):
                parse_yaml_subset(fence.group(1))  # raises on failure


class CliErrors(unittest.TestCase):
    def test_no_args(self):
        proc = _run_cli()
        self.assertEqual(proc.returncode, 2)

    def test_detect_with_recipe_rejected(self):
        proc = _run_cli(str(FIX_MIN), "--detect", "--recipe", "symfony")
        self.assertEqual(proc.returncode, 2)

    def test_recipe_without_review_root(self):
        proc = _run_cli(str(FIX_MIN), "--recipe", "symfony", "--no-console")
        self.assertEqual(proc.returncode, 2)

    def test_validate_without_review_root(self):
        proc = _run_cli("--validate")
        self.assertEqual(proc.returncode, 2)

    def test_validate_missing_context(self):
        with tempfile.TemporaryDirectory() as td:
            proc = _run_cli("--review-root", td, "--validate")
            self.assertEqual(proc.returncode, 2)


class PathSafety(unittest.TestCase):
    def test_assert_inside_project_accepts_inner(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inner = root / "src" / "x.php"
            inner.parent.mkdir()
            inner.write_text("<?php\n")
            assert_inside_project(inner, root)  # no raise

    def test_assert_inside_project_rejects_outside(self):
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            outside = Path(td2) / "evil.php"
            outside.write_text("<?php\n")
            with self.assertRaises(PathOutsideProjectRoot):
                assert_inside_project(outside, Path(td1))

    def test_assert_inside_project_handles_symlinks(self):
        # /tmp on macOS is a symlink → /private/tmp. resolve() should normalize
        # both sides.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inner = root / "x.php"
            inner.write_text("<?php\n")
            # Pass via unresolved /tmp/...; resolve() handles the symlink.
            assert_inside_project(inner, root)


class ExtractorSandbox(unittest.TestCase):
    """Tests for run_extractor wrapper (timeout/missing/path-safety)."""

    def setUp(self):
        # Re-import to access run_extractor.
        import importlib
        sys.path.insert(0, str(BIN_DIR))
        self.recon_inv = importlib.import_module("recon_inventory")

    def test_runs_on_symfony_fixture_routes(self):
        if not shutil.which("php"):
            self.skipTest("php not on PATH")
        out, warn = self.recon_inv.run_extractor(
            PLUGIN_ROOT, FIX_MIN, "routes", FIX_MIN / "src" / "Controller",
        )
        self.assertIsNone(warn, msg=warn)
        self.assertEqual(out["kind"], "routes")

    def test_path_outside_project_returns_warning(self):
        if not shutil.which("php"):
            self.skipTest("php not on PATH")
        with tempfile.TemporaryDirectory() as td:
            outside = Path(td) / "x.php"
            outside.write_text("<?php\n")
            out, warn = self.recon_inv.run_extractor(
                PLUGIN_ROOT, FIX_MIN, "routes", outside,
            )
            self.assertIsNone(out)
            self.assertIn("path_outside_project_root", warn)

    def test_missing_extractor_returns_warning(self):
        if not shutil.which("php"):
            self.skipTest("php not on PATH")
        with tempfile.TemporaryDirectory() as td:
            fake_root = Path(td)
            out, warn = self.recon_inv.run_extractor(
                fake_root, FIX_MIN, "routes", FIX_MIN / "src",
            )
            self.assertIsNone(out)
            self.assertIn("extract_php_metadata.php missing", warn)


class SandboxNormalizeExclude(unittest.TestCase):
    """sandbox._normalize_exclude — caller-extras append to DEFAULT_EXCLUDE
    while preserving order and dropping duplicates / empty entries.
    """

    def setUp(self):
        sys.path.insert(0, str(BIN_DIR))
        from recon import sandbox
        self.sandbox = sandbox

    def test_none_yields_defaults_only(self):
        out = self.sandbox._normalize_exclude(None)
        self.assertEqual(out, self.sandbox.DEFAULT_EXCLUDE)

    def test_extras_appended_after_defaults(self):
        out = self.sandbox._normalize_exclude(("legacy", "generated"))
        self.assertEqual(out[: len(self.sandbox.DEFAULT_EXCLUDE)], self.sandbox.DEFAULT_EXCLUDE)
        self.assertEqual(out[-2:], ("legacy", "generated"))

    def test_duplicates_with_defaults_dropped(self):
        # vendor is already in DEFAULT_EXCLUDE; passing it as extra should
        # not double-emit.
        out = self.sandbox._normalize_exclude(("vendor", "legacy"))
        self.assertEqual(out.count("vendor"), 1)
        self.assertIn("legacy", out)

    def test_slashes_and_whitespace_normalized(self):
        out = self.sandbox._normalize_exclude(("/legacy/", "  generated  ", ""))
        self.assertIn("legacy", out)
        self.assertIn("generated", out)
        # Empty entry dropped, no leading/trailing slashes leaked through.
        self.assertNotIn("", out)
        for entry in out:
            self.assertFalse(entry.startswith("/"))
            self.assertFalse(entry.endswith("/"))


class RunExtractorForwardsExclude(unittest.TestCase):
    """End-to-end check that run_extractor forwards exclude= to the PHP
    extractor and that vendored / oversize files are skipped pre-parse.
    """

    def setUp(self):
        if not shutil.which("php"):
            self.skipTest("php not on PATH")
        sys.path.insert(0, str(BIN_DIR))
        from recon import sandbox
        self.sandbox = sandbox

    def _project(self, td: Path) -> Path:
        proj = td / "p"
        (proj / "app").mkdir(parents=True)
        (proj / "app" / "Real.php").write_text(
            "<?php\nnamespace App;\nclass Real {}\n"
        )
        (proj / "vendor" / "fake").mkdir(parents=True)
        (proj / "vendor" / "fake" / "X.php").write_text(
            "<?php\nnamespace Vendor;\nclass X {}\n"
        )
        return proj

    def test_default_exclude_drops_vendor(self):
        with tempfile.TemporaryDirectory() as td:
            proj = self._project(Path(td))
            out, warn = self.sandbox.run_extractor(
                PLUGIN_ROOT, proj, "class", proj,
            )
            self.assertIsNone(warn, msg=warn)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Real", fqns)
            self.assertNotIn("Vendor\\X", fqns)

    def test_user_extra_exclude_appended(self):
        with tempfile.TemporaryDirectory() as td:
            proj = self._project(Path(td))
            (proj / "legacy").mkdir()
            (proj / "legacy" / "Old.php").write_text(
                "<?php\nnamespace Legacy;\nclass Old {}\n"
            )
            out, warn = self.sandbox.run_extractor(
                PLUGIN_ROOT, proj, "class", proj, exclude=("legacy",),
            )
            self.assertIsNone(warn, msg=warn)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Real", fqns)
            self.assertNotIn("Vendor\\X", fqns)
            self.assertNotIn("Legacy\\Old", fqns)

    def test_explicit_max_file_size_drops_giant(self):
        with tempfile.TemporaryDirectory() as td:
            proj = self._project(Path(td))
            big = "<?php\nnamespace App;\n// " + ("y" * (3 * 1024 * 1024)) + "\nclass Huge {}\n"
            (proj / "app" / "Huge.php").write_text(big)
            out, warn = self.sandbox.run_extractor(
                PLUGIN_ROOT, proj, "class", proj, max_file_size=2 * 1024 * 1024,
            )
            self.assertIsNone(warn, msg=warn)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Real", fqns)
            self.assertNotIn("App\\Huge", fqns)


if __name__ == "__main__":
    unittest.main()
