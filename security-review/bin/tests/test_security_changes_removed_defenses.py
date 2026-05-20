"""Tests for `bin/diff_removed_defenses.py` (Wave 2-F).

Covers tightened regex patterns for removed-defense detection in unified diffs
+ pair-detection for refactoring vs. genuine removal.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import diff_removed_defenses as drd  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _hunk(file: str, removed: list[str] | None = None, added: list[str] | None = None,
          context_before: list[str] | None = None,
          context_after: list[str] | None = None,
          old_start: int = 10) -> str:
    """Build a minimal unified-diff hunk for one file."""
    removed = removed or []
    added = added or []
    cb = context_before or []
    ca = context_after or []
    minus_count = len(cb) + len(removed) + len(ca)
    plus_count = len(cb) + len(added) + len(ca)
    header = f"diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n"
    hunk_header = f"@@ -{old_start},{minus_count} +{old_start},{plus_count} @@\n"
    body_lines: list[str] = []
    for line in cb:
        body_lines.append(f" {line}")
    for line in removed:
        body_lines.append(f"-{line}")
    for line in added:
        body_lines.append(f"+{line}")
    for line in ca:
        body_lines.append(f" {line}")
    return header + hunk_header + "\n".join(body_lines) + "\n"


def _categories(entries: list[dict]) -> set[str]:
    return {e["pattern_matched"] for e in entries}


# ---------------------------------------------------------------------------
# Pattern tests — one per category from REMOVED_DEFENSE_PATTERNS.
# ---------------------------------------------------------------------------


class PatternTests(unittest.TestCase):
    def test_pattern_isgranted_attribute(self):
        diff = _hunk("src/Controller/Foo.php",
                     removed=["    #[IsGranted('ROLE_ADMIN')]"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        cats = _categories(entries)
        self.assertIn("symfony_attr_isgranted", cats)
        # Carry file + old line.
        match = next(e for e in entries if e["pattern_matched"] == "symfony_attr_isgranted")
        self.assertEqual(match["file"], "src/Controller/Foo.php")
        self.assertIsInstance(match["line_in_old"], int)

    def test_pattern_denyaccess(self):
        diff = _hunk("src/Controller/Bar.php",
                     removed=["        $this->denyAccessUnlessGranted('ROLE_USER');"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("symfony_call_denyaccess", _categories(entries))

    def test_pattern_blade_can(self):
        diff = _hunk("resources/views/post.blade.php",
                     removed=["@can('edit', $post)"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("laravel_blade_can", _categories(entries))

    def test_pattern_can_with_string_filtered(self):
        """`->can('edit')` triggers; `$collection->can()` (no string) does not."""
        diff_pos = _hunk("app/Http/Controllers/PostController.php",
                         removed=["        if ($user->can('edit', $post)) {"])
        entries = drd.scan_diff_for_removed_defenses(diff_pos)
        self.assertIn("laravel_can_with_string", _categories(entries))

        diff_neg = _hunk("app/Service/Util.php",
                         removed=["        if ($collection->can()) {"])
        entries_neg = drd.scan_diff_for_removed_defenses(diff_neg)
        self.assertNotIn("laravel_can_with_string", _categories(entries_neg))

    def test_pattern_authorize(self):
        diff = _hunk("app/Http/Controllers/PostController.php",
                     removed=["        $this->authorize('update', $post);"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("laravel_authorize", _categories(entries))

    def test_pattern_gate_authorize(self):
        diff = _hunk("app/Http/Controllers/UserController.php",
                     removed=["        Gate::authorize('admin');"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("laravel_authorize", _categories(entries))

    def test_pattern_gate_define(self):
        diff = _hunk("app/Providers/AuthServiceProvider.php",
                     removed=["        Gate::define('manage-posts', function ($user) {"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("laravel_gate_define", _categories(entries))

    def test_pattern_middleware_string(self):
        diff = _hunk("routes/web.php",
                     removed=["Route::get('/profile', ...)->middleware('auth');"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("middleware_auth_single", _categories(entries))

    def test_pattern_middleware_array(self):
        diff = _hunk("routes/web.php",
                     removed=["Route::get('/admin', ...)->middleware(['auth', 'admin']);"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("middleware_auth_array", _categories(entries))

    def test_pattern_middleware_throttle_single(self):
        diff = _hunk("routes/api.php",
                     removed=["Route::post('/login', ...)->middleware('throttle:5,1');"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("middleware_throttle_single", _categories(entries))

    def test_pattern_middleware_throttle_array(self):
        diff = _hunk("routes/api.php",
                     removed=["Route::post('/login', ...)->middleware(['throttle:60,1', 'auth']);"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        cats = _categories(entries)
        self.assertIn("middleware_throttle_array", cats)
        # Same line also triggers `auth` array form — both are valid hits.
        self.assertIn("middleware_auth_array", cats)

    def test_pattern_csrf_protection(self):
        diff = _hunk("config/packages/framework.yaml",
                     removed=["    'csrf_protection' => true,"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("symfony_csrf_protection", _categories(entries))

    def test_pattern_hash_equals(self):
        diff = _hunk("src/Service/TokenComparator.php",
                     removed=["        return hash_equals($expected, $actual);"])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("hash_equals", _categories(entries))

    def test_pattern_random_secure(self):
        diff = _hunk("src/Service/TokenGenerator.php",
                     removed=[
                         "        $bytes = random_bytes(32);",
                         "        $n = random_int(1, 1000);",
                     ])
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertEqual(
            sum(1 for e in entries if e["pattern_matched"] == "random_secure"),
            2,
        )


# ---------------------------------------------------------------------------
# Pair detection — added equivalent within ±10 lines.
# ---------------------------------------------------------------------------


class PairDetectionTests(unittest.TestCase):
    def test_added_equivalent_detection_denyaccess_to_isgranted(self):
        """Refactor: removed denyAccessUnlessGranted, added #[IsGranted] near."""
        diff = _hunk(
            "src/Controller/Foo.php",
            context_before=["    public function index()", "    {"],
            removed=["        $this->denyAccessUnlessGranted('ROLE_USER');"],
            added=["        // moved to attribute"],
            context_after=["    }", "", "    #[IsGranted('ROLE_USER')]",
                           "    public function show()"],
        )
        # Note: pair detection looks for added line carrying the equivalent.
        # The `#[IsGranted]` here is in CONTEXT, not added — let's redo with
        # a proper added attribute.
        diff = _hunk(
            "src/Controller/Foo.php",
            context_before=["    public function index()", "    {"],
            removed=["        $this->denyAccessUnlessGranted('ROLE_USER');"],
            added=["        // refactored", "    }", "",
                   "    #[IsGranted('ROLE_USER')]",
                   "    public function show()"],
        )
        entries = drd.scan_diff_for_removed_defenses(diff)
        match = next(e for e in entries if e["pattern_matched"] == "symfony_call_denyaccess")
        self.assertTrue(match["added_equivalent_detected"])

    def test_added_equivalent_detection_no_pair(self):
        """Genuine removal — no equivalent added nearby → False."""
        diff = _hunk(
            "src/Controller/Bar.php",
            removed=["        $this->denyAccessUnlessGranted('ROLE_ADMIN');"],
            added=["        return $this->render('admin/list.html.twig');"],
        )
        entries = drd.scan_diff_for_removed_defenses(diff)
        match = next(e for e in entries if e["pattern_matched"] == "symfony_call_denyaccess")
        self.assertFalse(match["added_equivalent_detected"])

    def test_pair_detection_respects_file_boundary(self):
        """Equivalent in DIFFERENT file must not count as paired."""
        diff = (
            _hunk("src/Controller/A.php",
                  removed=["        $this->denyAccessUnlessGranted('ROLE_USER');"])
            + _hunk("src/Controller/B.php",
                    added=["        $this->denyAccessUnlessGranted('ROLE_USER');"],
                    old_start=20)
        )
        entries = drd.scan_diff_for_removed_defenses(diff)
        match = next(e for e in entries if e["pattern_matched"] == "symfony_call_denyaccess")
        # Different file → not paired.
        self.assertFalse(match["added_equivalent_detected"])
        self.assertEqual(match["file"], "src/Controller/A.php")

    def test_pair_detection_middleware_auth(self):
        """Removed middleware('auth') with added middleware('auth') in same hunk."""
        diff = _hunk(
            "routes/web.php",
            removed=["Route::get('/profile', [Foo::class, 'show'])->middleware('auth');"],
            added=["Route::get('/profile', [Foo::class, 'show'])->middleware('auth')->name('profile');"],
        )
        entries = drd.scan_diff_for_removed_defenses(diff)
        match = next(e for e in entries if e["pattern_matched"] == "middleware_auth_single")
        self.assertTrue(match["added_equivalent_detected"])


# ---------------------------------------------------------------------------
# Diff parser edge cases.
# ---------------------------------------------------------------------------


class DiffParserTests(unittest.TestCase):
    def test_file_header_minus_minus_minus_not_treated_as_removal(self):
        """`--- a/path` is a header, must not be matched as a deleted line."""
        diff = "--- a/src/Foo.php\n+++ b/src/Foo.php\n"
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertEqual(entries, [])

    def test_dev_null_added_for_removed_file(self):
        """`+++ /dev/null` for whole-file removal — parser shouldn't crash."""
        diff = (
            "diff --git a/src/Voter/OldVoter.php b/src/Voter/OldVoter.php\n"
            "deleted file mode 100644\n"
            "--- a/src/Voter/OldVoter.php\n"
            "+++ /dev/null\n"
            "@@ -1,5 +0,0 @@\n"
            "-<?php\n"
            "-namespace App\\Voter;\n"
            "-class OldVoter extends Voter {\n"
            "-    $this->denyAccessUnlessGranted('ROLE_USER');\n"
            "-}\n"
        )
        entries = drd.scan_diff_for_removed_defenses(diff)
        self.assertIn("symfony_call_denyaccess", _categories(entries))

    def test_empty_diff_returns_empty(self):
        self.assertEqual(drd.scan_diff_for_removed_defenses(""), [])


# ---------------------------------------------------------------------------
# CLI smoke test.
# ---------------------------------------------------------------------------


class CliTests(unittest.TestCase):
    def test_main_outputs_valid_json(self):
        diff = _hunk("src/Controller/Foo.php",
                     removed=["    #[IsGranted('ROLE_ADMIN')]"])
        with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as f:
            f.write(diff)
            patch_path = f.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = drd.main([patch_path])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertIn("removed_defenses", payload)
            self.assertEqual(len(payload["removed_defenses"]), 1)
            self.assertEqual(
                payload["removed_defenses"][0]["pattern_matched"],
                "symfony_attr_isgranted",
            )
        finally:
            Path(patch_path).unlink()

    def test_main_multiple_files_concatenated(self):
        d1 = _hunk("src/A.php", removed=["    hash_equals($a, $b);"])
        d2 = _hunk("src/B.php", removed=["    random_bytes(16);"])
        with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as f1, \
             tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as f2:
            f1.write(d1)
            f2.write(d2)
            p1, p2 = f1.name, f2.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = drd.main([p1, p2])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            cats = {e["pattern_matched"] for e in payload["removed_defenses"]}
            self.assertEqual(cats, {"hash_equals", "random_secure"})
        finally:
            Path(p1).unlink()
            Path(p2).unlink()


if __name__ == "__main__":
    unittest.main()
