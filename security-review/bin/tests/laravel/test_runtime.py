"""Tests for `recon_bags.stack.laravel.runtime` Octane detection.

Octane in composer.json (require/require-dev) → octane=true.
config/octane.php parsed for `'server' => 'xxx'` literal first, then for
`env('OCTANE_SERVER', 'xxx')` default fallback. Absent config file →
octane_server=null even when octane is true (deployment is generic).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_BIN = Path(__file__).resolve().parent.parent.parent
PLUGIN_ROOT = PLUGIN_BIN.parent
sys.path.insert(0, str(PLUGIN_BIN))

from recon.recipes import laravel  # noqa: E402

FIX_OCTANE = Path(__file__).resolve().parent.parent / "fixtures" / "laravel_octane"
FIX_NO_OCTANE = Path(__file__).resolve().parent.parent / "fixtures" / "laravel_no_octane"


class RuntimeBuilderTests(unittest.TestCase):
    def test_octane_in_composer_emits_true(self):
        payload = laravel._build_runtime(FIX_OCTANE)
        self.assertEqual(payload.status, "ok")
        self.assertTrue(payload.data["octane"])

    def test_no_octane_emits_false(self):
        payload = laravel._build_runtime(FIX_NO_OCTANE)
        self.assertEqual(payload.status, "ok")
        self.assertFalse(payload.data["octane"])
        # config/octane.php absent → server stays null.
        self.assertIsNone(payload.data["octane_server"])

    def test_octane_server_from_config_literal(self):
        payload = laravel._build_runtime(FIX_OCTANE)
        self.assertEqual(payload.data["octane_server"], "swoole")

    def test_octane_server_from_env_default(self):
        """When config returns env('OCTANE_SERVER', 'roadrunner') with no literal."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "composer.json").write_text(
                '{"require": {"laravel/octane": "^2.0"}}', encoding="utf-8",
            )
            (root / "config").mkdir()
            (root / "config" / "octane.php").write_text(
                "<?php\nreturn [\n    'server' => env('OCTANE_SERVER', 'roadrunner'),\n];",
                encoding="utf-8",
            )
            payload = laravel._build_runtime(root)
            self.assertTrue(payload.data["octane"])
            self.assertEqual(payload.data["octane_server"], "roadrunner")

    def test_octane_no_config_file_returns_null_server(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "composer.json").write_text(
                '{"require": {"laravel/octane": "^2.0"}}', encoding="utf-8",
            )
            payload = laravel._build_runtime(root)
            self.assertTrue(payload.data["octane"])
            self.assertIsNone(payload.data["octane_server"])
            # composer is the only source.
            self.assertEqual(payload.source_files, ["composer.json"])

    def test_octane_in_require_dev_emits_true(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "composer.json").write_text(
                '{"require-dev": {"laravel/octane": "^2.0"}}', encoding="utf-8",
            )
            payload = laravel._build_runtime(root)
            self.assertTrue(payload.data["octane"])

    def test_octane_frankenphp_value_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "composer.json").write_text(
                '{"require": {"laravel/octane": "^2.0"}}', encoding="utf-8",
            )
            (root / "config").mkdir()
            (root / "config" / "octane.php").write_text(
                "<?php\nreturn ['server' => 'frankenphp'];", encoding="utf-8",
            )
            payload = laravel._build_runtime(root)
            self.assertEqual(payload.data["octane_server"], "frankenphp")

    def test_runtime_data_keys_match_schema(self):
        """Whatever the runtime builder returns must obey the schema contract."""
        payload = laravel._build_runtime(FIX_OCTANE)
        self.assertIsNotNone(payload.data)
        self.assertEqual(set(payload.data.keys()), {"octane", "octane_server"})

    def test_no_composer_no_octane(self):
        """Empty project — composer.json missing → octane=False, server=null."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = laravel._build_runtime(root)
            self.assertFalse(payload.data["octane"])
            self.assertIsNone(payload.data["octane_server"])
            self.assertEqual(payload.source_files, [])


if __name__ == "__main__":
    unittest.main()
