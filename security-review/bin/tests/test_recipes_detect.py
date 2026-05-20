"""Detect-formula tests for symfony / generic_php recipes (rev 3.5 G-Conf.1).

Five canonical cases:
  (а) полный Symfony 7        → score 1.0
  (б) Symfony без symfony.lock → score 0.8
  (в) только symfony/console   → score 0.4 (below threshold)
  (г) Laravel + случайный symfony dep → score 0.4
  (д) генерик-php без symfony  → score 0.0 (None)

Plus loader / detect_best behavior tests.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon.recipes import (  # noqa: E402
    detect_best, load_recipe, available_recipes, STACK_DETECT_THRESHOLD,
)
from recon.recipes.symfony import detect as detect_symfony  # noqa: E402
from recon.recipes.generic_php import detect as detect_generic  # noqa: E402


def make_project(td: Path, **layout) -> Path:
    """Create a minimal project layout under td.

    Keys understood:
      composer_json: dict to dump as composer.json (or False to omit).
      symfony_lock:  bool — create empty symfony.lock.
      bin_console:   bool — create empty bin/console.
      bundles_php:   bool — create empty config/bundles.php.
      php_files:     list[str] — relative paths to create as empty .php files.
    """
    if "composer_json" in layout and layout["composer_json"] is not False:
        (td / "composer.json").write_text(json.dumps(layout["composer_json"]))
    if layout.get("symfony_lock"):
        (td / "symfony.lock").write_text("[]")
    if layout.get("bin_console"):
        (td / "bin").mkdir(exist_ok=True)
        (td / "bin" / "console").write_text("#!/usr/bin/env php\n")
    if layout.get("bundles_php"):
        (td / "config").mkdir(exist_ok=True)
        (td / "config" / "bundles.php").write_text("<?php return [];")
    for rel in layout.get("php_files", ()):
        path = td / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<?php\n")
    return td


class SymfonyDetectFormula(unittest.TestCase):
    def test_a_full_symfony7(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"symfony/framework-bundle": "^7.0"}},
                symfony_lock=True,
                bin_console=True,
                bundles_php=True,
            )
            m = detect_symfony(root)
            self.assertIsNotNone(m)
            self.assertAlmostEqual(m.confidence, 1.0, places=5)
            self.assertGreaterEqual(m.confidence, STACK_DETECT_THRESHOLD)
            self.assertEqual(m.version, "^7.0")

    def test_b_no_symfony_lock_vendored(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"symfony/framework-bundle": "^7.0"}},
                symfony_lock=False,
                bin_console=True,
                bundles_php=True,
            )
            m = detect_symfony(root)
            self.assertIsNotNone(m)
            self.assertAlmostEqual(m.confidence, 0.8, places=5)
            self.assertGreaterEqual(m.confidence, STACK_DETECT_THRESHOLD)

    def test_c_only_symfony_console_dep(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"symfony/console": "^7.0"}},
            )
            m = detect_symfony(root)
            # framework-bundle absent → 0.0 from composer; no other signals → None.
            self.assertIsNone(m)

    def test_c2_console_dep_with_bin_console(self):
        # Edge: only bin/console artifact (e.g. legacy project), no
        # framework-bundle → score 0.2, well below threshold.
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"symfony/console": "^7.0"}},
                bin_console=True,
            )
            m = detect_symfony(root)
            self.assertIsNotNone(m)
            self.assertAlmostEqual(m.confidence, 0.2, places=5)
            self.assertLess(m.confidence, STACK_DETECT_THRESHOLD)

    def test_d_laravel_with_random_symfony_dep(self):
        # framework-bundle absent → 0.0 from composer.
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={
                    "require": {
                        "laravel/framework": "^11.0",
                        "symfony/string": "^7.0",  # transitive-ish, not framework-bundle
                    }
                },
            )
            m = detect_symfony(root)
            self.assertIsNone(m)

    def test_e_generic_php_no_symfony(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"slim/slim": "^4.0"}},
                php_files=["public/index.php", "src/App.php"],
            )
            m = detect_symfony(root)
            self.assertIsNone(m)

    def test_devdep_only_framework_bundle(self):
        # framework-bundle in require-dev — still counts (rare but valid for
        # Symfony test apps embedded inside libraries).
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require-dev": {"symfony/framework-bundle": "^7.0"}},
            )
            m = detect_symfony(root)
            self.assertIsNotNone(m)
            self.assertAlmostEqual(m.confidence, 0.4, places=5)


class GenericPhpDetect(unittest.TestCase):
    def test_with_composer_and_php(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"slim/slim": "^4.0"}},
                php_files=["public/index.php"],
            )
            m = detect_generic(root)
            self.assertIsNotNone(m)
            self.assertAlmostEqual(m.confidence, 0.8, places=5)

    def test_only_composer(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(Path(td), composer_json={"name": "x/y"})
            m = detect_generic(root)
            self.assertIsNotNone(m)
            self.assertAlmostEqual(m.confidence, 0.5, places=5)

    def test_empty_dir_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            m = detect_generic(Path(td))
            self.assertIsNone(m)


class DetectBestSelection(unittest.TestCase):
    def test_full_symfony_wins_over_generic(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"symfony/framework-bundle": "^7.0"}},
                symfony_lock=True, bin_console=True, bundles_php=True,
                php_files=["src/App.php"],
            )
            picked = detect_best(root)
            self.assertIsNotNone(picked)
            name, match = picked
            self.assertEqual(name, "symfony")

    def test_below_threshold_falls_to_generic(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_project(
                Path(td),
                composer_json={"require": {"symfony/console": "^7.0"}},
                bin_console=True,  # 0.2 — below threshold
                php_files=["src/x.php"],
            )
            picked = detect_best(root)
            self.assertIsNotNone(picked)
            name, _ = picked
            self.assertEqual(name, "generic_php")

    def test_bare_dir_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(detect_best(Path(td)))


class RegistryShape(unittest.TestCase):
    def test_known_recipes_loadable(self):
        for name in available_recipes():
            mod = load_recipe(name)
            self.assertEqual(mod.LANGUAGE, "php")
            # Required API surface present.
            self.assertTrue(callable(mod.detect))
            self.assertTrue(callable(mod.build_inventory))
            self.assertTrue(callable(mod.sanity_probes))
            self.assertEqual(mod.RECIPE_NAME, name)

    def test_symfony_schema_keys_match_plan(self):
        from recon.recipes.symfony import FRAMEWORK_SPECIFIC_SCHEMA
        # rev 3.7 plan section A: voters, forms, serializer_groups, twig_overrides,
        # doctrine_listeners, firewalls, messenger_transports.
        # v3.1: graphql_layer added (optional, present-if-detected).
        # v3.2: easyadmin_crud_controllers added (recipe-level enumeration of
        # AbstractCrudController subclasses with configure_fields/actions).
        # v3.2: admin_authz_coverage added (CRUD ↔ voter cross-check).
        # v3.2.4: sonata_admin_classes added (parallel admin-bundle for Sonata).
        # v3.4.0 (Wave 2-D): routes_authz_matrix, sensitive_columns.
        expected = {"voters", "forms", "serializer_groups", "twig_overrides",
                    "doctrine_listeners", "firewalls", "messenger_transports",
                    "graphql_layer", "easyadmin_crud_controllers",
                    "sonata_admin_classes", "admin_authz_coverage",
                    "routes_authz_matrix", "sensitive_columns"}
        self.assertEqual(set(FRAMEWORK_SPECIFIC_SCHEMA.keys()), expected)


class InventoryShape(unittest.TestCase):
    def test_symfony_no_plugin_root_returns_unknown_skeleton(self):
        # Without `plugin_root` the recipe cannot run the PHP extractor,
        # so it emits an `unknown`-everywhere skeleton (not a STUB).
        from recon.recipes.symfony import build_inventory
        with tempfile.TemporaryDirectory() as td:
            r = build_inventory(Path(td))
            self.assertEqual(r.status, "partial")
            for sid, payload in r.core.items():
                self.assertEqual(payload.status, "unknown", f"core/{sid}")
            for k, payload in r.framework_specific.items():
                self.assertEqual(payload.status, "unknown", f"fs/{k}")

    def test_generic_php_stub_has_no_framework_specific(self):
        # generic_php is still a stub (out of S2 scope).
        from recon.recipes.generic_php import build_inventory
        with tempfile.TemporaryDirectory() as td:
            r = build_inventory(Path(td))
            self.assertEqual(r.framework_specific, {})


if __name__ == "__main__":
    unittest.main()
