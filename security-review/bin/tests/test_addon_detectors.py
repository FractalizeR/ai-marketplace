"""Unit tests for addon detector modules (Stage 1).

Covers the lightweight composer-based detectors:
- recon.recipes.easyadmin_detect.detect_easyadmin
- recon.recipes.sonata_detect.detect_sonata

These probes are intentionally cheap — they only inspect `composer.json`,
not the source tree — so the tests use ephemeral directories with hand-written
composer.json files. The heavier `collect_*` enumerations have separate
coverage in `test_recipe_symfony.py` (driven by full fixtures).
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


_BIN = Path(__file__).resolve().parent.parent
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

from recon.recipes.easyadmin_detect import detect_easyadmin  # noqa: E402
from recon.recipes.sonata_detect import detect_sonata  # noqa: E402
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402


def _section_payload(text: str, section_id: str) -> dict | None:
    """Return the parsed payload for `## ... <!-- section_id: X --> ... yaml ...`.

    For dot-paths like `recon_bags.addon.easyadmin.crud_controllers`, the first
    segment selects the top-level section and the rest walk into the parsed dict.
    Mirrors the helper used in test_recipe_symfony.py — kept inline so this
    test module stays self-contained.
    """
    import re as _re
    if "." not in section_id:
        anchor = f"<!-- section_id: {section_id} -->"
        idx = text.find(anchor)
        if idx == -1:
            return None
        rest = text[idx:]
        m = _re.search(r"```yaml\s*\n(.*?)\n```", rest, _re.DOTALL)
        if not m:
            return None
        return parse_yaml_subset(m.group(1))
    parts = section_id.split(".")
    cur = _section_payload(text, parts[0])
    for p in parts[1:]:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _write_composer(root: Path, *, require: dict | None = None, require_dev: dict | None = None) -> None:
    data: dict = {"name": "fixture/inline", "type": "project"}
    if require is not None:
        data["require"] = require
    if require_dev is not None:
        data["require-dev"] = require_dev
    (root / "composer.json").write_text(json.dumps(data), encoding="utf-8")


class DetectEasyadminTests(unittest.TestCase):
    def test_returns_true_when_package_in_require(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"easycorp/easyadmin-bundle": "^4.10"})
            self.assertTrue(detect_easyadmin(root))

    def test_returns_true_when_package_in_require_dev(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require_dev={"easycorp/easyadmin-bundle": "^4.10"})
            self.assertTrue(detect_easyadmin(root))

    def test_returns_false_when_package_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_easyadmin(root))

    def test_returns_false_when_no_composer_json(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(detect_easyadmin(Path(td)))

    def test_returns_false_on_malformed_composer_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "composer.json").write_text("{not valid json", encoding="utf-8")
            self.assertFalse(detect_easyadmin(root))

    def test_returns_false_when_composer_root_is_not_object(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "composer.json").write_text("[]", encoding="utf-8")
            self.assertFalse(detect_easyadmin(root))


class DetectSonataTests(unittest.TestCase):
    def test_returns_true_when_package_in_require(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"sonata-project/admin-bundle": "^4.30"})
            self.assertTrue(detect_sonata(root))

    def test_returns_true_when_package_in_require_dev(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require_dev={"sonata-project/admin-bundle": "^4.30"})
            self.assertTrue(detect_sonata(root))

    def test_returns_false_when_package_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"symfony/framework-bundle": "^7.0"})
            self.assertFalse(detect_sonata(root))

    def test_returns_false_when_no_composer_json(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(detect_sonata(Path(td)))

    def test_easyadmin_and_sonata_are_independent(self):
        """Presence of one addon does not affect the other's detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_composer(root, require={"easycorp/easyadmin-bundle": "^4.10"})
            self.assertTrue(detect_easyadmin(root))
            self.assertFalse(detect_sonata(root))


class StackBlockPropagatesAddons(unittest.TestCase):
    """`_stack_block(...)` must surface `detected_addons` as `stack.addons`."""

    def _fake_recipe(self):
        """Build a minimal in-process stand-in for a recipe module.

        Avoids touching the real Symfony recipe (which calls into the PHP
        extractor when build_inventory runs). Only `_stack_block` is under test.
        """
        from recon.types import StackMatch

        class _Rec:
            RECIPE_NAME = "symfony"
            LANGUAGE = "php"

            @staticmethod
            def detect(_project_root):
                return StackMatch(
                    name="symfony", version="^7.0", confidence=1.0,
                    evidence=["composer.json"],
                )

        return _Rec()

    def test_addons_emitted_sorted(self):
        import recon_inventory as ri
        with tempfile.TemporaryDirectory() as td:
            block = ri._stack_block(
                self._fake_recipe(),
                Path(td),
                detected_addons=["sonata", "easyadmin"],
            )
            self.assertEqual(block.get("addons"), ["easyadmin", "sonata"])

    def test_addons_omitted_when_empty(self):
        """Empty list → no `addons` key in frontmatter (keeps emit tidy)."""
        import recon_inventory as ri
        with tempfile.TemporaryDirectory() as td:
            block = ri._stack_block(
                self._fake_recipe(), Path(td), detected_addons=[],
            )
            self.assertNotIn("addons", block)

    def test_addons_omitted_when_argument_missing(self):
        """Default `detected_addons=None` keeps backward-compat call sites green."""
        import recon_inventory as ri
        with tempfile.TemporaryDirectory() as td:
            block = ri._stack_block(self._fake_recipe(), Path(td))
            self.assertNotIn("addons", block)


class FrontmatterAddonsEndToEnd(unittest.TestCase):
    """End-to-end check: composer.json with addon dep → `stack.addons` in frontmatter.

    Uses the existing symfony_admin / symfony_sonata_admin / symfony_minimal
    fixtures so we don't drift from real-world composer shapes.
    """

    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    def _run_and_read(self, fixture: str) -> str:
        """Run the recon recipe on a fixture and return CONTEXT.md text.

        Returns "" if PHP is unavailable (matches the skip pattern used
        elsewhere in this suite).
        """
        import shutil as _shutil
        import subprocess as _subprocess
        if _shutil.which("php") is None:
            self.skipTest("php not on PATH")
        fix_path = self.fixtures_dir / fixture
        if not fix_path.is_dir():
            self.skipTest(f"fixture {fixture} not present")
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            review_root.mkdir()
            proc = _subprocess.run(
                [
                    sys.executable,
                    str(_BIN / "recon_inventory.py"),
                    str(fix_path),
                    "--recipe", "symfony",
                    "--review-root", str(review_root),
                    "--no-console",
                ],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            return (review_root / "CONTEXT.md").read_text(encoding="utf-8")

    def _extract_addons(self, text: str) -> list[str]:
        """Pull `stack.addons:` list out of frontmatter via `parse_yaml_subset`.

        Reuses the same YAML-subset parser the production emitter is validated
        against, so the test cannot drift from the real emit format (M-1).
        """
        m = FRONTMATTER_RE.match(text)
        if not m:
            return []
        fm = parse_yaml_subset(m.group(1))
        stack = fm.get("stack") if isinstance(fm, dict) else None
        if not isinstance(stack, dict):
            return []
        addons = stack.get("addons")
        return list(addons) if isinstance(addons, list) else []

    def test_easyadmin_fixture_lists_easyadmin_addon(self):
        text = self._run_and_read("symfony_admin")
        addons = self._extract_addons(text)
        self.assertIn("easyadmin", addons)
        self.assertNotIn("sonata", addons)
        # Recon must emit the addon bag with a valid status + items shape.
        payload = _section_payload(text, "recon_bags.addon.easyadmin.crud_controllers")
        self.assertIsInstance(payload, dict, f"missing easyadmin bag in:\n{text}")
        self.assertIn(payload.get("status"), {"ok", "partial", "none"})
        self.assertIsInstance(payload.get("items"), list)

    def test_sonata_fixture_lists_sonata_addon(self):
        text = self._run_and_read("symfony_sonata_admin")
        addons = self._extract_addons(text)
        self.assertIn("sonata", addons)
        self.assertNotIn("easyadmin", addons)
        # Mirror for Sonata — the recon must emit `admin_classes` bag.
        payload = _section_payload(text, "recon_bags.addon.sonata.admin_classes")
        self.assertIsInstance(payload, dict, f"missing sonata bag in:\n{text}")
        self.assertIn(payload.get("status"), {"ok", "partial", "none"})
        self.assertIsInstance(payload.get("items"), list)

    def test_minimal_fixture_has_no_addons(self):
        text = self._run_and_read("symfony_minimal")
        addons = self._extract_addons(text)
        self.assertEqual(addons, [])


class AvailableRecipesExcludesDetectModules(unittest.TestCase):
    """Regression: `*_detect.py` files must NOT be listed as recipes.

    `recon.recipes.__init__.available_recipes()` is used to enumerate
    loadable recipes; addon detectors live in the same package but expose
    `detect_<addon>` not the recipe contract.
    """

    def test_easyadmin_detect_not_listed(self):
        from recon.recipes import available_recipes
        recipes = available_recipes()
        self.assertNotIn("easyadmin_detect", recipes)
        self.assertNotIn("sonata_detect", recipes)
        # Real recipes are still listed.
        self.assertIn("symfony", recipes)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
