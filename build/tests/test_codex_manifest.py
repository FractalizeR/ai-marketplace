"""Unit the stdlib mirror of Codex `validate_plugin.py` (build/codex_manifest.py).

The mirror gates the authored plugin.json / marketplace.json without PyYAML. Its
plugin-manifest half is additionally pinned against the REAL validator by a durable
skip-if-unavailable test in test_codex_pkg; here we exercise every rule + mutation
and golden-anchor the marketplace (which has no runnable oracle).
"""

import copy
import json
import unittest
from pathlib import Path

import _common
from _common import REPO_ROOT

import codex_manifest as cm

HARNESS_ROOT = REPO_ROOT / "harness" / "codex"
PLUGIN_NAME = "fr-security-review"


def _plugin():
    return json.loads((HARNESS_ROOT / "plugin.json").read_text(encoding="utf-8"))


def _marketplace():
    return json.loads((HARNESS_ROOT / "marketplace.json").read_text(encoding="utf-8"))


class PluginManifestValidTests(unittest.TestCase):
    def test_authored_manifest_passes(self):
        self.assertEqual(cm.validate_plugin_manifest(_plugin()), [])

    def test_empty_capabilities_allowed(self):
        m = _plugin()
        m["interface"]["capabilities"] = []
        self.assertEqual(cm.validate_plugin_manifest(m), [])

    def test_default_prompt_string_or_array_ok(self):
        # The real validator only existence-checks defaultPrompt; both forms pass.
        for val in ("a bare string", ["a", "b"]):
            m = _plugin()
            m["interface"]["defaultPrompt"] = val
            self.assertEqual(cm.validate_plugin_manifest(m), [], val)


class PluginManifestMutationTests(unittest.TestCase):
    def _fails(self, mutate, needle):
        m = _plugin()
        mutate(m)
        problems = cm.validate_plugin_manifest(m)
        self.assertTrue(any(needle in p for p in problems),
                        f"expected {needle!r} in {problems}")

    def test_bad_semver(self):
        self._fails(lambda m: m.__setitem__("version", "1.0"), "strict semver")

    def test_extra_top_level_key(self):
        self._fails(lambda m: m.__setitem__("hooks", "./hooks/"), "is not accepted")

    def test_unknown_author_key(self):
        self._fails(lambda m: m["author"].__setitem__("twitter", "x"), "author.twitter")

    def test_unknown_interface_key(self):
        self._fails(lambda m: m["interface"].__setitem__("bogus", "x"), "interface.bogus")

    def test_missing_author_name(self):
        self._fails(lambda m: m["author"].__setitem__("name", "  "), "author.name")

    def test_bad_author_url(self):
        self._fails(lambda m: m["author"].__setitem__("url", "http://x.com"), "author.url")

    def test_blank_interface_field(self):
        self._fails(lambda m: m["interface"].__setitem__("displayName", ""), "displayName")

    def test_capabilities_not_array(self):
        self._fails(lambda m: m["interface"].__setitem__("capabilities", "x"), "capabilities")

    def test_capabilities_non_string_member(self):
        self._fails(lambda m: m["interface"].__setitem__("capabilities", [1]), "capabilities")

    def test_missing_default_prompt(self):
        self._fails(lambda m: m["interface"].pop("defaultPrompt"), "defaultPrompt")

    def test_skills_not_skills(self):
        self._fails(lambda m: m.__setitem__("skills", "./other/"), "must resolve to `skills`")

    def test_bad_brand_color(self):
        self._fails(lambda m: m["interface"].__setitem__("brandColor", "red"), "brandColor")

    def test_todo_marker_nested_in_list(self):
        self._fails(lambda m: m["interface"].__setitem__(
            "capabilities", ["ok", "[TODO: fill me]"]), "[TODO")

    def test_todo_marker_nested_in_dict(self):
        self._fails(lambda m: m["interface"].__setitem__(
            "shortDescription", "[TODO: describe]"), "[TODO")


class MarketplaceValidTests(unittest.TestCase):
    def test_authored_marketplace_passes(self):
        self.assertEqual(
            cm.validate_marketplace(_marketplace(), plugin_name=PLUGIN_NAME), [])

    def test_golden_entry_shape(self):
        # H1: the marketplace half has no runnable oracle — pin the entry to the
        # exact scaffold/spec shape (create_basic_plugin.build_marketplace_entry).
        entry = next(e for e in _marketplace()["plugins"] if e["name"] == PLUGIN_NAME)
        self.assertEqual(entry["source"], {"source": "local",
                                           "path": f"./plugins/{PLUGIN_NAME}"})
        self.assertIn(entry["policy"]["installation"], cm.INSTALL_POLICIES)
        self.assertIn(entry["policy"]["authentication"], cm.AUTH_POLICIES)
        self.assertTrue(entry["category"].strip())


class MarketplaceMutationTests(unittest.TestCase):
    def _fails(self, mutate, needle):
        mp = _marketplace()
        mutate(mp)
        problems = cm.validate_marketplace(mp, plugin_name=PLUGIN_NAME)
        self.assertTrue(any(needle in p for p in problems),
                        f"expected {needle!r} in {problems}")

    def test_entry_name_mismatch(self):
        self._fails(lambda mp: mp["plugins"][0].__setitem__("name", "other"),
                    "no entry for plugin")

    def test_wrong_source_path(self):
        self._fails(lambda mp: mp["plugins"][0]["source"].__setitem__("path", "./x"),
                    "source.path")

    def test_source_not_local(self):
        self._fails(lambda mp: mp["plugins"][0]["source"].__setitem__("source", "git"),
                    "source.source")

    def test_bad_install_policy(self):
        self._fails(lambda mp: mp["plugins"][0]["policy"].__setitem__("installation", "MAYBE"),
                    "policy.installation")

    def test_bad_auth_policy(self):
        self._fails(lambda mp: mp["plugins"][0]["policy"].__setitem__("authentication", "NEVER"),
                    "policy.authentication")

    def test_missing_category(self):
        self._fails(lambda mp: mp["plugins"][0].__setitem__("category", ""), "category")

    def test_plugins_not_list(self):
        self._fails(lambda mp: mp.__setitem__("plugins", {}), "must be an array")

    def test_bad_marketplace_name(self):
        self._fails(lambda mp: mp.__setitem__("name", "bad name!"), "may only contain")


class SkillFrontmatterGateTests(unittest.TestCase):
    """Skill-frontmatter shape is gated by the WIRED gate (gates.check_codex_output,
    is_skill=True), not a mirror copy — assert it here so coverage is not lost."""

    GOOD = '---\nname: security-project\ndescription: "Audit a project."\n---\n\nBody.'

    def _check(self, text):
        from gates import check_codex_output
        return check_codex_output(text, is_skill=True)

    def test_good_frontmatter(self):
        self.assertEqual(self._check(self.GOOD), [])

    def test_missing_block(self):
        self.assertTrue(any("frontmatter" in x for x in self._check("no frontmatter")))

    def test_empty_name(self):
        p = self._check('---\nname:\ndescription: "d"\n---\n')
        self.assertTrue(any("`name`" in x for x in p))

    def test_empty_description(self):
        # gates._nonempty_value strips after unquoting → whitespace-only is empty.
        p = self._check('---\nname: s\ndescription: "   "\n---\n')
        self.assertTrue(any("`description`" in x for x in p))


class SemverEdgeTests(unittest.TestCase):
    def test_rejects_leading_zero(self):
        self.assertIsNone(cm.SEMVER_RE.fullmatch("01.0.0"))

    def test_rejects_v_prefix(self):
        self.assertIsNone(cm.SEMVER_RE.fullmatch("v1.0.0"))

    def test_rejects_two_component(self):
        self.assertIsNone(cm.SEMVER_RE.fullmatch("1.0"))

    def test_accepts_prerelease_and_build(self):
        self.assertIsNotNone(cm.SEMVER_RE.fullmatch("1.2.3-beta.1+codex.local"))


class ContractAndAssetFieldTests(unittest.TestCase):
    """MEDIUM (code review): the mirror is the sole fast-path gate — it must reject
    the apps/mcpServers/asset mutations the real validator rejects."""

    def _fails(self, mutate, needle):
        m = _plugin()
        mutate(m)
        problems = cm.validate_plugin_manifest(m)
        self.assertTrue(any(needle in p for p in problems), f"expected {needle!r} in {problems}")

    def test_apps_wrong_contract_path(self):
        self._fails(lambda m: m.__setitem__("apps", "./skills/"), "must resolve to `.app.json`")

    def test_mcpservers_wrong_contract_path(self):
        self._fails(lambda m: m.__setitem__("mcpServers", "./skills/"),
                    "must resolve to `.mcp.json`")

    def test_composer_icon_escape(self):
        self._fails(lambda m: m["interface"].__setitem__("composerIcon", "../evil.png"),
                    "composerIcon")

    def test_logo_absolute(self):
        self._fails(lambda m: m["interface"].__setitem__("logo", "/abs/logo.png"), "logo")

    def test_screenshots_not_a_list(self):
        self._fails(lambda m: m["interface"].__setitem__("screenshots", "shot.png"),
                    "screenshots")

    def test_screenshots_escape_member(self):
        self._fails(lambda m: m["interface"].__setitem__("screenshots", ["../x.png"]),
                    "screenshots[0]")

    def test_good_asset_paths_pass(self):
        m = _plugin()
        m["interface"]["composerIcon"] = "assets/icon.png"
        m["interface"]["screenshots"] = ["assets/a.png", "assets/b.png"]
        self.assertEqual(cm.validate_plugin_manifest(m), [])


if __name__ == "__main__":
    unittest.main()
