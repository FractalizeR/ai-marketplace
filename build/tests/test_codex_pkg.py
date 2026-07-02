"""Phase 3B-pkg: Codex bundle topology, authored configs, and packaging gates.

Everything builds into a tmp `--out` (dist/ is gitignored and ephemeral). The
plugin-manifest half of the stdlib mirror is pinned against the REAL
`validate_plugin.py` (skip-if-PyYAML-absent) run on the emitted bundle.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import _common
from _common import PLUGIN_ROOT, REPO_ROOT

from gates import check_codex_dispatch_template
import build
import bundle

HARNESS_ROOT = REPO_ROOT / "harness" / "codex"
PLUGIN_NAME = "fr-security-review"
MARKETPLACE_NAME = "fractalizer-marketplace"
_VALIDATE_PLUGIN = (Path.home() / ".codex" / "skills" / ".system"
                    / "plugin-creator" / "scripts" / "validate_plugin.py")


def _build_to(out: Path) -> int:
    return build.main(["--harness=codex", "--mode=write", "--out", str(out)])


class BundleTopologyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name) / "codex"
        self.assertEqual(_build_to(self.out), 0)
        self.plugin = self.out / "plugins" / PLUGIN_NAME
        self.core = self.plugin / "core"

    def tearDown(self):
        self._tmp.cleanup()

    def test_topology(self):
        for rel in (
            ".fr-codex-bundle",
            ".agents/plugins/marketplace.json",
            f"plugins/{PLUGIN_NAME}/.codex-plugin/plugin.json",
            f"plugins/{PLUGIN_NAME}/skills/security-project/SKILL.md",
            f"plugins/{PLUGIN_NAME}/skills/security-changes/SKILL.md",
            f"plugins/{PLUGIN_NAME}/core/bin",
            f"plugins/{PLUGIN_NAME}/core/checklists",
            f"plugins/{PLUGIN_NAME}/core/agents/security.md",
            f"plugins/{PLUGIN_NAME}/core/agents/security-recon.md",
            f"plugins/{PLUGIN_NAME}/core/agents/security-refute.md",
            f"plugins/{PLUGIN_NAME}/adapter.json",
            f"plugins/{PLUGIN_NAME}/INSTALL.md",
        ):
            self.assertTrue((self.out / rel).exists(), f"missing {rel}")

    def test_sentinel_at_bundle_root_not_plugin(self):
        # H2: _guard_out reads out/marker, so the sentinel must sit at the ROOT.
        self.assertTrue((self.out / ".fr-codex-bundle").is_file())
        self.assertFalse((self.plugin / ".fr-codex-bundle").exists())

    def test_core_not_double_nested(self):
        # H2-DS: bundle_core appends core/ itself — no core/core/.
        self.assertFalse((self.core / "core").exists())
        self.assertTrue((self.core / "bin").is_dir())

    def test_php_sandbox_bundled(self):
        self.assertTrue((self.core / "bin" / "recon" / "extract_php_metadata.php").is_file())

    def test_no_test_fixtures_or_bytecode(self):
        for p in self.core.rglob("*"):
            parts = p.relative_to(self.core).parts
            self.assertNotIn("tests", parts, f"test fixture leaked: {p}")
            self.assertNotIn("__pycache__", parts, f"bytecode leaked: {p}")

    def test_skills_carry_nonempty_frontmatter(self):
        for name in ("security-project", "security-changes"):
            text = (self.plugin / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\nname:"), f"{name} SKILL.md lacks skill frontmatter")

    def test_agents_have_no_leading_frontmatter(self):
        for name in ("security", "security-recon", "security-refute"):
            text = (self.core / "agents" / f"{name}.md").read_text(encoding="utf-8")
            self.assertFalse(text.startswith("---\n"), f"{name}.md carries frontmatter")

    def test_agent_filenames_match_readfollow_refs(self):
        # E-B6: every agents/<role>.md a dispatch template reads must be produced.
        produced = {p.name for p in (self.core / "agents").glob("*.md")}
        refs = set()
        for skill in (self.plugin / "skills").rglob("SKILL.md"):
            for m in _iter_refs(skill.read_text(encoding="utf-8")):
                refs.add(m)
        self.assertTrue(refs, "no read-follow refs found in skills")
        self.assertTrue(refs <= produced, f"dangling refs: {refs - produced}")

    def test_deterministic_across_builds(self):
        with tempfile.TemporaryDirectory() as d2:
            out2 = Path(d2) / "codex"
            self.assertEqual(_build_to(out2), 0)
            a = {p.relative_to(self.out): p.read_bytes()
                 for p in self.out.rglob("*") if p.is_file()}
            b = {p.relative_to(out2): p.read_bytes()
                 for p in out2.rglob("*") if p.is_file()}
            self.assertEqual(set(a), set(b))
            for rel in a:
                self.assertEqual(a[rel], b[rel], f"byte drift in {rel}")


def _iter_refs(text):
    import re
    for m in re.finditer(r"agents/(security(?:-recon|-refute)?\.md)", text):
        yield m.group(1)


class CodexConfigTests(unittest.TestCase):
    def test_authored_configs_valid(self):
        self.assertEqual(bundle.validate_codex_configs(HARNESS_ROOT), [])

    def test_unsafe_plugin_name_flagged(self):
        # HIGH: a path-traversal plugin name must be a gate problem, not a disk write.
        with tempfile.TemporaryDirectory() as d:
            broken = Path(d) / "harness"
            broken.mkdir()
            for name in ("plugin.json", "marketplace.json", "adapter.json", "INSTALL.md"):
                (broken / name).write_text(
                    (HARNESS_ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
            pj = json.loads((broken / "plugin.json").read_text(encoding="utf-8"))
            pj["name"] = "../../evil"
            (broken / "plugin.json").write_text(json.dumps(pj), encoding="utf-8")
            problems = bundle.validate_codex_configs(broken)
            self.assertTrue(any("filesystem-safe" in p for p in problems))
            self.assertIsNone(bundle.safe_plugin_name(broken))

    def test_adapter_entrypoint_is_skill(self):
        adapter = json.loads((HARNESS_ROOT / "adapter.json").read_text(encoding="utf-8"))
        self.assertEqual(adapter["entrypoint_kind"], "skill")

    def test_adapter_required_keys(self):
        adapter = json.loads((HARNESS_ROOT / "adapter.json").read_text(encoding="utf-8"))
        self.assertEqual(bundle._ADAPTER_REQUIRED - adapter.keys(), set())

    def test_adapter_worker_invocation_passes_codex_dispatch(self):
        adapter = json.loads((HARNESS_ROOT / "adapter.json").read_text(encoding="utf-8"))
        self.assertEqual(check_codex_dispatch_template(adapter["worker_invocation"]), [])

    def test_discovery_cmd_is_codex_debug_models(self):
        adapter = json.loads((HARNESS_ROOT / "adapter.json").read_text(encoding="utf-8"))
        self.assertEqual(adapter["model_discovery_cmd"], "codex debug models")


class InstallDocTests(unittest.TestCase):
    def setUp(self):
        self.text = (HARNESS_ROOT / "INSTALL.md").read_text(encoding="utf-8")

    def test_marketplace_add_and_plugin_add_present(self):
        for anchor in ("codex plugin marketplace add", "CORE_ROOT",
                       "codex debug models", "workspace-write"):
            self.assertIn(anchor, self.text, f"INSTALL.md missing {anchor!r}")

    def test_install_command_matches_marketplace_name(self):
        # Codex: INSTALL.md's `plugin add <plugin>@<marketplace>` must match the
        # authored marketplace.json name (a silent rename breaks the instruction).
        mp = json.loads((HARNESS_ROOT / "marketplace.json").read_text(encoding="utf-8"))
        self.assertEqual(mp["name"], MARKETPLACE_NAME)
        self.assertIn(f"codex plugin add {PLUGIN_NAME}@{MARKETPLACE_NAME}", self.text)


class WritePathGuardTests(unittest.TestCase):
    def test_guard_refuses_foreign_dir(self):
        with tempfile.TemporaryDirectory() as d:
            foreign = Path(d) / "notabundle"
            foreign.mkdir()
            (foreign / "precious.txt").write_text("keep me", encoding="utf-8")
            rc = build.main(["--harness=codex", "--mode=write", "--out", str(foreign)])
            self.assertEqual(rc, 2)
            self.assertTrue((foreign / "precious.txt").is_file())

    def test_guard_refuses_codex_source_tree(self):
        rc = build.main(["--harness=codex", "--mode=write", "--out", str(build._HARNESS_CODEX)])
        self.assertEqual(rc, 2)
        self.assertTrue((build._HARNESS_CODEX / "plugin.json").is_file(), "sources survived")

    def test_guard_refuses_opencode_sentinel(self):
        # L2: a codex write must not clobber an OpenCode bundle (foreign sentinel).
        with tempfile.TemporaryDirectory() as d:
            foreign = Path(d) / "opencode-bundle"
            foreign.mkdir()
            (foreign / bundle.BUNDLE_MARKER).write_text("x", encoding="utf-8")
            (foreign / "precious.txt").write_text("keep", encoding="utf-8")
            rc = build.main(["--harness=codex", "--mode=write", "--out", str(foreign)])
            self.assertEqual(rc, 2)
            self.assertTrue((foreign / "precious.txt").is_file())

    def test_guard_allows_prior_codex_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "codex"
            self.assertEqual(_build_to(out), 0)
            self.assertEqual(_build_to(out), 0)   # re-build over prior bundle (has marker)
            self.assertTrue((out / ".fr-codex-bundle").is_file())

    def test_guard_refuses_dist_root(self):
        # HIGH: writing AT dist/ would swap the whole dist/ (every harness) aside.
        with self.assertRaises(ValueError):
            build._guard_out(build._DIST_ROOT, marker=bundle.CODEX_BUNDLE_MARKER)

    def test_guard_refuses_foreign_sentinel_one_level_down(self):
        # HIGH: the other harness's marker may sit one level below --out (dist case).
        with tempfile.TemporaryDirectory() as d:
            container = Path(d) / "container"
            (container / "opencode").mkdir(parents=True)
            (container / "opencode" / bundle.BUNDLE_MARKER).write_text("x", encoding="utf-8")
            (container / "keep.txt").write_text("keep", encoding="utf-8")
            rc = build.main(["--harness=codex", "--mode=write", "--out", str(container)])
            self.assertEqual(rc, 2)
            self.assertTrue((container / "opencode" / bundle.BUNDLE_MARKER).is_file())

    def test_traversal_name_writes_nothing(self):
        # HIGH: a `../../evil` plugin name must not escape the staging dir on write.
        with tempfile.TemporaryDirectory() as d:
            broken = Path(d) / "harness"
            broken.mkdir()
            for name in ("plugin.json", "marketplace.json", "adapter.json", "INSTALL.md"):
                (broken / name).write_text(
                    (HARNESS_ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
            pj = json.loads((broken / "plugin.json").read_text(encoding="utf-8"))
            pj["name"] = "../../evil"
            (broken / "plugin.json").write_text(json.dumps(pj), encoding="utf-8")
            out = Path(d) / "codex"
            from unittest import mock
            with mock.patch.object(build, "_HARNESS_CODEX", broken):
                rc = build.main(["--harness=codex", "--mode=write", "--out", str(out)])
            self.assertEqual(rc, 1)
            self.assertFalse(out.exists())
            self.assertFalse((Path(d) / "evil").exists(), "traversal escaped staging")


@unittest.skipUnless(_VALIDATE_PLUGIN.is_file(), "codex validate_plugin.py not installed")
class RealValidatorOracleTests(unittest.TestCase):
    """DoD-5: pin the mirror against the REAL validator on the emitted bundle."""

    def test_real_validate_plugin_passes(self):
        try:
            import yaml  # noqa: F401 - the real validator needs it
        except ImportError:
            self.skipTest("PyYAML not available for the real validator")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "codex"
            self.assertEqual(_build_to(out), 0)
            plugin_root = out / "plugins" / PLUGIN_NAME
            proc = subprocess.run(
                [sys.executable, str(_VALIDATE_PLUGIN), str(plugin_root)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0,
                             f"real validate_plugin.py failed:\n{proc.stdout}\n{proc.stderr}")


if __name__ == "__main__":
    unittest.main()
