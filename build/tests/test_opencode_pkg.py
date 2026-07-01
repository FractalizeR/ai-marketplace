"""Phase 2B-pkg: OpenCode bundle, authored configs, and packaging gates.

Everything builds into a tmp `--out` (dist/ is gitignored and ephemeral), so no
test touches the real dist/. The engine copy is asserted by *properties* (no
fixtures/bytecode, sandbox present, every runtime module included), never an
exact file count, so unrelated bin/ growth does not churn these tests.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _common
from _common import PLUGIN_ROOT, REPO_ROOT

from gates import check_dispatch_template, check_opencode_output
import build
import bundle

HARNESS_ROOT = REPO_ROOT / "harness" / "opencode"


def _build_to(out: Path) -> int:
    return build.main(["--harness=opencode", "--mode=write", "--out", str(out)])


class BundleManifestTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name) / "bundle"
        self.assertEqual(_build_to(self.out), 0)
        self.core = self.out / "core"

    def tearDown(self):
        self._tmp.cleanup()

    def test_topology(self):
        for rel in (
            "core/bin", "core/checklists",
            "commands/security-project.md", "commands/security-changes.md",
            "agents/security.md", "agents/security-recon.md", "agents/security-refute.md",
            "opencode.json", "adapter.json", "INSTALL.md",
        ):
            self.assertTrue((self.out / rel).exists(), f"missing {rel}")

    def test_php_sandbox_bundled(self):
        self.assertTrue((self.core / "bin" / "recon" / "extract_php_metadata.php").is_file())

    def test_no_test_fixtures_or_bytecode(self):
        for p in self.core.rglob("*"):
            parts = p.relative_to(self.core).parts
            self.assertNotIn("tests", parts, f"test fixture leaked: {p}")
            self.assertNotIn("__pycache__", parts, f"bytecode leaked: {p}")

    def test_every_runtime_bin_module_bundled(self):
        # Every non-test .py under bin/ must be present in the bundle.
        src_bin = PLUGIN_ROOT / "bin"
        for src in src_bin.rglob("*.py"):
            rel = src.relative_to(src_bin)
            if "tests" in rel.parts or "__pycache__" in rel.parts:
                continue
            with self.subTest(module=str(rel)):
                self.assertTrue((self.core / "bin" / rel).is_file(), f"missing {rel}")

    def test_deterministic_across_builds(self):
        with tempfile.TemporaryDirectory() as d2:
            out2 = Path(d2) / "bundle"
            self.assertEqual(_build_to(out2), 0)
            a = {p.relative_to(self.out): p.read_bytes()
                 for p in self.out.rglob("*") if p.is_file()}
            b = {p.relative_to(out2): p.read_bytes()
                 for p in out2.rglob("*") if p.is_file()}
            self.assertEqual(set(a), set(b))
            for rel in a:
                self.assertEqual(a[rel], b[rel], f"byte drift in {rel}")


class OutputTopologyTests(unittest.TestCase):
    def test_command_goes_flat_to_commands(self):
        out = Path("/x")
        cmd = PLUGIN_ROOT / "commands" / "security-project.md"
        self.assertEqual(build.opencode_out_path(cmd, out), out / "commands" / "security-project.md")

    def test_agent_goes_flat_to_agents(self):
        out = Path("/x")
        agent = PLUGIN_ROOT / "agents" / "security.md"
        self.assertEqual(build.opencode_out_path(agent, out), out / "agents" / "security.md")

    def test_agent_files_carry_description_frontmatter(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "bundle"
            self.assertEqual(_build_to(out), 0)
            for name in ("security", "security-recon", "security-refute"):
                text = (out / "agents" / f"{name}.md").read_text(encoding="utf-8")
                self.assertTrue(text.startswith("---\ndescription:"),
                                f"{name}.md lacks a description frontmatter")


class AdapterConfigTests(unittest.TestCase):
    def setUp(self):
        self.adapter = json.loads((HARNESS_ROOT / "adapter.json").read_text(encoding="utf-8"))

    def test_required_keys_present(self):
        self.assertEqual(bundle._ADAPTER_REQUIRED - self.adapter.keys(), set())

    def test_entrypoint_is_command(self):
        self.assertEqual(self.adapter["entrypoint_kind"], "command")

    def test_fanout_is_external_process(self):
        self.assertEqual(self.adapter["fanout"], "external_process")

    def test_worker_invocation_passes_dispatch_check(self):
        self.assertEqual(check_dispatch_template(self.adapter["worker_invocation"]), [])

    def test_worker_invocation_carries_full_placeholder_set(self):
        # The placeholder set mirrors the section templates' --worker-cmd-template
        # (mode=, not capture= — the dispatcher captures stdout via --capture-dir).
        wi = self.adapter["worker_invocation"]
        for field in ("{model}", "{review_root}", "{project_root}",
                      "{core_root}", "{slice_id}", "{slice_config}", "{mode}"):
            self.assertIn(field, wi, f"worker_invocation dropped {field}")
        self.assertNotIn("{capture}", wi, "worker_invocation should not claim {capture}")

    def test_discovery_cmd_is_opencode_models(self):
        self.assertEqual(self.adapter["model_discovery_cmd"], "opencode models")


class OpencodeConfigTests(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((HARNESS_ROOT / "opencode.json").read_text(encoding="utf-8"))

    def test_has_schema(self):
        self.assertIn("$schema", self.cfg)

    def test_permission_has_concrete_keys(self):
        perm = self.cfg["permission"]
        for key in bundle._PERM_REQUIRED:
            self.assertIn(key, perm, f"permission missing {key!r}")

    def test_task_denied_encodes_ad4(self):
        self.assertEqual(self.cfg["permission"]["task"], "deny")

    def test_network_denied(self):
        self.assertEqual(self.cfg["permission"]["webfetch"], "deny")
        self.assertEqual(self.cfg["permission"]["websearch"], "deny")


class InstallDocTests(unittest.TestCase):
    def setUp(self):
        self.text = (HARNESS_ROOT / "INSTALL.md").read_text(encoding="utf-8")

    def test_mentions_install_targets_and_setup(self):
        for anchor in (".opencode/commands", ".opencode/agents", "CORE_ROOT",
                       "OPENCODE_CONFIG", "opencode models", "external_directory"):
            self.assertIn(anchor, self.text, f"INSTALL.md missing {anchor!r}")


class ValidateStaticConfigsTests(unittest.TestCase):
    def test_authored_configs_are_valid(self):
        self.assertEqual(bundle.validate_static_configs(HARNESS_ROOT), [])

    def test_wrong_entrypoint_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            self._seed(d, adapter_override={"entrypoint_kind": "skill"})
            problems = bundle.validate_static_configs(Path(d))
            self.assertTrue(any("entrypoint_kind" in p for p in problems))

    def test_missing_permission_key_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            self._seed(d, opencode_perm={"external_directory": "allow", "task": "deny"})
            problems = bundle.validate_static_configs(Path(d))
            self.assertTrue(any("permission missing key" in p for p in problems))

    def test_task_not_denied_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            perm = {k: "allow" for k in bundle._PERM_REQUIRED}  # task=allow
            self._seed(d, opencode_perm=perm)
            problems = bundle.validate_static_configs(Path(d))
            self.assertTrue(any("task must be 'deny'" in p for p in problems))

    def test_network_allow_flagged(self):
        # A stray webfetch:allow must be caught (offline-posture guarantee).
        with tempfile.TemporaryDirectory() as d:
            perm = {k: "deny" for k in bundle._PERM_REQUIRED}
            perm["webfetch"] = "allow"
            self._seed(d, opencode_perm=perm)
            problems = bundle.validate_static_configs(Path(d))
            self.assertTrue(any("webfetch must be 'deny'" in p for p in problems))

    def test_malformed_json_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "adapter.json").write_text("{not json", encoding="utf-8")
            (Path(d) / "opencode.json").write_text("{}", encoding="utf-8")
            problems = bundle.validate_static_configs(Path(d))
            self.assertTrue(any("unreadable/invalid" in p for p in problems))

    def _seed(self, d, *, adapter_override=None, opencode_perm=None):
        adapter = json.loads((HARNESS_ROOT / "adapter.json").read_text(encoding="utf-8"))
        adapter.update(adapter_override or {})
        (Path(d) / "adapter.json").write_text(json.dumps(adapter), encoding="utf-8")
        cfg = {"$schema": "x", "permission": opencode_perm
               if opencode_perm is not None
               else {k: ("deny" if k in ("task", "webfetch", "websearch") else "allow")
                     for k in bundle._PERM_REQUIRED}}
        (Path(d) / "opencode.json").write_text(json.dumps(cfg), encoding="utf-8")


class WritePathTests(unittest.TestCase):
    def test_fail_closed_on_broken_config(self):
        # Point config validation at a dir with a broken adapter.json; write must
        # return 1 and never create the out bundle.
        with tempfile.TemporaryDirectory() as d:
            broken = Path(d) / "harness"
            broken.mkdir()
            (broken / "adapter.json").write_text('{"entrypoint_kind": "skill"}', encoding="utf-8")
            (broken / "opencode.json").write_text('{"permission": {}}', encoding="utf-8")
            out = Path(d) / "bundle"
            with mock.patch.object(build, "_HARNESS_OPENCODE", broken):
                rc = build.main(["--harness=opencode", "--mode=write", "--out", str(out)])
            self.assertEqual(rc, 1)
            self.assertFalse(out.exists(), "leaky partial bundle written despite bad config")

    def test_guard_refuses_foreign_dir(self):
        with tempfile.TemporaryDirectory() as d:
            foreign = Path(d) / "notabundle"
            foreign.mkdir()
            (foreign / "precious.txt").write_text("keep me", encoding="utf-8")
            rc = build.main(["--harness=opencode", "--mode=write", "--out", str(foreign)])
            self.assertEqual(rc, 2)  # ValueError → CLI boundary exit 2
            self.assertTrue((foreign / "precious.txt").is_file(), "guard let a foreign dir be clobbered")

    def test_guard_refuses_foreign_dir_with_adapter_json(self):
        # Regression: adapter.json is a common filename and is a git-tracked SOURCE
        # file — it must NOT mark a foreign dir as a clobber-safe bundle.
        with tempfile.TemporaryDirectory() as d:
            foreign = Path(d) / "someones-tool"
            foreign.mkdir()
            (foreign / "adapter.json").write_text("{}", encoding="utf-8")
            (foreign / "precious.txt").write_text("keep me", encoding="utf-8")
            rc = build.main(["--harness=opencode", "--mode=write", "--out", str(foreign)])
            self.assertEqual(rc, 2)
            self.assertTrue((foreign / "precious.txt").is_file())

    def test_guard_refuses_authored_source_tree(self):
        rc = build.main(["--harness=opencode", "--mode=write",
                         "--out", str(build._HARNESS_OPENCODE)])
        self.assertEqual(rc, 2)
        self.assertTrue((build._HARNESS_OPENCODE / "sections").is_dir(), "sources survived")

    def test_artifact_incompatible_with_write(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "bundle"
            rc = build.main(["--harness=opencode", "--mode=write", "--out", str(out),
                             "--artifact", str(PLUGIN_ROOT / "agents" / "security.md")])
            self.assertEqual(rc, 2)
            self.assertFalse(out.exists())

    def test_guard_allows_prior_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "bundle"
            self.assertEqual(_build_to(out), 0)          # first build
            self.assertEqual(_build_to(out), 0)          # re-build over prior bundle (has marker)
            self.assertTrue((out / "adapter.json").is_file())

    def test_guard_unit_allows_nonexistent_and_dist(self):
        with tempfile.TemporaryDirectory() as d:
            build._guard_out(Path(d) / "does-not-exist")  # no raise
        # under repo dist/ is always ours
        build._guard_out(build._DIST_ROOT / "opencode")   # no raise even if absent/present


class BundleWalkFilterTests(unittest.TestCase):
    def test_excludes_fixtures_bytecode_and_junk(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            (src / "keep.py").write_text("x", encoding="utf-8")
            (src / "sub").mkdir()
            (src / "sub" / "also.py").write_text("y", encoding="utf-8")
            (src / "tests").mkdir()
            (src / "tests" / "fixture.py").write_text("z", encoding="utf-8")
            (src / "__pycache__").mkdir()
            (src / "__pycache__" / "c.pyc").write_text("b", encoding="utf-8")
            (src / "stray.pyc").write_text("b", encoding="utf-8")
            (src / ".DS_Store").write_text("junk", encoding="utf-8")
            got = {rel.as_posix() for _, rel in bundle._iter_bundled_files(src)}
            self.assertEqual(got, {"keep.py", "sub/also.py"})


class BundleRegressionTests(unittest.TestCase):
    def test_no_leak_in_built_command_and_agent_files(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "bundle"
            self.assertEqual(_build_to(out), 0)
            for sub in ("commands", "agents"):
                for f in (out / sub).glob("*.md"):
                    with self.subTest(artifact=f.name):
                        self.assertEqual(check_opencode_output(f.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main()
