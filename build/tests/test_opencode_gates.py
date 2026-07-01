"""Structural gate tests + full OpenCode build integration (no-leak/coverage/determinism)."""

import unittest

import _common
from _common import ARTIFACTS, BUILD_DIR, read

from gates import check_opencode_output, check_dispatch_template
from prose_coupling import load_pins, pins_for
from extract import extract, CAT_TASK
from sections import partition_sections, attach_segments, detect_coupling
from adapters import get_adapter
from build import render_opencode_artifact, opencode_out_path


class GateUnitTests(unittest.TestCase):
    def test_clean_text_passes(self):
        self.assertEqual(check_opencode_output("# ok\n$ARGUMENTS and ${CORE_ROOT}\n"), [])

    def test_core_root_leak(self):
        self.assertTrue(check_opencode_output("x ${CLAUDE_PLUGIN_ROOT} y"))

    def test_task_paren_leak(self):
        self.assertTrue(check_opencode_output('Task(subagent_type="x", prompt="""y""")'))

    def test_task_bare_leak(self):
        self.assertTrue(check_opencode_output('Task subagent_type=security-refute prompt="z"'))

    def test_auq_leak(self):
        self.assertTrue(check_opencode_output("ask via AskUserQuestion now"))

    def test_mcp_leak(self):
        self.assertTrue(check_opencode_output("use mcp__phpstorm__search_symbol here"))

    def test_allowed_tools_in_frontmatter_flagged(self):
        self.assertTrue(check_opencode_output("---\nallowed-tools:\n  - Read\n---\nbody\n"))

    def test_allowed_tools_in_body_ok(self):
        self.assertEqual(
            check_opencode_output("---\ndescription: x\n---\nnot in allowed-tools, use Grep\n"),
            [],
        )

    def test_xref_file_ref_flagged(self):
        self.assertTrue(check_opencode_output("see security-project.md step 4"))

    def test_dispatch_template_structural_invariants(self):
        # Each dispatch template must wire `opencode run`, `-m`, and `--agent`.
        self.assertTrue(check_dispatch_template("just prose, no dispatch"))
        self.assertTrue(check_dispatch_template("opencode run -m high"))          # no --agent
        self.assertTrue(check_dispatch_template("opencode run --agent security"))  # no -m
        self.assertEqual(
            check_dispatch_template("opencode run -m high --agent security"), [])


class FullBuildIntegrationTests(unittest.TestCase):
    """These require the 12 section templates to exist (Phase 2B-core step 3)."""

    def setUp(self):
        self.adapter = get_adapter("opencode")
        self.pins = load_pins(BUILD_DIR / "PROSE_COUPLING.md")

    def _coupled_sections(self, path, kind):
        text = read(path)
        segs = extract(text, kind)
        task_spans = [s.span for s in segs if s.category == CAT_TASK]
        secs = partition_sections(text, task_spans=task_spans)
        secs = attach_segments(secs, segs)
        file_rel = f"{path.parent.name}/{path.name}"
        secs = detect_coupling(secs, [p.pinned for p in pins_for(self.pins, file_rel)])
        return [s for s in secs if s.is_coupled]

    def test_all_artifacts_pass_gates(self):
        for path, kind in ARTIFACTS.items():
            with self.subTest(artifact=path.name):
                out = render_opencode_artifact(path, self.adapter, self.pins)
                self.assertEqual(check_opencode_output(out), [], f"gate violations in {path.name}")

    def test_render_is_deterministic(self):
        for path, kind in ARTIFACTS.items():
            with self.subTest(artifact=path.name):
                a = render_opencode_artifact(path, self.adapter, self.pins)
                b = render_opencode_artifact(path, self.adapter, self.pins)
                self.assertEqual(a, b)

    def test_every_coupled_section_has_a_template(self):
        for path, kind in ARTIFACTS.items():
            for sec in self._coupled_sections(path, kind):
                with self.subTest(artifact=path.name, anchor=sec.section_anchor):
                    out = self.adapter.render_section(
                        sec, __import__("adapters").RenderContext(path.stem))
                    self.assertTrue(out.strip())

    def test_no_orphan_templates(self):
        # Every template file under sections/ must correspond to a coupled section.
        sections_root = BUILD_DIR.parent / "harness" / "opencode" / "sections"
        if not sections_root.is_dir():
            self.skipTest("no templates yet")
        valid = set()
        for path, kind in ARTIFACTS.items():
            for sec in self._coupled_sections(path, kind):
                valid.add((path.stem, sec.section_anchor))
        for tpl in sections_root.rglob("*.md"):
            key = (tpl.parent.name, tpl.stem)
            with self.subTest(template=str(tpl.relative_to(sections_root))):
                self.assertIn(key, valid, f"orphan template {tpl}")

    def test_no_sibling_md_ref_survives_in_any_artifact(self):
        import re
        md_ref = re.compile(r"\b(?:agents/)?security(?:-project|-changes|-recon|-refute)?\.md\b")
        for path, kind in ARTIFACTS.items():
            with self.subTest(artifact=path.name):
                out = render_opencode_artifact(path, self.adapter, self.pins)
                self.assertIsNone(md_ref.search(out))

    def test_build_guard_rejects_dispatch_template_without_opencode_run(self):
        proj = next(p for p in ARTIFACTS if p.name == "security-project.md")
        # Fake loader returns a dispatch template missing `opencode run`.
        def bad_loader(basename, anchor):
            return "### x\n\njust prose, no dispatch primitive\n"
        broken = get_adapter("opencode").__class__(template_loader=bad_loader)
        with self.assertRaises(AssertionError):
            render_opencode_artifact(proj, broken, self.pins)

    def test_dispatch_templates_wire_opencode_run(self):
        # recon / worker / refute templates must mention `opencode run`.
        dispatch_anchors = {
            "4-recon-phase", "5-recon-phase",
            "8-parallel-worker-launch", "10-parallel-worker-launch-in-mode-changes",
            "11-5-1-launching-the-refute-wave", "12-5-1-launching-the-refute-wave",
        }
        for path, kind in ARTIFACTS.items():
            for sec in self._coupled_sections(path, kind):
                if sec.section_anchor in dispatch_anchors:
                    with self.subTest(anchor=sec.section_anchor):
                        out = self.adapter.render_section(
                            sec, __import__("adapters").RenderContext(path.stem))
                        self.assertEqual(check_dispatch_template(out), [])


if __name__ == "__main__":
    unittest.main()
