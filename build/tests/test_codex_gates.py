"""Codex structural gate tests + full Codex build integration."""

import unittest

import _common
from _common import ARTIFACTS, BUILD_DIR, read

from gates import check_codex_output, check_codex_dispatch_template
from prose_coupling import load_pins, pins_for
from extract import extract, CAT_TASK, ArtifactKind
from sections import partition_sections, attach_segments, detect_coupling
from adapters import get_adapter, RenderContext
from build import render_codex_artifact


CLEAN_SKILL = '---\nname: security-project\ndescription: "audit"\n---\nbody with ${FR_SECURITY_CORE_ROOT}\n'


class OutputGateUnitTests(unittest.TestCase):
    def test_clean_skill_passes(self):
        self.assertEqual(check_codex_output(CLEAN_SKILL, is_skill=True), [])

    def test_args_is_forbidden_for_codex(self):
        # Diverges from OpenCode (which keeps $ARGUMENTS).
        self.assertTrue(check_codex_output(CLEAN_SKILL.replace("body", "$ARGUMENTS"),
                                           is_skill=True))

    def test_core_root_leak(self):
        self.assertTrue(check_codex_output("x ${CLAUDE_PLUGIN_ROOT} y", is_skill=False))

    def test_task_leak(self):
        self.assertTrue(check_codex_output('Task(subagent_type="x", prompt="""y""")',
                                           is_skill=False))
        self.assertTrue(check_codex_output('Task subagent_type=security-refute prompt="z"',
                                           is_skill=False))

    def test_auq_leak(self):
        self.assertTrue(check_codex_output("ask via AskUserQuestion now", is_skill=False))

    def test_mcp_leak(self):
        self.assertTrue(check_codex_output("use mcp__phpstorm__search_symbol", is_skill=False))

    def test_skill_missing_frontmatter_flagged(self):
        self.assertTrue(check_codex_output("no frontmatter here\n", is_skill=True))

    def test_skill_empty_description_flagged(self):
        # M2-Claude: a synthesized-but-empty description passes 3A silently unless the
        # gate positively asserts non-empty — it would then fail 3B validate_plugin.
        block = '---\nname: security-project\ndescription: ""\n---\nbody\n'
        problems = check_codex_output(block, is_skill=True)
        self.assertTrue(any("description" in p for p in problems))

    def test_skill_empty_name_flagged(self):
        block = '---\nname: \ndescription: "x"\n---\nbody\n'
        problems = check_codex_output(block, is_skill=True)
        self.assertTrue(any("name" in p for p in problems))

    def test_skill_allowed_tools_key_flagged(self):
        block = '---\nname: security-project\ndescription: "x"\nallowed-tools:\n  - Read\n---\nb\n'
        self.assertTrue(check_codex_output(block, is_skill=True))

    def test_agent_with_frontmatter_flagged(self):
        # E-C3: worker agent prose must be stripped of its Claude frontmatter.
        self.assertTrue(check_codex_output("---\nname: security\n---\nbody\n", is_skill=False))

    def test_agent_without_frontmatter_passes(self):
        self.assertEqual(check_codex_output("You are a worker.\n", is_skill=False), [])

    def test_orchestrator_xref_flagged(self):
        self.assertTrue(check_codex_output("see security-project.md step 4", is_skill=False))
        self.assertTrue(check_codex_output("see security-changes.md step 4", is_skill=False))

    def test_agent_read_follow_ref_allowed(self):
        # agents/*.md and bare role refs are REAL bundled files → not a violation.
        for ref in ("read and follow agents/security.md",
                    "follow agents/security-recon.md",
                    "follow agents/security-refute.md"):
            with self.subTest(ref=ref):
                self.assertEqual(check_codex_output(f"body {ref}\n", is_skill=False), [])


class DispatchTemplateGateTests(unittest.TestCase):
    GOOD_WORKER = ('codex exec -m {model} -C {project_root} -s workspace-write '
                   '--add-dir {review_root} --skip-git-repo-check -o {capture} '
                   '"read and follow {core_root}/agents/security.md then audit"')
    GOOD_RECON = ('codex exec -m <HIGH_TIER> -C <PROJECT_ROOT> -s workspace-write '
                  '--add-dir <REVIEW_ROOT> --skip-git-repo-check '
                  '-o <REVIEW_ROOT>/captures/recon.capture.txt '
                  '"read and follow <FR_SECURITY_CORE_ROOT>/agents/security-recon.md"')

    def test_good_worker_passes(self):
        self.assertEqual(check_codex_dispatch_template(self.GOOD_WORKER), [])

    def test_good_recon_passes(self):
        self.assertEqual(check_codex_dispatch_template(self.GOOD_RECON), [])

    def test_missing_codex_exec(self):
        self.assertTrue(check_codex_dispatch_template(
            self.GOOD_WORKER.replace("codex exec", "run")))

    def test_missing_model_flag(self):
        self.assertTrue(check_codex_dispatch_template(
            self.GOOD_WORKER.replace("-m {model}", "")))

    def test_missing_add_dir(self):
        self.assertTrue(check_codex_dispatch_template(
            self.GOOD_WORKER.replace("--add-dir {review_root} ", "")))

    def test_missing_output_capture(self):
        self.assertTrue(check_codex_dispatch_template(
            self.GOOD_WORKER.replace("-o {capture} ", "")))

    def test_missing_read_follow_ref(self):
        self.assertTrue(check_codex_dispatch_template(
            self.GOOD_WORKER.replace("{core_root}/agents/security.md", "somewhere")))

    def test_dollar_core_root_agents_flagged(self):
        # E-C10: ${FR_SECURITY_CORE_ROOT}/agents in a fan-out template = str.format KeyError.
        bad = self.GOOD_WORKER.replace("{core_root}/agents/security.md",
                                       "${FR_SECURITY_CORE_ROOT}/agents/security.md")
        self.assertTrue(check_codex_dispatch_template(bad))


class FullBuildIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("codex")
        self.pins = load_pins(BUILD_DIR / "PROSE_COUPLING.md")

    def _coupled_sections(self, path):
        text = read(path)
        kind = ARTIFACTS[path]
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
                out = render_codex_artifact(path, self.adapter, self.pins)
                is_skill = kind is ArtifactKind.COMMAND
                self.assertEqual(check_codex_output(out, is_skill=is_skill), [],
                                 f"gate violations in {path.name}")

    def test_render_is_deterministic(self):
        for path in ARTIFACTS:
            with self.subTest(artifact=path.name):
                a = render_codex_artifact(path, self.adapter, self.pins)
                b = render_codex_artifact(path, self.adapter, self.pins)
                self.assertEqual(a, b)

    def test_every_coupled_section_has_a_template(self):
        for path in ARTIFACTS:
            for sec in self._coupled_sections(path):
                with self.subTest(artifact=path.name, anchor=sec.section_anchor):
                    out = self.adapter.render_section(sec, RenderContext(path.stem))
                    self.assertTrue(out.strip())

    def test_no_orphan_templates(self):
        sections_root = BUILD_DIR.parent / "harness" / "codex" / "sections"
        valid = set()
        for path in ARTIFACTS:
            for sec in self._coupled_sections(path):
                valid.add((path.stem, sec.section_anchor))
        for tpl in sections_root.rglob("*.md"):
            key = (tpl.parent.name, tpl.stem)
            with self.subTest(template=str(tpl.relative_to(sections_root))):
                self.assertIn(key, valid, f"orphan template {tpl}")

    def test_dispatch_templates_wire_codex_exec(self):
        dispatch_anchors = {
            "4-recon-phase", "5-recon-phase",
            "8-parallel-worker-launch", "10-parallel-worker-launch-in-mode-changes",
            "11-5-1-launching-the-refute-wave", "12-5-1-launching-the-refute-wave",
        }
        for path in ARTIFACTS:
            for sec in self._coupled_sections(path):
                if sec.section_anchor in dispatch_anchors:
                    with self.subTest(anchor=sec.section_anchor):
                        out = self.adapter.render_section(sec, RenderContext(path.stem))
                        self.assertEqual(check_codex_dispatch_template(out), [])

    def test_build_guard_rejects_dispatch_template_without_codex_exec(self):
        proj = next(p for p in ARTIFACTS if p.name == "security-project.md")

        def bad_loader(basename, anchor):
            return "### x\n\njust prose, no dispatch primitive\n"

        broken = get_adapter("codex").__class__(template_loader=bad_loader)
        with self.assertRaises(AssertionError):
            render_codex_artifact(proj, broken, self.pins)


if __name__ == "__main__":
    unittest.main()
