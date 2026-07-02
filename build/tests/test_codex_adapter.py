"""CodexAdapter token + section rendering tests (parallel to test_opencode_adapter)."""

import unittest

import _common  # noqa: F401  (sys.path side effect)

from segments import RenderMode, Segment, Tier
from sections import Section
from extract import (
    CAT_AGENT_FRONTMATTER,
    CAT_ARGS,
    CAT_AUQ,
    CAT_CMD_FRONTMATTER,
    CAT_CORE_ROOT,
    CAT_MCP,
    CAT_TASK,
)
from adapters import (
    CodexAdapter,
    CODEX_CORE_ROOT,
    CODEX_ARGS_PHRASE,
    MCP_PHRASE,
    AUQ_PHRASE,
    RenderContext,
    _strip_codex_xrefs,
)


def _seg(cat, text, span=(0, 0), attrs=None):
    s0, s1 = span if span != (0, 0) else (0, len(text))
    return Segment(cat, Tier.ACTIVE_PARSED, text, (s0, s1), RenderMode.ECHO, attrs or {})


class TokenRenderTests(unittest.TestCase):
    def setUp(self):
        self.a = CodexAdapter(template_loader=lambda b, s: f"TPL[{b}/{s}]")

    def test_core_root(self):
        self.assertEqual(
            self.a.render_segment(_seg(CAT_CORE_ROOT, "${CLAUDE_PLUGIN_ROOT}")),
            CODEX_CORE_ROOT,
        )

    def test_args_renders_neutral_phrase_not_identity(self):
        # Diverges from OpenCode: Codex has no $ARGUMENTS substitution.
        out = self.a.render_segment(_seg(CAT_ARGS, "$ARGUMENTS"))
        self.assertEqual(out, CODEX_ARGS_PHRASE)
        self.assertNotIn("$ARGUMENTS", out)

    def test_agent_frontmatter_stripped(self):
        out = self.a.render_segment(
            _seg(CAT_AGENT_FRONTMATTER, "---\nname: security\n---\n",
                 attrs={"description": '"deep review"'}))
        self.assertEqual(out, "")

    def test_mcp_phrase(self):
        self.assertEqual(
            self.a.render_segment(_seg(CAT_MCP, "mcp__phpstorm__search_symbol")),
            MCP_PHRASE,
        )

    def test_auq_prose_mention(self):
        self.assertEqual(
            self.a.render_segment(_seg(CAT_AUQ, "AskUserQuestion",
                                       attrs={"occurrence_kind": "prose-mention"})),
            AUQ_PHRASE,
        )

    def test_auq_labeled_block_raises(self):
        with self.assertRaises(AssertionError):
            self.a.render_segment(_seg(CAT_AUQ, "AskUserQuestion",
                                       attrs={"occurrence_kind": "labeled-block"}))

    def test_task_block_raises(self):
        with self.assertRaises(AssertionError):
            self.a.render_segment(_seg(CAT_TASK, 'Task(subagent_type="x", prompt="""y""")'))


class SkillFrontmatterTests(unittest.TestCase):
    """The skill `name` reaches the synth via instance state even on the _splice
    path (M2-DS): the frontmatter lives in the uncoupled _preamble section."""

    def _render_preamble(self, artifact_basename, desc='"hi"'):
        fm = f'---\ndescription: {desc}\n---\n'
        text = fm + "body\n"
        seg = _seg(CAT_CMD_FRONTMATTER, fm, span=(0, len(fm)), attrs={"description": desc})
        sec = Section(0, None, "_preamble", (0, len(text)), text, inner_segments=[seg])
        a = CodexAdapter(template_loader=lambda b, s: "X")
        return a.render_section(sec, RenderContext(artifact_basename))

    def test_name_from_ctx_reaches_splice_frontmatter(self):
        out = self._render_preamble("security-project")
        self.assertTrue(out.startswith("---\nname: security-project\ndescription: "))
        self.assertIn('"hi"', out)
        self.assertIn("\n---\n", out)
        self.assertTrue(out.endswith("body\n"))

    def test_description_unwrapped_and_quoted(self):
        out = self._render_preamble("security-changes", desc='"a "b" c"')
        line = [l for l in out.splitlines() if l.startswith("description:")][0]
        self.assertTrue(line.startswith('description: "'))
        self.assertTrue(line.endswith('"'))
        self.assertIn('\\"', line)          # embedded quote escaped
        self.assertNotIn('\\\\', line)


class SectionRenderTests(unittest.TestCase):
    def test_neutral_splice(self):
        text = "A ${CLAUDE_PLUGIN_ROOT} B"
        token = Segment(CAT_CORE_ROOT, Tier.ACTIVE_PARSED, "${CLAUDE_PLUGIN_ROOT}",
                        (2, 23), RenderMode.CANONICAL, {})
        sec = Section(2, "H", "h", (0, len(text)), text, inner_segments=[token])
        a = CodexAdapter(template_loader=lambda b, s: "X")
        self.assertEqual(a.render_section(sec, RenderContext("x")),
                         f"A {CODEX_CORE_ROOT} B")

    def test_coupled_uses_template(self):
        sec = Section(3, "H", "8-parallel-worker-launch", (0, 1), "x",
                      pins=["pin"], is_coupled=True)
        a = CodexAdapter(template_loader=lambda b, s: f"CODEX_TPL[{b}/{s}]")
        out = a.render_section(sec, RenderContext("security-project"))
        self.assertEqual(out, "CODEX_TPL[security-project/8-parallel-worker-launch]")


class XrefStripTests(unittest.TestCase):
    """C1: strip ONLY orchestrator refs; PRESERVE agent read-follow refs (real
    bundled files a codex worker opens)."""

    def test_strips_orchestrator_refs(self):
        self.assertEqual(_strip_codex_xrefs("see security-project.md now"),
                         "see security-project now")
        self.assertEqual(_strip_codex_xrefs("see security-changes.md now"),
                         "see security-changes now")

    def test_preserves_agent_read_follow_refs(self):
        for ref in ("agents/security.md", "agents/security-recon.md",
                    "agents/security-refute.md", "security-recon.md",
                    "security-refute.md"):
            with self.subTest(ref=ref):
                self.assertIn(ref, _strip_codex_xrefs(f"read and follow {ref}"))

    def test_preserves_unrelated_md(self):
        out = _strip_codex_xrefs("read CONTEXT.md and README.md")
        self.assertIn("CONTEXT.md", out)
        self.assertIn("README.md", out)

    def test_no_fixed_length_lookbehind_blindspot(self):
        # A fixed-length `(?<!agents/)` would spuriously spare an orchestrator ref
        # sitting behind a path segment that happens to end in "agents/".
        self.assertEqual(_strip_codex_xrefs("subagents/security-project.md"),
                         "subagents/security-project")

    def test_word_char_prefix_not_stripped(self):
        # A longer token that merely ends in "security-project.md" is left intact.
        self.assertEqual(_strip_codex_xrefs("xsecurity-project.md"),
                         "xsecurity-project.md")


if __name__ == "__main__":
    unittest.main()
