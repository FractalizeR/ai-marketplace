"""OpenCodeAdapter token + section rendering tests."""

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
    OpenCodeAdapter,
    OPENCODE_CORE_ROOT,
    OPENCODE_AUQ_PHRASE,
    OPENCODE_MCP_PHRASE,
    RenderContext,
)


def _seg(cat, text, span=(0, 0), attrs=None):
    s0, s1 = span if span != (0, 0) else (0, len(text))
    return Segment(cat, Tier.ACTIVE_PARSED, text, (s0, s1), RenderMode.ECHO, attrs or {})


class TokenRenderTests(unittest.TestCase):
    def setUp(self):
        self.a = OpenCodeAdapter(template_loader=lambda b, s: f"TPL[{b}/{s}]")

    def test_core_root(self):
        self.assertEqual(self.a.render_segment(_seg(CAT_CORE_ROOT, "${CLAUDE_PLUGIN_ROOT}")),
                         OPENCODE_CORE_ROOT)

    def test_args_identity(self):
        self.assertEqual(self.a.render_segment(_seg(CAT_ARGS, "$ARGUMENTS")), "$ARGUMENTS")

    def test_agent_frontmatter_synthesizes_description(self):
        # OpenCode agents need a `description` to register under --agent (model comes
        # from the dispatcher -m), so the block is synthesized, not stripped.
        out = self.a.render_segment(
            _seg(CAT_AGENT_FRONTMATTER, "---\n...\n---\n", attrs={"description": '"deep review"'}))
        self.assertTrue(out.startswith("---\ndescription: "))
        self.assertIn("deep review", out)
        self.assertTrue(out.endswith("---\n"))

    def test_mcp_phrase(self):
        self.assertEqual(self.a.render_segment(_seg(CAT_MCP, "mcp__phpstorm__search_symbol")),
                         OPENCODE_MCP_PHRASE)

    def test_cmd_frontmatter_synth(self):
        out = self.a.render_segment(
            _seg(CAT_CMD_FRONTMATTER, "---\n...\n---\n", attrs={"description": '"hi"'}))
        self.assertTrue(out.startswith("---\ndescription: "))
        self.assertIn('"hi"', out)
        self.assertTrue(out.endswith("---\n"))

    def test_cmd_frontmatter_caps_1024(self):
        long = '"' + "word " * 400 + '"'
        out = self.a.render_segment(
            _seg(CAT_CMD_FRONTMATTER, "x", attrs={"description": long}))
        desc_line = out.splitlines()[1]
        self.assertLessEqual(len(desc_line) - len("description: "), 1024)

    def test_auq_prose_mention(self):
        self.assertEqual(
            self.a.render_segment(_seg(CAT_AUQ, "AskUserQuestion",
                                       attrs={"occurrence_kind": "prose-mention"})),
            OPENCODE_AUQ_PHRASE,
        )

    def test_auq_labeled_block_raises(self):
        with self.assertRaises(AssertionError):
            self.a.render_segment(_seg(CAT_AUQ, "AskUserQuestion",
                                       attrs={"occurrence_kind": "labeled-block"}))

    def test_task_block_raises(self):
        with self.assertRaises(AssertionError):
            self.a.render_segment(_seg(CAT_TASK, 'Task(subagent_type="x", prompt="""y""")'))


class SectionRenderTests(unittest.TestCase):
    def test_neutral_splice(self):
        # "A ${CLAUDE_PLUGIN_ROOT} B" with the core-root token tagged at 2..23.
        text = "A ${CLAUDE_PLUGIN_ROOT} B"
        token = Segment(CAT_CORE_ROOT, Tier.ACTIVE_PARSED, "${CLAUDE_PLUGIN_ROOT}",
                        (2, 23), RenderMode.CANONICAL, {})
        sec = Section(2, "H", "h", (0, len(text)), text, inner_segments=[token])
        a = OpenCodeAdapter(template_loader=lambda b, s: "X")
        self.assertEqual(a.render_section(sec, RenderContext("x")),
                         f"A {OPENCODE_CORE_ROOT} B")

    def test_coupled_uses_template_and_strips_xref(self):
        sec = Section(3, "H", "8-parallel-worker-launch", (0, 1), "x",
                      pins=["pin"], is_coupled=True)
        a = OpenCodeAdapter(
            template_loader=lambda b, s: f"see security-project.md for {b}/{s}")
        out = a.render_section(sec, RenderContext("security-changes"))
        self.assertIn("security-project for", out)
        self.assertNotIn("security-project.md", out)


class XrefStripTests(unittest.TestCase):
    def setUp(self):
        self.a = OpenCodeAdapter(template_loader=lambda b, s: "x")

    def _render_neutral(self, text):
        from segments import Segment as _S, Tier as _T, RenderMode as _R
        sec = Section(2, "H", "h", (0, len(text)), text, inner_segments=[])
        return self.a.render_section(sec, RenderContext("x"))

    def test_strips_all_sibling_artifact_md_refs(self):
        for ref in ("security-project.md", "security-changes.md",
                    "agents/security-recon.md", "agents/security.md",
                    "agents/security-refute.md"):
            with self.subTest(ref=ref):
                out = self._render_neutral(f"see {ref} now")
                self.assertNotIn(".md", out)

    def test_does_not_strip_unrelated_md(self):
        out = self._render_neutral("read CONTEXT.md and README.md")
        self.assertIn("CONTEXT.md", out)
        self.assertIn("README.md", out)


class FrontmatterValidityTests(unittest.TestCase):
    def setUp(self):
        self.a = OpenCodeAdapter(template_loader=lambda b, s: "x")

    def _desc_line(self, attrs):
        out = self.a.render_segment(_seg(CAT_CMD_FRONTMATTER, "x", attrs=attrs))
        return out, out.splitlines()[1]

    def test_quoted_value_balanced_after_truncation(self):
        long = '"' + "word " * 400 + '"'  # > 1024
        out, line = self._desc_line({"description": long})
        self.assertTrue(line.startswith('description: "'))
        self.assertTrue(line.endswith('"'))
        # exactly two delimiting quotes (no embedded raw quote left dangling)
        self.assertEqual(line.count('"'), line.count('\\"') + 2)
        self.assertLessEqual(len(line) - len('description: "') - 1, 1024)

    def test_embedded_quote_escaped(self):
        _out, line = self._desc_line({"description": '"a "b" c"'})
        self.assertNotIn('\\\\', line)
        self.assertIn('\\"', line)


if __name__ == "__main__":
    unittest.main()
