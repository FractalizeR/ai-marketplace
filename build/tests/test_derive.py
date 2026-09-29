"""Codex derivation: token substitution, frontmatter, templates, stale-hash detection."""

import tempfile
import unittest
from pathlib import Path

import _common
from _common import PLUGIN_ROOT, read

from derive import (
    AUQ_PHRASE,
    CODEX_ARGS_PHRASE,
    CODEX_CORE_ROOT,
    MCP_PHRASE,
    ArtifactKind,
    Template,
    derive_artifact,
    hash_header,
    load_templates,
    refreshed_templates,
    section_sha256,
    strip_codex_xrefs,
    substitute_tokens,
)
from gates import check_codex_output
from sections import partition_sections

PROJECT = PLUGIN_ROOT / "commands" / "security-project.md"
TEMPLATES = _common.REPO_ROOT / "harness" / "codex" / "sections"


def _tpl(body, sha=None):
    return Template(Path("x.md"), sha, body)


def _fresh(source, anchor, body):
    sec = next(s for s in partition_sections(source) if s.section_anchor == anchor)
    return _tpl(body, section_sha256(sec))


class TokenSubstitutionTests(unittest.TestCase):
    def test_core_root(self):
        self.assertEqual(substitute_tokens("a ${CLAUDE_PLUGIN_ROOT}/bin"),
                         f"a {CODEX_CORE_ROOT}/bin")

    def test_args_renders_neutral_phrase(self):
        self.assertEqual(substitute_tokens("flags: $ARGUMENTS."),
                         f"flags: {CODEX_ARGS_PHRASE}.")

    def test_mcp_phrase(self):
        self.assertEqual(substitute_tokens("use mcp__phpstorm__search_symbol"),
                         f"use {MCP_PHRASE}")

    def test_auq_prose_mention_replaced(self):
        self.assertEqual(substitute_tokens("checkpoint (via AskUserQuestion)"),
                         f"checkpoint (via {AUQ_PHRASE})")

    def test_auq_followed_by_colon_mid_line_is_prose(self):
        self.assertEqual(substitute_tokens("ask via AskUserQuestion: yes"),
                         f"ask via {AUQ_PHRASE}: yes")

    def test_labeled_auq_left_to_leak(self):
        for text in ("AskUserQuestion:\n  q: x\n", "text\n   AskUserQuestion:\n"):
            with self.subTest(text=text):
                self.assertEqual(substitute_tokens(text), text)

    def test_task_directive_left_to_leak(self):
        text = 'Task(subagent_type="x", prompt="""y""")'
        self.assertEqual(substitute_tokens(text), text)


class FrontmatterTests(unittest.TestCase):
    def _derive(self, kind, desc='"hi"'):
        src = f"---\ndescription: {desc}\nallowed-tools:\n  - AskUserQuestion\n---\nbody\n"
        out, problems = derive_artifact(src, kind=kind, name="security-project",
                                        templates={})
        self.assertEqual(problems, [])
        return out

    def test_command_becomes_skill_block(self):
        out = self._derive(ArtifactKind.COMMAND)
        self.assertEqual(out, '---\nname: security-project\ndescription: "hi"\n---\nbody\n')

    def test_agent_frontmatter_stripped(self):
        self.assertEqual(self._derive(ArtifactKind.AGENT), "body\n")

    def test_description_unwrapped_and_escaped(self):
        out = self._derive(ArtifactKind.COMMAND, desc='"a "b" c"')
        line = [l for l in out.splitlines() if l.startswith("description:")][0]
        self.assertEqual(line, 'description: "a \\"b\\" c"')

    def test_frontmatter_tokens_not_substituted_into_description(self):
        out = self._derive(ArtifactKind.COMMAND, desc='"uses ${CLAUDE_PLUGIN_ROOT}"')
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", out.splitlines()[2])


class XrefStripTests(unittest.TestCase):
    """Strip ONLY orchestrator refs; PRESERVE agent read-follow refs (real bundled
    files a Codex worker opens)."""

    def test_strips_orchestrator_refs(self):
        self.assertEqual(strip_codex_xrefs("see security-project.md now"),
                         "see security-project now")

    def test_preserves_agent_read_follow_refs(self):
        for ref in ("agents/security.md", "agents/security-recon.md", "security-recon.md"):
            with self.subTest(ref=ref):
                self.assertIn(ref, strip_codex_xrefs(f"read and follow {ref}"))

    def test_preserves_unrelated_md(self):
        out = strip_codex_xrefs("read CONTEXT.md and README.md")
        self.assertIn("CONTEXT.md", out)
        self.assertIn("README.md", out)

    def test_no_fixed_length_lookbehind_blindspot(self):
        self.assertEqual(strip_codex_xrefs("subagents/security-project.md"),
                         "subagents/security-project")

    def test_word_char_prefix_not_stripped(self):
        self.assertEqual(strip_codex_xrefs("xsecurity-project.md"), "xsecurity-project.md")


class TemplateTests(unittest.TestCase):
    SRC = "intro\n## A\nsee security-project.md\n## B\n${CLAUDE_PLUGIN_ROOT}\n"

    def _derive(self, templates):
        return derive_artifact(self.SRC, kind=ArtifactKind.AGENT, name="art",
                               templates=templates)

    def test_templated_section_replaced_rest_substituted(self):
        out, problems = self._derive({"a": _fresh(self.SRC, "a", "## A\nTPL security-project.md\n")})
        self.assertEqual(problems, [])
        self.assertEqual(out, f"intro\n## A\nTPL security-project\n## B\n{CODEX_CORE_ROOT}\n")

    def test_orphan_template_is_a_problem(self):
        _out, problems = self._derive({"renamed": _tpl("x", "0" * 64)})
        self.assertTrue(any("matches no section" in p for p in problems))

    def test_anchor_matching_two_sections_is_a_problem(self):
        src = "## A\nx\n## A\ny\n"
        _out, problems = derive_artifact(src, kind=ArtifactKind.AGENT, name="art",
                                         templates={"a": _tpl("t", "0" * 64)})
        self.assertTrue(any("matches 2 sections" in p for p in problems))

    def test_missing_hash_header_is_a_problem(self):
        _out, problems = self._derive({"a": _tpl("## A\nt\n")})
        self.assertTrue(any("no source-sha256 header" in p for p in problems))

    def test_stale_hash_is_a_problem(self):
        _out, problems = self._derive({"a": _tpl("## A\nt\n", "0" * 64)})
        self.assertTrue(any("is stale" in p and "refresh-hashes" in p for p in problems))

    def test_bad_dispatch_template_is_a_problem(self):
        src = "## 8. Parallel worker launch\nx\n"
        tpl = _fresh(src, "8-parallel-worker-launch", "## 8. Parallel worker launch\nprose\n")
        _out, problems = derive_artifact(src, kind=ArtifactKind.AGENT, name="art",
                                         templates={"8-parallel-worker-launch": tpl})
        self.assertTrue(any("codex exec" in p for p in problems))

    def test_header_is_parsed_off_and_never_emitted(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "art").mkdir()
            sec = next(s for s in partition_sections(self.SRC) if s.section_anchor == "a")
            (Path(d) / "art" / "a.md").write_text(
                hash_header(section_sha256(sec)) + "## A\nbody\n", encoding="utf-8")
            templates = load_templates("art", Path(d))
        out, problems = self._derive(templates)
        self.assertEqual(problems, [])
        self.assertNotIn("source-sha256", out)
        self.assertIn("## A\nbody\n", out)

    def test_real_templates_all_carry_current_hashes(self):
        templates = load_templates("security-project", TEMPLATES)
        self.assertTrue(templates)
        _out, problems = derive_artifact(read(PROJECT), kind=ArtifactKind.COMMAND,
                                         name="security-project", templates=templates)
        self.assertEqual(problems, [])


class RefreshTests(unittest.TestCase):
    SRC = "## A\nnew prose\n"

    def test_stale_template_gets_new_header_and_same_body(self):
        tpl = Template(Path("a.md"), "0" * 64, "## A\nbody\n")
        updates, problems = refreshed_templates(self.SRC, name="art", templates={"a": tpl})
        self.assertEqual(problems, [])
        sec = partition_sections(self.SRC)[0]
        self.assertEqual(updates, {Path("a.md"): hash_header(section_sha256(sec)) + "## A\nbody\n"})

    def test_fresh_template_untouched(self):
        updates, _ = refreshed_templates(self.SRC, name="art",
                                         templates={"a": _fresh(self.SRC, "a", "b")})
        self.assertEqual(updates, {})

    def test_orphan_blocks_refresh(self):
        updates, problems = refreshed_templates(
            self.SRC, name="art",
            templates={"a": _tpl("b"), "gone": _tpl("c")})
        self.assertEqual(updates, {})
        self.assertTrue(problems)


class LeakGateBitesTests(unittest.TestCase):
    """A Task directive or a labeled AskUserQuestion block in an un-templated section
    of the real command must fail the no-leak gate; the same inside a templated
    section is replaced and does not leak."""

    ANCHOR = "### 7. Wave plan generation\n"

    def _gate_with(self, insertion, anchor=ANCHOR):
        source = read(PROJECT)
        self.assertIn(anchor, source)
        source = source.replace(anchor, anchor + "\n" + insertion + "\n", 1)
        templates = load_templates("security-project", TEMPLATES)
        out, _problems = derive_artifact(source, kind=ArtifactKind.COMMAND,
                                         name="security-project", templates=templates)
        return check_codex_output(out, is_skill=True)

    def test_untemplated_task_block_leaks(self):
        violations = self._gate_with('Task(subagent_type="x", prompt="y")\n')
        self.assertTrue(any(v.startswith("leak[task_block]") for v in violations), violations)

    def test_untemplated_bare_task_block_leaks(self):
        violations = self._gate_with('Task subagent_type=x prompt="y"\n')
        self.assertTrue(any(v.startswith("leak[task_block]") for v in violations), violations)

    def test_untemplated_labeled_auq_leaks(self):
        violations = self._gate_with('AskUserQuestion:\n  question: "pick one"\n')
        self.assertTrue(any(v.startswith("leak[auq]") for v in violations), violations)

    def test_same_insertion_in_templated_section_is_replaced(self):
        violations = self._gate_with('Task(subagent_type="x", prompt="y")\n',
                                     anchor="### 8. Parallel worker launch\n")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
