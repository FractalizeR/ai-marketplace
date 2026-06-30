"""Attr-value assertions, parser-reads-not-asserts, negative guards, structure."""

import unittest
from collections import Counter

import _common
from _common import ARTIFACTS, PLUGIN_ROOT, read

from extract import (
    ArtifactKind, CAT_CORE_ROOT, CAT_TASK, _assemble, extract,
)
from segments import Tier, assert_partition
from build import build
from adapters import ClaudeAdapter


def _segments(rel):
    path = PLUGIN_ROOT / rel
    return extract(read(path), ARTIFACTS[path])


def _by_cat(segments, cat):
    return [s for s in segments if s.category == cat]


class StructureTests(unittest.TestCase):
    def test_assert_partition_holds(self):
        for path, kind in ARTIFACTS.items():
            with self.subTest(path=path.name):
                source = read(path)
                assert_partition(extract(source, kind), source)

    def test_emitted_categories_are_known(self):
        known = {
            "neutral", "CORE_ROOT", "args_injection", "cmd_frontmatter",
            "agent_frontmatter", "task_block", "auq", "mcp_ref",
        }
        for path, kind in ARTIFACTS.items():
            for s in extract(read(path), kind):
                self.assertIn(s.category, known)


class AttrValueTests(unittest.TestCase):
    def test_core_root_role_and_fence_distribution(self):
        roles, fences = Counter(), Counter()
        for path, kind in ARTIFACTS.items():
            for s in _by_cat(extract(read(path), kind), "CORE_ROOT"):
                roles[s.attrs["role"]] += 1
                fences[s.attrs["fence_context"]] += 1
        self.assertEqual(dict(roles), {"path_prefix": 19, "flag_value": 2})
        self.assertEqual(dict(fences), {"triple_fence": 17, "inline_code": 4})

    def test_task_blocks_both_syntaxes_and_attrs(self):
        rows = []
        for rel in ("commands/security-project.md", "commands/security-changes.md"):
            for s in _by_cat(_segments(rel), "task_block"):
                rows.append((s.attrs["syntax_variant"], s.attrs["subagent_type"],
                             s.attrs["is_template"], s.attrs["is_directive"]))
        # 6 directive blocks: recon (paren), worker (paren, templated model), refute (bare) x2
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(v == "paren" for v, *_ in rows), 4)
        self.assertEqual(sum(v == "bare" for v, *_ in rows), 2)
        worker = [r for r in rows if r[1] == "security"]
        self.assertTrue(all(r[2] for r in worker))           # model is_template
        self.assertTrue(all(is_dir for *_, is_dir in rows))  # all directives
        self.assertEqual({r[1] for r in rows},
                         {"security-recon", "security", "security-refute"})

    def test_prose_task_mentions_not_tagged(self):
        # Each command has exactly 3 Task *directives*; the prose `Task(...)`
        # mention (project:122 / changes:126) must not be tagged.
        for rel in ("commands/security-project.md", "commands/security-changes.md"):
            self.assertEqual(len(_by_cat(_segments(rel), "task_block")), 3)

    def test_task_prompt_body_heredoc_captured(self):
        worker = next(s for s in _segments("commands/security-project.md")
                      if s.category == "task_block" and s.attrs["subagent_type"] == "security")
        body = worker.attrs["prompt_body"]
        self.assertIn("mode: project", body)
        self.assertIn("review_root:", body)
        self.assertNotIn('"""', body)  # heredoc delimiters excluded from body

    def test_agent_frontmatter_models(self):
        models = {}
        for rel in ("agents/security.md", "agents/security-recon.md", "agents/security-refute.md"):
            fm = _by_cat(_segments(rel), "agent_frontmatter")[0]
            models[rel.split("/")[-1]] = fm.attrs["model"]
        self.assertEqual(models["security.md"], "opus")
        self.assertEqual(models["security-recon.md"], "sonnet")
        self.assertEqual(models["security-refute.md"], "sonnet")

    def test_command_frontmatter_allowed_tools(self):
        fm = _by_cat(_segments("commands/security-project.md"), "cmd_frontmatter")[0]
        self.assertEqual(fm.attrs["core_root_globs"], 2)
        self.assertTrue(fm.attrs["has_task_entry"])
        self.assertTrue(fm.attrs["has_auq_entry"])
        self.assertIn("Read", fm.attrs["allowed_tools"])

    def test_auq_occurrence_kinds(self):
        kinds = Counter()
        for path, kind in ARTIFACTS.items():
            for s in _by_cat(extract(read(path), kind), "auq"):
                kinds[s.attrs["occurrence_kind"]] += 1
        self.assertEqual(dict(kinds), {"prose-mention": 5, "labeled-block": 1})

    def test_args_injection_present_in_both_commands(self):
        for rel in ("commands/security-project.md", "commands/security-changes.md"):
            args = _by_cat(_segments(rel), "args_injection")
            self.assertEqual(len(args), 1)
            self.assertEqual(args[0].original_text, "$ARGUMENTS")

    def test_mcp_refs_tagged_optional(self):
        total = 0
        for path, kind in ARTIFACTS.items():
            for s in _by_cat(extract(read(path), kind), "mcp_ref"):
                total += 1
                self.assertTrue(s.attrs["optional"])
                self.assertTrue(s.attrs["tool"].startswith("mcp__"))
        self.assertEqual(total, 5)


class ParserReadsNotAssertsTests(unittest.TestCase):
    """Prove ACTIVE_PARSED parsers read input rather than hardcode expectations."""

    def test_agent_model_flips_on_mutation(self):
        source = read(PLUGIN_ROOT / "agents" / "security.md").replace(
            "model: opus", "model: sonnet", 1
        )
        fm = [s for s in extract(source, ArtifactKind.AGENT)
              if s.category == "agent_frontmatter"][0]
        self.assertEqual(fm.attrs["model"], "sonnet")

    def test_task_subagent_type_flips_on_mutation(self):
        source = read(PLUGIN_ROOT / "commands" / "security-project.md").replace(
            'subagent_type="security"', 'subagent_type="mutant"', 1
        )
        types = {s.attrs["subagent_type"]
                 for s in extract(source, ArtifactKind.COMMAND)
                 if s.category == "task_block"}
        self.assertIn("mutant", types)


class NegativeGuardTests(unittest.TestCase):
    def test_base_branch_never_tagged(self):
        # ${BASE_BRANCH} is a harness-agnostic shell var: must stay NEUTRAL.
        source = read(PLUGIN_ROOT / "commands" / "security-changes.md")
        segments = extract(source, ArtifactKind.COMMAND)
        neutral_occurrences = sum(
            s.original_text.count("${BASE_BRANCH}")
            for s in segments if s.tier is Tier.NEUTRAL
        )
        self.assertEqual(neutral_occurrences, source.count("${BASE_BRANCH}"))
        self.assertGreater(neutral_occurrences, 0)

    def test_arguments_heading_not_tagged_as_args(self):
        # `## ARGUMENTS` (no $) must not be mistaken for $ARGUMENTS.
        for rel in ("commands/security-project.md", "commands/security-changes.md"):
            args = [s for s in _segments(rel) if s.category == "args_injection"]
            self.assertTrue(all(s.original_text == "$ARGUMENTS" for s in args))

    def test_placeholders_not_tagged_as_point_tokens(self):
        # <REVIEW_ROOT>/<PROJECT_ROOT> live in neutral or inside task prompt bodies,
        # never as their own tagged point token.
        point_cats = {"CORE_ROOT", "args_injection", "auq", "mcp_ref"}
        for path, kind in ARTIFACTS.items():
            for s in extract(read(path), kind):
                if s.category in point_cats:
                    self.assertNotIn("<REVIEW_ROOT>", s.original_text)
                    self.assertNotIn("<PROJECT_ROOT>", s.original_text)


class SubsumptionTests(unittest.TestCase):
    """The overlap-resolution path (no real artifact exercises it today)."""

    SYNTHETIC = (
        '---\n'
        'description: "x"\n'
        'allowed-tools:\n'
        '  - Read\n'
        '---\n'
        '\n'
        'Body.\n'
        '\n'
        '```\n'
        'Task(subagent_type="security", prompt="""\n'
        '  path: ${CLAUDE_PLUGIN_ROOT}/bin/x.py\n'
        '  ref: mcp__phpstorm__foo\n'
        '""")\n'
        '```\n'
    )

    def test_point_tokens_inside_task_body_are_subsumed(self):
        segs = extract(self.SYNTHETIC, ArtifactKind.COMMAND)
        assert_partition(segs, self.SYNTHETIC)
        self.assertEqual(len(_by_cat(segs, "task_block")), 1)
        self.assertEqual(len(_by_cat(segs, "CORE_ROOT")), 0)   # subsumed
        self.assertEqual(len(_by_cat(segs, "mcp_ref")), 0)     # subsumed
        body = _by_cat(segs, "task_block")[0].attrs["prompt_body"]
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", body)
        self.assertIn("mcp__phpstorm__foo", body)
        # Round-trip still identical (subsumed CORE_ROOT echoes inside the block).
        self.assertEqual(build(segs, ClaudeAdapter()), self.SYNTHETIC)

    def test_partial_overlap_raises_loudly(self):
        source = "x" * 15
        matches = [
            {"start": 0, "end": 10, "category": CAT_TASK, "attrs": {}},
            {"start": 5, "end": 15, "category": CAT_CORE_ROOT, "attrs": {}},
        ]
        with self.assertRaises(AssertionError):
            _assemble(source, matches)


if __name__ == "__main__":
    unittest.main()
