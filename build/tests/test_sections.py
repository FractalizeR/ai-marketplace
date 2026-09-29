"""Section partition: faithfulness, boundary awareness, templated-anchor set."""

import unittest

import _common
from _common import ARTIFACTS, TEMPLATES_ROOT, read

from sections import (
    assert_section_partition,
    frontmatter_end,
    partition_sections,
    slugify,
    task_spans,
)

_EXPECTED_TEMPLATED = {
    "security-project": {
        "3b-resolve-console-runner-environment-aware",
        "4-recon-phase",
        "6-optional-interactive-checkpoint",
        "8-parallel-worker-launch",
        "9-safety-net-progress-per-worker",
    },
}


class RealArtifactTests(unittest.TestCase):
    def test_faithful_partition_all_artifacts(self):
        for path in ARTIFACTS:
            with self.subTest(artifact=path.name):
                text = read(path)
                secs = partition_sections(text)
                self.assertTrue(secs)
                assert_section_partition(secs, text)

    def test_templated_anchor_set(self):
        # Pins the directory listing that decides which sections are replaced.
        found = {}
        for tpl in sorted(TEMPLATES_ROOT.glob("*/*.md")):
            found.setdefault(tpl.parent.name, set()).add(tpl.stem)
        self.assertEqual(found, _EXPECTED_TEMPLATED)

    def test_every_templated_anchor_names_one_section(self):
        for path in ARTIFACTS:
            anchors = [s.section_anchor for s in partition_sections(read(path))]
            for anchor in _EXPECTED_TEMPLATED.get(path.stem, ()):
                with self.subTest(artifact=path.name, anchor=anchor):
                    self.assertEqual(anchors.count(anchor), 1)

    def test_each_real_task_directive_lies_in_one_templated_section(self):
        proj = next(p for p in ARTIFACTS if p.name == "security-project.md")
        text = read(proj)
        spans = task_spans(text, frontmatter_end(text))
        self.assertEqual(len(spans), 2)
        secs = partition_sections(text)
        for start, end in spans:
            owner = [s for s in secs if s.span[0] <= start and end <= s.span[1]]
            with self.subTest(span=(start, end)):
                self.assertEqual(len(owner), 1)
                self.assertIn(owner[0].section_anchor, _EXPECTED_TEMPLATED["security-project"])


class BoundaryAwarenessTests(unittest.TestCase):
    def test_heading_inside_triple_fence_not_a_boundary(self):
        text = "# Top\n\n```\n## not a heading\n```\n\n## Real\nbody\n"
        secs = partition_sections(text)
        anchors = [s.section_anchor for s in secs]
        self.assertIn("real", anchors)
        self.assertNotIn("not-a-heading", anchors)

    def test_heading_inside_four_backtick_block_not_a_boundary(self):
        text = "# Top\n\n````markdown\n## inner\n```\n### deeper\n```\n````\n\n## Real\nx\n"
        secs = partition_sections(text)
        anchors = [s.section_anchor for s in secs]
        self.assertNotIn("inner", anchors)
        self.assertNotIn("deeper", anchors)
        self.assertIn("real", anchors)

    def test_heading_inside_task_paren_body_not_a_boundary(self):
        text = '# Top\nTask(subagent_type="x", prompt="""\n## prompt\n""")\n## Real\nx\n'
        anchors = [s.section_anchor for s in partition_sections(text)]
        self.assertNotIn("prompt", anchors)
        self.assertIn("real", anchors)

    def test_heading_inside_task_bare_body_not_a_boundary(self):
        text = '# Top\nTask subagent_type=x prompt="\n## prompt\n"\n## Real\nx\n'
        anchors = [s.section_anchor for s in partition_sections(text)]
        self.assertNotIn("prompt", anchors)
        self.assertIn("real", anchors)

    def test_frontmatter_is_opaque(self):
        text = "---\ndescription: x\n# not a heading\n---\n## Real\nx\n"
        secs = partition_sections(text)
        self.assertEqual([s.section_anchor for s in secs], ["_preamble", "real"])


class EdgeCaseTests(unittest.TestCase):
    def test_unterminated_fence_is_opaque_to_eof(self):
        text = "# T\nintro\n```\n## not a heading\nmore\n"
        secs = partition_sections(text)
        assert_section_partition(secs, text)
        self.assertNotIn("not-a-heading", [s.section_anchor for s in secs])

    def test_consecutive_headings_zero_body(self):
        text = "# A\n## B\n### C\nbody\n"
        secs = partition_sections(text)
        assert_section_partition(secs, text)
        self.assertEqual([s.section_anchor for s in secs], ["a", "b", "c"])

    def test_heading_at_offset_zero_has_no_empty_preamble(self):
        text = "## Only\nbody\n"
        secs = partition_sections(text)
        assert_section_partition(secs, text)
        self.assertEqual(len(secs), 1)
        self.assertEqual(secs[0].section_anchor, "only")


class SlugifyTests(unittest.TestCase):
    def test_cases(self):
        self.assertEqual(slugify("4. Recon phase"), "4-recon-phase")
        self.assertEqual(slugify("0.5.3. Deferred git check (optional)"),
                         "0-5-3-deferred-git-check-optional")
        self.assertEqual(slugify("3b. Resolve console runner (environment-aware)"),
                         "3b-resolve-console-runner-environment-aware")


if __name__ == "__main__":
    unittest.main()
