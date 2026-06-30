"""Section partition, coupling detection, and guard tests."""

import unittest

import _common
from _common import ARTIFACTS, read

from extract import extract, CAT_TASK, CAT_AUQ
from segments import assert_partition, Tier
from sections import (
    partition_sections,
    assert_section_partition,
    attach_segments,
    detect_coupling,
    assert_coupling_guards,
    slugify,
)
from prose_coupling import load_pins, pins_for
from _common import BUILD_DIR

_EXPECTED_COUPLED = {
    "security-project.md": {
        "3b-resolve-console-runner-environment-aware",
        "4-recon-phase",
        "6-optional-interactive-checkpoint",
        "8-parallel-worker-launch",
        "9-safety-net-progress-per-worker",
        "11-5-1-launching-the-refute-wave",
    },
    "security-changes.md": {
        "4c-resolve-console-runner-environment-aware",
        "5-recon-phase",
        "6-summary-and-optional-checkpoint",
        "10-parallel-worker-launch-in-mode-changes",
        "10a-safety-net-progress-critical",
        "12-5-1-launching-the-refute-wave",
    },
}


def _pipeline(path, kind, pins):
    text = read(path)
    segs = extract(text, kind)
    assert_partition(segs, text)
    task_spans = [s.span for s in segs if s.category == CAT_TASK]
    secs = partition_sections(text, task_spans=task_spans)
    assert_section_partition(secs, text)
    secs = attach_segments(secs, segs)
    file_rel = f"{path.parent.name}/{path.name}"
    secs = detect_coupling(secs, [p.pinned for p in pins_for(pins, file_rel)])
    return text, segs, secs


class SectionPartitionTests(unittest.TestCase):
    def setUp(self):
        self.pins = load_pins(BUILD_DIR / "PROSE_COUPLING.md")

    def test_faithful_partition_all_artifacts(self):
        for path, kind in ARTIFACTS.items():
            with self.subTest(artifact=path.name):
                _text, _segs, secs = _pipeline(path, kind, self.pins)
                self.assertTrue(secs)

    def test_tagged_segments_within_one_section(self):
        # attach_segments asserts internally; this just exercises every artifact.
        for path, kind in ARTIFACTS.items():
            with self.subTest(artifact=path.name):
                _pipeline(path, kind, self.pins)

    def test_coupling_matches_register(self):
        for path, kind in ARTIFACTS.items():
            with self.subTest(artifact=path.name):
                _text, _segs, secs = _pipeline(path, kind, self.pins)
                coupled = {s.section_anchor for s in secs if s.is_coupled}
                self.assertEqual(coupled, _EXPECTED_COUPLED.get(path.name, set()))

    def test_guards_pass_on_real_artifacts(self):
        for path, kind in ARTIFACTS.items():
            with self.subTest(artifact=path.name):
                _text, _segs, secs = _pipeline(path, kind, self.pins)
                assert_coupling_guards(secs)  # must not raise

    def test_prose_mention_auq_does_not_couple_arguments_section(self):
        # V1-C1 regression: the `## ARGUMENTS` AskUserQuestion prose-mention must
        # NOT promote its section to coupled.
        proj = next(p for p in ARTIFACTS if p.name == "security-project.md")
        _text, _segs, secs = _pipeline(proj, ARTIFACTS[proj], self.pins)
        args_sec = next(s for s in secs if s.heading_text == "ARGUMENTS")
        self.assertFalse(args_sec.is_coupled)
        self.assertTrue(
            any(
                seg.category == CAT_AUQ
                and seg.attrs.get("occurrence_kind") == "prose-mention"
                for seg in args_sec.inner_segments
            )
        )


class BoundaryAwarenessTests(unittest.TestCase):
    def test_heading_inside_triple_fence_not_a_boundary(self):
        text = "# Top\n\n```\n## not a heading\n```\n\n## Real\nbody\n"
        secs = partition_sections(text, task_spans=[])
        anchors = [s.section_anchor for s in secs]
        self.assertIn("real", anchors)
        self.assertNotIn("not-a-heading", anchors)

    def test_heading_inside_four_backtick_block_not_a_boundary(self):
        text = "# Top\n\n````markdown\n## inner\n```\n### deeper\n```\n````\n\n## Real\nx\n"
        secs = partition_sections(text, task_spans=[])
        anchors = [s.section_anchor for s in secs]
        self.assertNotIn("inner", anchors)
        self.assertNotIn("deeper", anchors)
        self.assertIn("real", anchors)

    def test_heading_inside_task_span_not_a_boundary(self):
        text = "# Top\nintro\n## prompt\n## Real\nx\n"
        # mark "## prompt\n" as an opaque task span
        start = text.index("## prompt")
        end = text.index("## Real")
        secs = partition_sections(text, task_spans=[(start, end)])
        anchors = [s.section_anchor for s in secs]
        self.assertNotIn("prompt", anchors)
        self.assertIn("real", anchors)


class GuardTests(unittest.TestCase):
    def test_task_block_in_uncoupled_section_raises(self):
        from segments import Segment, RenderMode
        from sections import Section
        task = Segment(CAT_TASK, Tier.ACTIVE_PARSED, 'Task(subagent_type="x", prompt="""y""")',
                       (5, 44), RenderMode.ECHO, {})
        sec = Section(3, "H", "h", (0, 50), "x" * 50,
                      inner_segments=[task], is_coupled=False)
        with self.assertRaises(AssertionError):
            assert_coupling_guards([sec])

    def test_labeled_auq_in_uncoupled_section_raises(self):
        from segments import Segment, RenderMode
        from sections import Section
        auq = Segment(CAT_AUQ, Tier.ACTIVE_PARSED, "AskUserQuestion", (5, 20),
                      RenderMode.ECHO, {"occurrence_kind": "labeled-block"})
        sec = Section(3, "H", "h", (0, 50), "x" * 50,
                      inner_segments=[auq], is_coupled=False)
        with self.assertRaises(AssertionError):
            assert_coupling_guards([sec])


class EdgeCaseTests(unittest.TestCase):
    def test_unterminated_fence_is_opaque_to_eof(self):
        text = "# T\nintro\n```\n## not a heading\nmore\n"
        secs = partition_sections(text, task_spans=[])
        assert_section_partition(secs, text)
        self.assertNotIn("not-a-heading", [s.section_anchor for s in secs])

    def test_consecutive_headings_zero_body(self):
        text = "# A\n## B\n### C\nbody\n"
        secs = partition_sections(text, task_spans=[])
        assert_section_partition(secs, text)
        self.assertEqual([s.section_anchor for s in secs], ["a", "b", "c"])

    def test_heading_at_offset_zero_has_no_empty_preamble(self):
        text = "## Only\nbody\n"
        secs = partition_sections(text, task_spans=[])
        assert_section_partition(secs, text)
        self.assertEqual(len(secs), 1)
        self.assertEqual(secs[0].section_anchor, "only")


class SlugifyTests(unittest.TestCase):
    def test_cases(self):
        self.assertEqual(slugify("4. Recon phase"), "4-recon-phase")
        self.assertEqual(slugify("11.5.1. Launching the refute wave"),
                         "11-5-1-launching-the-refute-wave")
        self.assertEqual(slugify("3b. Resolve console runner (environment-aware)"),
                         "3b-resolve-console-runner-environment-aware")


if __name__ == "__main__":
    unittest.main()
