"""Tests for dedupe.renderer — focused on Executive Summary rendering.

Covers the Dedup-quality stat (Task 3 of v3.1.4): aggregated counts of the
heuristic flags FLAG_MERGED_DESPITE_HASH_MISMATCH, FLAG_CROSS_SINK_MERGE,
FLAG_PARSE_FAILED across merged + manual collections. The stat line is
emitted only when at least one counter is non-zero.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dedupe.models import (  # noqa: E402
    FLAG_CROSS_SINK_MERGE,
    FLAG_MERGED_DESPITE_HASH_MISMATCH,
    FLAG_PARSE_FAILED,
    Finding,
    HardeningNote,
    MergedFinding,
    NeedsValidation,
)
from dedupe.pipeline import attach_side_records  # noqa: E402
from dedupe.pipeline import dedupe as df_dedupe  # noqa: E402
from dedupe.renderer import (  # noqa: E402
    render_finding,
    render_index_report,
    render_summary,
    write_split_report,
)


def _mk_finding(
    sink_file: str = "src/A.php",
    sink_line: int = 10,
    severity: str = "High",
    confidence: int = 9,
    sink_kind: str = "sql_concat",
    root_cause_family: str = "injection",
    enclosing_symbol: str = "Repo::find",
    sink_snippet: str = "code",
) -> Finding:
    return Finding(
        title_line="h",
        sink_file=sink_file,
        sink_line=sink_line,
        severity=severity,
        confidence=confidence,
        sink_kind=sink_kind,
        root_cause_family=root_cause_family,
        enclosing_symbol=enclosing_symbol,
        sink_snippet=sink_snippet,
        raw_body="body",
    )


def _mk_merged(*flags: str, **finding_kwargs) -> MergedFinding:
    return MergedFinding(
        primary=_mk_finding(**finding_kwargs),
        flags=list(flags),
    )


class DedupQualityStatTests(unittest.TestCase):
    """Aggregated dedup-quality stat in Executive Summary."""

    def test_summary_includes_dedup_quality_when_nonzero(self):
        """One merged finding with FLAG_MERGED_DESPITE_HASH_MISMATCH -> stat
        line present and contains the correct counts."""
        merged = [_mk_merged(FLAG_MERGED_DESPITE_HASH_MISMATCH)]
        manual: list[MergedFinding] = []
        summary = render_summary(merged, manual)
        self.assertIn(
            "Dedup quality: 1 hash-mismatch merges, "
            "0 cross-sink merges, 0 parse failures",
            summary,
        )

    def test_summary_omits_dedup_quality_when_clean(self):
        """No flags -> line absent (avoid noise on clean runs)."""
        merged = [_mk_merged()]
        manual: list[MergedFinding] = []
        summary = render_summary(merged, manual)
        self.assertNotIn("Dedup quality:", summary)

    def test_summary_includes_dedup_quality_with_only_parse_failures(self):
        """Only FLAG_PARSE_FAILED (manual) -> stat line still shown."""
        merged: list[MergedFinding] = []
        manual = [_mk_merged(FLAG_PARSE_FAILED, sink_file="", sink_line=0)]
        summary = render_summary(merged, manual)
        self.assertIn(
            "Dedup quality: 0 hash-mismatch merges, "
            "0 cross-sink merges, 1 parse failures",
            summary,
        )

    def test_summary_dedup_quality_aggregates_across_merged_and_manual(self):
        """Flags in merged and manual must be counted together."""
        merged = [
            _mk_merged(FLAG_MERGED_DESPITE_HASH_MISMATCH),
            _mk_merged(FLAG_CROSS_SINK_MERGE, sink_file="src/B.php"),
        ]
        manual = [_mk_merged(FLAG_PARSE_FAILED, sink_file="", sink_line=0)]
        summary = render_summary(merged, manual)
        self.assertIn(
            "Dedup quality: 1 hash-mismatch merges, "
            "1 cross-sink merges, 1 parse failures",
            summary,
        )

    def test_summary_dedup_quality_empty_inputs(self):
        """Empty merged + empty manual -> section must be absent."""
        summary = render_summary([], [])
        self.assertNotIn("Dedup quality:", summary)

    def test_summary_dedup_quality_only_cross_sink(self):
        """Only cross-sink merges -> line shown with other counts = 0."""
        merged = [_mk_merged(FLAG_CROSS_SINK_MERGE)]
        summary = render_summary(merged, [])
        self.assertIn(
            "Dedup quality: 0 hash-mismatch merges, "
            "1 cross-sink merges, 0 parse failures",
            summary,
        )


class DiffBlockTests(unittest.TestCase):
    """`## Diff vs previous run` block in the executive summary."""

    def _diff(self, new=(), recurring=(), closed=()):
        from dedupe.state import FindingsDiff
        return FindingsDiff(new=list(new), recurring=list(recurring), closed=list(closed))

    def _snap(self, sink_hash="h1", sink_kind="idor_lookup", severity="High",
              file="src/A.php", line=10, title="t"):
        from dedupe.state import FindingSnapshot
        return FindingSnapshot(sink_hash, file, line, sink_kind, severity, title)

    def test_no_diff_means_no_block(self):
        """diff=None (first run) → block absent."""
        summary = render_summary([], [], diff=None)
        self.assertNotIn("Diff vs previous run", summary)

    def test_block_renders_counts_when_diff_provided(self):
        diff = self._diff(
            new=[self._snap("h1"), self._snap("h2")],
            recurring=[self._snap("h3")],
            closed=[self._snap("h4")],
        )
        summary = render_summary([], [], diff=diff)
        self.assertIn("## Diff vs previous run", summary)
        self.assertIn("New findings (not in previous state): 2", summary)
        self.assertIn("Recurring (also in previous state): 1", summary)
        self.assertIn("Closed (in previous state, gone now): 1", summary)

    def test_closed_findings_listed_with_location(self):
        """`### Closed since previous run` lists each closed snapshot
        with its sink_hash + file:line for triage."""
        diff = self._diff(closed=[
            self._snap("hclosed1", file="src/X.php", line=42,
                       sink_kind="dql_concat", severity="Critical"),
        ])
        summary = render_summary([], [], diff=diff)
        self.assertIn("### Closed since previous run", summary)
        self.assertIn("`hclosed1`", summary)
        self.assertIn("src/X.php:42", summary)
        self.assertIn("`dql_concat`", summary)

    def test_no_closed_section_when_closed_empty(self):
        diff = self._diff(new=[self._snap("h1")])
        summary = render_summary([], [], diff=diff)
        self.assertIn("Diff vs previous run", summary)
        self.assertNotIn("Closed since previous run", summary)


class ChecklistCoverageBlockTests(unittest.TestCase):
    """`## Checklist coverage` block, sourced from waves_plan.json."""

    PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent  # vr/code-review/

    def _finding_with_discovered_via(self, dv: str) -> MergedFinding:
        f = _mk_finding()
        f.discovered_via = dv
        return MergedFinding(primary=f, flags=[])

    def test_no_waves_plan_means_no_block(self):
        """waves_plan=None → coverage block absent (back-compat)."""
        summary = render_summary([], [], waves_plan=None)
        self.assertNotIn("## Checklist coverage", summary)

    def test_active_checklist_with_findings_count(self):
        """A checklist in waves_plan referenced by ≥1 finding shows N count."""
        # Pick a real on-disk checklist so normalization succeeds.
        cl = self.PLUGIN_ROOT / "checklists" / "core" / "auth.md"
        self.assertTrue(cl.is_file())
        merged = [
            self._finding_with_discovered_via("checklist:checklists/core/auth.md"),
            self._finding_with_discovered_via("checklist:checklists/core/auth.md"),
        ]
        plan = [{
            "wave_id": "W1",
            "slice_id": "W1_PART1",
            "checklists": [str(cl)],
        }]
        summary = render_summary(
            merged, [],
            waves_plan=plan,
            plugin_root=self.PLUGIN_ROOT,
        )
        self.assertIn("## Checklist coverage", summary)
        self.assertIn(
            "`checklists/core/auth.md` (W1): activated, 2 findings",
            summary,
        )

    def test_active_checklist_with_zero_findings_marked_was_empty(self):
        """A checklist in waves_plan with no findings → '0 findings ← was empty'."""
        cl = self.PLUGIN_ROOT / "checklists" / "core" / "crypto.md"
        self.assertTrue(cl.is_file())
        plan = [{
            "wave_id": "W4",
            "slice_id": "W4_PART1",
            "checklists": [str(cl)],
        }]
        summary = render_summary(
            [], [],
            waves_plan=plan,
            plugin_root=self.PLUGIN_ROOT,
        )
        self.assertIn(
            "`checklists/core/crypto.md` (W4): activated, 0 findings ← was empty",
            summary,
        )

    def test_inactive_checklist_tagged_with_stack(self):
        """Stack checklists not in waves_plan -> marked '(stack: <stack>)'."""
        # Active: only core/auth. All other on-disk checklists report as
        # inactive — at minimum we expect stacks/symfony/auth tagged.
        cl_active = self.PLUGIN_ROOT / "checklists" / "core" / "auth.md"
        plan = [{
            "wave_id": "W1",
            "slice_id": "W1_PART1",
            "checklists": [str(cl_active)],
        }]
        summary = render_summary(
            [], [],
            waves_plan=plan,
            plugin_root=self.PLUGIN_ROOT,
        )
        self.assertIn("## Checklist coverage", summary)
        # Symfony auth is stacks/symfony/auth.md -> stack inferred = symfony.
        self.assertIn(
            "`checklists/stacks/symfony/auth.md`: not activated (stack: symfony)",
            summary,
        )

    def test_path_normalization_strips_plugin_root(self):
        """Absolute checklist path is rendered relative to plugin_root."""
        cl = self.PLUGIN_ROOT / "checklists" / "core" / "injection.md"
        plan = [{
            "wave_id": "W2",
            "slice_id": "W2_PART1",
            "checklists": [str(cl.resolve())],
        }]
        summary = render_summary(
            [], [],
            waves_plan=plan,
            plugin_root=self.PLUGIN_ROOT,
        )
        # Absolute path should NOT appear; relative form must.
        self.assertNotIn(str(cl.resolve()), summary)
        self.assertIn("`checklists/core/injection.md`", summary)


class VerdictBucketRenderingTests(unittest.TestCase):
    """`## Needs validation` / `## Hardening notes` + attached annotations
    (P2.3 -- rendering only; `attach_side_records` itself is P2.2, imported
    here unmodified to drive realistic MergedFinding/NeedsValidation/
    HardeningNote wiring for the renderer under test)."""

    def _nv(self, sink_snippet="code", **kwargs) -> NeedsValidation:
        defaults = dict(
            sink_file="src/A.php", sink_line=10,
            claimed_root_cause="claimed cause",
            trace="trace text",
            blockers=["some blocker"],
            validation_plan_local="local plan",
            raw_body=(
                "* **claimed_root_cause**: claimed cause\n"
                "* **trace**: trace text\n"
                "* **blockers**:\n    - some blocker\n"
                "* **validation_plan_local**: local plan\n"
            ),
            source_file="W1.md", slice_id="W1",
        )
        defaults.update(kwargs)
        return NeedsValidation(sink_snippet=sink_snippet, **defaults)

    def _hn(self, sink_snippet="code", **kwargs) -> HardeningNote:
        defaults = dict(
            sink_file="src/A.php", sink_line=10,
            text="hardening text",
            raw_body="* **text**: hardening text\n",
            source_file="W1.md", slice_id="W1",
        )
        defaults.update(kwargs)
        return HardeningNote(sink_snippet=sink_snippet, **defaults)

    # -- attached annotations (rendered inside render_finding) ----

    def test_matched_needs_validation_renders_attached_in_finding(self):
        mf = _mk_merged(sink_snippet="code")
        nv = self._nv(sink_snippet="code")
        result = attach_side_records([mf], [nv], [])
        self.assertEqual(len(result.matched), 1)
        self.assertEqual(result.unmatched_needs_validation, [])
        body = render_finding(1, mf)
        self.assertIn("**Needs validation (attached):**", body)
        self.assertIn("claimed cause", body)
        self.assertIn("some blocker", body)
        self.assertIn("local plan", body)
        self.assertNotIn("### Needs validation", body)

    def test_matched_hardening_renders_attached_in_finding(self):
        mf = _mk_merged(sink_snippet="code")
        hn = self._hn(sink_snippet="code")
        result = attach_side_records([mf], [], [hn])
        self.assertEqual(len(result.matched), 1)
        self.assertEqual(result.unmatched_hardening, [])
        body = render_finding(1, mf)
        self.assertIn("**Hardening notes (attached):**", body)
        self.assertIn("hardening text", body)

    def test_attached_annotation_survives_in_manual_review(self):
        """Trap #2: a finding that stays in manual_review (never
        auto-promoted) must still carry its attached bucket annotation --
        `attach_side_records` must be called with the UNION of main + manual
        for this to work, since it only indexes what it is given."""
        f_manual = Finding(
            title_line="h", sink_file="src/Misc.php", sink_line=10,
            severity="Medium", confidence=6,
            sink_kind="other:weird", root_cause_family="business_logic",
            enclosing_symbol="Misc::speculate",
            sink_snippet="$x = rand();",
            raw_body="body",
        )
        merged, manual = df_dedupe([f_manual])
        self.assertEqual(merged, [])
        self.assertEqual(len(manual), 1)
        nv = self._nv(sink_snippet="$x = rand();", sink_file="src/Misc.php", sink_line=10)
        result = attach_side_records(merged + manual, [nv], [])
        self.assertEqual(len(result.matched), 1)
        body = render_finding(1, manual[0])
        self.assertIn("**Needs validation (attached):**", body)
        self.assertIn("claimed cause", body)

    # -- standalone sections (index REPORT.md only) ----

    def test_unmatched_needs_validation_gets_own_section(self):
        """Standalone sections render in `render_index_report` (the index
        REPORT.md), AFTER the findings table -- NOT inside `render_summary`
        (which only carries the counts line; see
        `test_no_bucket_kwargs_omits_both_sections` and
        `test_executive_summary_counts_line`)."""
        mf = _mk_merged(sink_snippet="code")
        nv = self._nv(sink_snippet="totally different snippet")
        result = attach_side_records([mf], [nv], [])
        self.assertEqual(result.matched, [])
        self.assertEqual(len(result.unmatched_needs_validation), 1)
        index = render_index_report(
            [mf], [], "REPORT",
            unmatched_needs_validation=result.unmatched_needs_validation,
        )
        self.assertIn("## Needs validation", index)
        self.assertIn("### Needs validation 1:", index)
        self.assertIn("claimed cause", index)
        # Placement: after the findings-by-category table.
        self.assertLess(
            index.index("## Findings by category"), index.index("## Needs validation"),
        )
        # Must not leak into the per-finding body of an unrelated finding.
        finding_body = render_finding(1, mf)
        self.assertNotIn("Needs validation", finding_body)

    def test_unmatched_hardening_gets_own_section(self):
        mf = _mk_merged(sink_snippet="code")
        hn = self._hn(sink_snippet="totally different snippet")
        result = attach_side_records([mf], [], [hn])
        self.assertEqual(len(result.unmatched_hardening), 1)
        index = render_index_report(
            [mf], [], "REPORT",
            unmatched_hardening=result.unmatched_hardening,
        )
        self.assertIn("## Hardening notes", index)
        self.assertIn("### Hardening 1:", index)
        self.assertIn("hardening text", index)

    def test_nohash00_needs_validation_not_lost(self):
        """A record with an empty `sink_snippet` hashes to the `nohash00`
        sentinel and can never match (`attach_side_records`) -- it must
        still render in the standalone section, not silently vanish."""
        nv = self._nv(sink_snippet="")
        self.assertEqual(nv.sink_hash, "nohash00")
        result = attach_side_records([], [nv], [])
        self.assertEqual(result.matched, [])
        self.assertEqual(len(result.unmatched_needs_validation), 1)
        index = render_index_report(
            [], [], "REPORT",
            unmatched_needs_validation=result.unmatched_needs_validation,
        )
        self.assertIn("## Needs validation", index)
        self.assertIn("nohash00", index)
        self.assertIn("claimed cause", index)

    def test_nohash00_hardening_not_lost(self):
        hn = self._hn(sink_snippet="")
        self.assertEqual(hn.sink_hash, "nohash00")
        result = attach_side_records([], [], [hn])
        self.assertEqual(len(result.unmatched_hardening), 1)
        index = render_index_report(
            [], [], "REPORT",
            unmatched_hardening=result.unmatched_hardening,
        )
        self.assertIn("## Hardening notes", index)
        self.assertIn("nohash00", index)
        self.assertIn("hardening text", index)

    # -- back-compat: old call sites (no bucket kwargs) unaffected ----

    def test_no_bucket_kwargs_omits_both_sections(self):
        mf = _mk_merged(sink_snippet="code")
        summary = render_summary([mf], [])
        index = render_index_report([mf], [], "REPORT")
        for text in (summary, index):
            self.assertNotIn("## Needs validation", text)
            self.assertNotIn("## Hardening notes", text)
        self.assertNotIn("Needs validation:", summary)
        self.assertNotIn("Hardening notes:", summary)

    def test_executive_summary_counts_line(self):
        mf = _mk_merged(sink_snippet="code")
        nv_matched = self._nv(sink_snippet="code")
        nv_standalone = self._nv(sink_snippet="other")
        result = attach_side_records([mf], [nv_matched, nv_standalone], [])
        summary = render_summary(
            [mf], [],
            unmatched_needs_validation=result.unmatched_needs_validation,
        )
        self.assertIn("Needs validation: 2 (1 attached to findings, 1 standalone)", summary)

    # -- split report: buckets only in the index, never per-family ----

    def test_split_report_sections_only_in_index_not_family_detail(self):
        f = Finding(
            title_line="h", sink_file="src/A.php", sink_line=10,
            severity="High", confidence=9,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
            sink_snippet="code",
            raw_body="body",
        )
        merged, manual = df_dedupe([f])
        nv_standalone = self._nv(sink_snippet="unmatched snippet")
        hn_matched = self._hn(sink_snippet="code")
        result = attach_side_records(merged + manual, [nv_standalone], [hn_matched])
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "REPORT.md"
            details = Path(td) / "REPORT"
            write_split_report(
                merged, manual, out, details,
                unmatched_needs_validation=result.unmatched_needs_validation,
                unmatched_hardening=result.unmatched_hardening,
            )
            index_text = out.read_text(encoding="utf-8")
            self.assertIn("## Needs validation", index_text)
            family_text = (details / "injection.md").read_text(encoding="utf-8")
            self.assertNotIn("## Needs validation", family_text)
            self.assertNotIn("## Hardening notes", family_text)
            # The MATCHED hardening record still shows up inline, attached
            # to its finding, in the family detail file.
            self.assertIn("**Hardening notes (attached):**", family_text)
            self.assertIn("hardening text", family_text)


if __name__ == "__main__":
    unittest.main()
