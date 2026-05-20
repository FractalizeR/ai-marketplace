"""Tests for dedupe.renderer — focused on Executive Summary rendering.

Covers the Dedup-quality stat (Task 3 of v3.1.4): aggregated counts of the
heuristic flags FLAG_MERGED_DESPITE_HASH_MISMATCH, FLAG_CROSS_SINK_MERGE,
FLAG_PARSE_FAILED across merged + manual collections. The stat line is
emitted only when at least one counter is non-zero.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dedupe.models import (  # noqa: E402
    FLAG_CROSS_SINK_MERGE,
    FLAG_MERGED_DESPITE_HASH_MISMATCH,
    FLAG_PARSE_FAILED,
    Finding,
    MergedFinding,
)
from dedupe.renderer import render_summary  # noqa: E402


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
        """Один merged finding с FLAG_MERGED_DESPITE_HASH_MISMATCH → стат-строка
        присутствует и содержит правильные count'ы."""
        merged = [_mk_merged(FLAG_MERGED_DESPITE_HASH_MISMATCH)]
        manual: list[MergedFinding] = []
        summary = render_summary(merged, manual)
        self.assertIn(
            "Dedup quality: 1 hash-mismatch merges, "
            "0 cross-sink merges, 0 parse failures",
            summary,
        )

    def test_summary_omits_dedup_quality_when_clean(self):
        """Нет flag'ов → строка отсутствует (избегаем noise на чистых прогонах)."""
        merged = [_mk_merged()]
        manual: list[MergedFinding] = []
        summary = render_summary(merged, manual)
        self.assertNotIn("Dedup quality:", summary)

    def test_summary_includes_dedup_quality_with_only_parse_failures(self):
        """Только FLAG_PARSE_FAILED (manual) → стат-строка всё равно показана."""
        merged: list[MergedFinding] = []
        manual = [_mk_merged(FLAG_PARSE_FAILED, sink_file="", sink_line=0)]
        summary = render_summary(merged, manual)
        self.assertIn(
            "Dedup quality: 0 hash-mismatch merges, "
            "0 cross-sink merges, 1 parse failures",
            summary,
        )

    def test_summary_dedup_quality_aggregates_across_merged_and_manual(self):
        """Флаги в merged и manual должны учитываться вместе."""
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
        """Пустой merged + пустой manual → секции не должно быть."""
        summary = render_summary([], [])
        self.assertNotIn("Dedup quality:", summary)

    def test_summary_dedup_quality_only_cross_sink(self):
        """Только cross-sink merges → строка показана с другими count'ами = 0."""
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
            "`checklists/core/auth.md` (W1): активирован, 2 findings",
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
            "`checklists/core/crypto.md` (W4): активирован, 0 findings ← was empty",
            summary,
        )

    def test_inactive_checklist_tagged_with_stack(self):
        """Frameworks checklists not in waves_plan → marked '(стэк: <stack>)'."""
        # Active: only core/auth. All other on-disk checklists report as
        # inactive — at minimum we expect frameworks/symfony/auth tagged.
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
        # Symfony auth is frameworks/symfony/auth.md → stack inferred = symfony.
        self.assertIn(
            "`checklists/frameworks/symfony/auth.md`: не активирован (стэк: symfony)",
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


if __name__ == "__main__":
    unittest.main()
