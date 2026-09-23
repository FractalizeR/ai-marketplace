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
    FLAG_REFUTE_CLAIMED,
    Finding,
    HardeningNote,
    MergedFinding,
    NeedsValidation,
    checklist_tail,
    normalize_discovered_via,
)
from dedupe.pipeline import attach_side_records  # noqa: E402
from dedupe.pipeline import dedupe as df_dedupe  # noqa: E402
from dedupe.refute import compute_evidence_hash  # noqa: E402
from dedupe.renderer import (  # noqa: E402
    _replace_field,
    render_finding,
    render_hardening_entry,
    render_index_report,
    render_needs_validation_entry,
    render_report,
    render_summary,
    write_split_report,
)
from dedupe.state import Resolution, active_rejections  # noqa: E402


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


class ChecklistTailNormalizationTests(unittest.TestCase):
    """`models.checklist_tail` / `models.normalize_discovered_via` --
    table-driven cases. A foreign install's absolute prefix is built as a
    clearly-fake, non-existent path (never a real path on this machine) --
    these functions are pure string ops and never touch the filesystem."""

    def test_checklist_tail_cases(self):
        cases = [
            ("checklists/core/auth.md", "checklists/core/auth.md"),
            (
                "/opt/example-install/core/checklists/core/auth.md",
                "checklists/core/auth.md",
            ),
            (
                "/home/example-user/checklists/repo/security-review/checklists/core/auth.md",
                "checklists/core/auth.md",
            ),
            ("./checklists/x.md", "checklists/x.md"),
            ("/opt/example-install/file-without-marker.md", None),
            (
                "/Users/example/Library/Application Support/install/"
                "checklists/core/auth.md",
                "checklists/core/auth.md",
            ),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(checklist_tail(raw), expected)

    def test_normalize_discovered_via_cases(self):
        cases = [
            ("checklist:checklists/core/auth.md", "checklist:checklists/core/auth.md"),
            (
                "checklist:/opt/example-install/core/checklists/core/auth.md",
                "checklist:checklists/core/auth.md",
            ),
            (
                "checklist:/home/example-user/checklists/repo/security-review/"
                "checklists/core/auth.md",
                "checklist:checklists/core/auth.md",
            ),
            ("checklist:./checklists/x.md", "checklist:checklists/x.md"),
            ("exploratory", "exploratory"),
            (
                "checklist:/opt/example-install/file-without-marker.md",
                "checklist:/opt/example-install/file-without-marker.md",
            ),
            (
                "checklist:/Users/example/Library/Application Support/"
                "install/checklists/core/auth.md",
                "checklist:checklists/core/auth.md",
            ),
            # A token with no ".md" of its own must not extend to a LATER
            # token's ".md" -- each of these three ends unchanged.
            (
                "checklist:foo.md.bak",
                "checklist:foo.md.bak",
            ),
            (
                "checklist:checklists/core/auth",
                "checklist:checklists/core/auth",
            ),
            # Uppercase extension is still recognized.
            (
                "checklist:/opt/example-install/checklists/core/AUTH.MD",
                "checklist:checklists/core/AUTH.MD",
            ),
            # Two tokens, space-separated (no comma) -- each stops at the
            # other, neither swallows the other's path.
            (
                "checklist:/opt/example-install/checklists/core/a.md "
                "checklist:/opt/other-install/checklists/core/b.md",
                "checklist:checklists/core/a.md checklist:checklists/core/b.md",
            ),
            # A bare word before the token is untouched, not absorbed.
            (
                "exploratory checklist:/opt/example-install/checklists/core/a.md",
                "exploratory checklist:checklists/core/a.md",
            ),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(normalize_discovered_via(raw), expected)

    def test_normalize_discovered_via_does_not_cross_comma_to_a_later_md(self):
        """A `checklist:` token whose own path has no `.md` must not reach
        across a comma to a LATER token's `.md` and delete everything in
        between."""
        raw = (
            "checklist:core/auth, exploratory, "
            "checklist:/opt/example-install/checklists/core/a.md"
        )
        expected = (
            "checklist:core/auth, exploratory, "
            "checklist:checklists/core/a.md"
        )
        self.assertEqual(normalize_discovered_via(raw), expected)

    def test_normalize_discovered_via_does_not_misattribute_across_comma(self):
        """Free text with a `.md` mention after a comma must not be pulled
        into an EARLIER, unrelated `checklist:` token that has no `.md` of
        its own."""
        raw = (
            "checklist:/opt/example-install/checklists/core/auth (traced), "
            "see /opt/example-install/checklists/x.md"
        )
        # Neither side is a recognizable, self-contained `checklist:<path>.md`
        # token, so the value is left byte-identical.
        self.assertEqual(normalize_discovered_via(raw), raw)

    def test_normalize_discovered_via_two_tokens_comma_separated(self):
        """One relative + one foreign-absolute token, comma-separated ->
        both normalized, original separator (", ") preserved verbatim."""
        raw = (
            "checklist:checklists/core/auth.md, "
            "checklist:/opt/example-install/core/checklists/stacks/symfony/auth.md"
        )
        expected = (
            "checklist:checklists/core/auth.md, "
            "checklist:checklists/stacks/symfony/auth.md"
        )
        self.assertEqual(normalize_discovered_via(raw), expected)

    def test_spaced_path_does_not_swallow_comma_separated_next_token(self):
        """A spaced install path must still stop at the next `checklist:`
        token instead of consuming the separator and the second path too."""
        raw = (
            "checklist:/Users/example/Library/Application Support/"
            "install/checklists/core/auth.md, "
            "checklist:checklists/stacks/symfony/auth.md"
        )
        expected = (
            "checklist:checklists/core/auth.md, "
            "checklist:checklists/stacks/symfony/auth.md"
        )
        self.assertEqual(normalize_discovered_via(raw), expected)

    def test_spaced_path_does_not_swallow_trailing_exploratory_token(self):
        """A trailing space-separated `exploratory` token (no comma) must
        survive untouched, not get absorbed into the normalized path."""
        raw = (
            "checklist:/Users/example/Library/Application Support/"
            "install/checklists/core/auth.md exploratory"
        )
        expected = "checklist:checklists/core/auth.md exploratory"
        self.assertEqual(normalize_discovered_via(raw), expected)


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


class DiscoveredViaBodyReplacementTests(unittest.TestCase):
    """`render_finding` overwrites the `Discovered via` line in the replayed
    `raw_body` with `f.discovered_via`. `raw_body` is the worker's verbatim
    text -- normalizing `f.discovered_via` at parse time alone does not
    touch it, so this replacement is what keeps a foreign install's
    absolute path out of `REPORT/<family>.md`."""

    def test_body_discovered_via_line_replaced_with_normalized_value(self):
        f = _mk_finding()
        f.discovered_via = "checklist:checklists/core/auth.md"
        f.raw_body = (
            "* **Description**: test desc\n"
            "* **Discovered via**: checklist:/opt/example-install/core/"
            "checklists/core/auth.md\n"
        )
        mf = MergedFinding(primary=f, flags=[])
        body = render_finding(1, mf)
        self.assertNotIn("/opt/example-install", body)
        self.assertIn("* **Discovered via**: checklist:checklists/core/auth.md", body)

    def test_body_without_discovered_via_field_is_left_alone(self):
        """No `Discovered via` line in raw_body -> nothing is appended (the
        field replacement is opt-in on presence, unlike sink_hash)."""
        f = _mk_finding()
        f.discovered_via = "checklist:checklists/core/auth.md"
        f.raw_body = "* **Description**: test desc\n"
        mf = MergedFinding(primary=f, flags=[])
        body = render_finding(1, mf)
        self.assertNotIn("Discovered via", body)


class ReplaceFieldLiteralSubstitutionTests(unittest.TestCase):
    """`_replace_field` must treat `new_value` as literal text, not an
    `re.sub` replacement template -- a backslash in worker free text (a
    Windows install path, a PHP FQCN) must not raise `re.error`, and a
    literal `\\1` must not be expanded as a backreference."""

    def test_backslash_in_value_does_not_raise(self):
        body = "* **Discovered via**: checklist:checklists/core/auth.md\n"
        value = r"checklist:checklists/core/auth.md, traced via App\Controller\Foo"
        result = _replace_field(body, "Discovered via", value)
        self.assertIn(value, result)

    def test_literal_backreference_is_not_expanded(self):
        body = "* **Discovered via**: checklist:checklists/core/auth.md\n"
        result = _replace_field(body, "Discovered via", r"see \1 group")
        self.assertIn(r"* **Discovered via**: see \1 group", result)

    def test_render_finding_survives_backslash_in_discovered_via(self):
        """End-to-end through `render_finding`, not just the helper --
        `f.discovered_via` is worker free text once it carries no
        `checklist:` token for `normalize_discovered_via` to touch."""
        f = _mk_finding()
        f.discovered_via = r"App\Controller\Foo, checklist:checklists/core/auth.md"
        f.raw_body = "* **Discovered via**: checklist:checklists/core/auth.md\n"
        mf = MergedFinding(primary=f, flags=[])
        body = render_finding(1, mf)
        self.assertIn(r"App\Controller\Foo", body)


class StandaloneBucketDiscoveredViaNormalizationTests(unittest.TestCase):
    """`render_needs_validation_entry` / `render_hardening_entry` replay
    `raw_body` verbatim (like `render_finding` does for a `Finding`), but
    `NeedsValidation`/`HardeningNote` carry no parsed `discovered_via` field
    of their own -- so the `Discovered via` line must be re-normalized from
    the replayed body itself, not from a pre-normalized attribute."""

    def test_needs_validation_entry_normalizes_discovered_via(self):
        nv = NeedsValidation(
            sink_file="src/A.php", sink_line=10,
            claimed_root_cause="claimed cause",
            raw_body=(
                "* **claimed_root_cause**: claimed cause\n"
                "* **Discovered via**: checklist:/opt/example-install/core/"
                "checklists/core/auth.md\n"
            ),
            source_file="W1.md", slice_id="W1",
        )
        entry = render_needs_validation_entry(1, nv)
        self.assertNotIn("/opt/example-install", entry)
        self.assertIn("* **Discovered via**: checklist:checklists/core/auth.md", entry)

    def test_hardening_entry_normalizes_discovered_via(self):
        hn = HardeningNote(
            sink_file="src/A.php", sink_line=10,
            text="hardening text",
            raw_body=(
                "* **text**: hardening text\n"
                "* **Discovered via**: checklist:/opt/example-install/core/"
                "checklists/core/auth.md\n"
            ),
            source_file="W1.md", slice_id="W1",
        )
        entry = render_hardening_entry(1, hn)
        self.assertNotIn("/opt/example-install", entry)
        self.assertIn("* **Discovered via**: checklist:checklists/core/auth.md", entry)


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

    def test_loose_binding_says_so_in_the_rendered_annotation(self):
        # An annotation under a confirmed finding otherwise reads as "the
        # workers agreed on this sink"; the bare flag name does not say
        # otherwise to a human reading the report.
        # A canonical sink_kind on both sides: the fixture default is a
        # custom sink, which the loose tiers deliberately leave out.
        mf = _mk_merged(sink_snippet="code", sink_kind="dql_concat")
        nv = self._nv(
            sink_snippet="a different quotation of the same line",
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
        )
        attach_side_records([mf], [nv], [])
        body = render_finding(1, mf)
        self.assertIn("**Needs validation (attached):**", body)
        self.assertIn("bound by location, not by quoted text", body)

    def test_exact_binding_carries_no_attachment_caveat(self):
        mf = _mk_merged(sink_snippet="code")
        attach_side_records([mf], [self._nv(sink_snippet="code")], [])
        self.assertNotIn("bound by location", render_finding(1, mf))

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


class ResolutionAnnotationTests(unittest.TestCase):
    """Stage 2 / P2.5: `resolutions` (`sink_hash -> state.Resolution`) marks
    a finding as previously rejected WITHOUT suppressing it — the finding
    must still render in full; only a note is appended."""

    def _mk_mf(self, sink_snippet="code", **flags_and_fields) -> MergedFinding:
        f = _mk_finding(sink_snippet=sink_snippet)
        mf = MergedFinding(primary=f)
        for k, v in flags_and_fields.items():
            setattr(mf, k, v)
        return mf

    def test_rejected_resolution_renders_note_without_removing_finding(self):
        mf = self._mk_mf()
        resolutions = {mf.primary.sink_hash: Resolution(
            verdict="rejected", refute_file="src/Guard.php", refute_line=3, source="refute",
        )}
        body = render_finding(1, mf, resolutions=resolutions)
        # DoD 6: the finding itself is NOT suppressed -- title/body still present.
        self.assertIn(f"`{mf.primary.sink_file}:{mf.primary.sink_line}`", body)
        self.assertIn("Previously rejected", body)
        self.assertIn("src/Guard.php:3", body)

    def test_rejected_resolution_present_in_full_split_report(self):
        """Red-if-turned-into-a-filter guard: the finding must still appear
        BOTH in the index table AND in its per-family detail body -- a
        resolutions map must never remove a row/file entry, only annotate it."""
        f = Finding(
            title_line="h", sink_file="src/A.php", sink_line=10,
            severity="High", confidence=9,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find", sink_snippet="code", raw_body="body",
        )
        merged, manual = df_dedupe([f])
        resolutions = {merged[0].primary.sink_hash: Resolution(verdict="rejected", source="triage")}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "REPORT.md"
            details = Path(td) / "REPORT"
            write_split_report(merged, manual, out, details, resolutions=resolutions)
            index_text = out.read_text(encoding="utf-8")
            family_text = (details / "injection.md").read_text(encoding="utf-8")
        self.assertIn("`src/A.php:10`", index_text)
        self.assertIn("`src/A.php:10`", family_text)
        self.assertIn("Previously rejected", family_text)

    def test_no_evidence_location_falls_back_to_source_only_note(self):
        mf = self._mk_mf()
        resolutions = {mf.primary.sink_hash: Resolution(verdict="rejected", source="triage-bot")}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertIn("Previously rejected (source: `triage-bot`)", body)

    def test_reaffirmed_resolution_renders_no_note(self):
        mf = self._mk_mf()
        resolutions = {mf.primary.sink_hash: Resolution(verdict="reaffirmed", source="triage")}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertNotIn("Previously rejected", body)

    def test_no_matching_resolution_renders_no_note(self):
        mf = self._mk_mf()
        body = render_finding(1, mf, resolutions={"someotherhash": Resolution(verdict="rejected")})
        self.assertNotIn("Previously rejected", body)

    def test_resolutions_none_is_back_compat_no_note(self):
        mf = self._mk_mf()
        body = render_finding(1, mf)
        self.assertNotIn("Previously rejected", body)

    def test_fresh_refute_claim_this_run_takes_priority_over_historical_note(self):
        """A finding refuted THIS run already carries the live blockquote --
        the historical note would be redundant, not wrong, but must not
        double up."""
        mf = self._mk_mf(
            flags=[FLAG_REFUTE_CLAIMED],
            refute_rationale="fresh evidence this run",
            refute_confidence=9,
            refute_file="src/Fresh.php",
            refute_line=1,
        )
        resolutions = {mf.primary.sink_hash: Resolution(
            verdict="rejected", refute_file="src/Old.php", refute_line=99, source="refute",
        )}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertIn("Refute claim: fresh evidence this run", body)
        self.assertNotIn("src/Old.php", body)
        self.assertEqual(body.count("Previously rejected"), 0)

    def test_run_seq_never_leaks_into_rendered_output(self):
        mf = self._mk_mf()
        resolutions = {mf.primary.sink_hash: Resolution(
            verdict="rejected", refute_file="src/Guard.php", refute_line=3,
            source="refute", run_seq=42,
        )}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertNotIn("42", body)
        self.assertNotIn("run_seq", body)


class StandaloneResolutionAnnotationTests(unittest.TestCase):
    """A `resolutions` rejection also marks a STANDALONE `## Needs validation`
    / `## Hardening notes` entry (unmatched by `attach_side_records`), not
    just a confirmed `Finding` -- CLAUDE.md "memory marks, never suppresses"
    applies to leads and hardening notes the same as to findings. Bound
    (attached-to-a-finding) records with a tier-1 (exact-hash) bind are out
    of scope here: they share the parent's `sink_hash`, so the parent
    finding's own note already covers them; see
    `AttachedResolutionAnnotationTests` below for the tier-2/3 (by-location,
    own hash) case, which DOES get its own mark."""

    def _nv(self, sink_snippet="lead code", **kwargs) -> NeedsValidation:
        defaults = dict(
            sink_file="src/Lead.php", sink_line=20,
            claimed_root_cause="claimed cause",
            raw_body="* **claimed_root_cause**: claimed cause\n",
            source_file="W1.md", slice_id="W1",
        )
        defaults.update(kwargs)
        return NeedsValidation(sink_snippet=sink_snippet, **defaults)

    def _hn(self, sink_snippet="hardening code", **kwargs) -> HardeningNote:
        defaults = dict(
            sink_file="src/Harden.php", sink_line=30,
            text="hardening text",
            raw_body="* **text**: hardening text\n",
            source_file="W1.md", slice_id="W1",
        )
        defaults.update(kwargs)
        return HardeningNote(sink_snippet=sink_snippet, **defaults)

    def test_needs_validation_entry_marks_rejected_hash(self):
        nv = self._nv()
        resolutions = {nv.sink_hash: Resolution(
            verdict="rejected", refute_file="src/Guard.php", refute_line=3, source="refute",
        )}
        entry = render_needs_validation_entry(1, nv, resolutions=resolutions)
        # DoD: the lead itself is not suppressed -- title/body still present.
        self.assertIn("### Needs validation 1: `src/Lead.php:20`", entry)
        self.assertIn("claimed cause", entry)
        self.assertIn("Previously rejected", entry)
        self.assertIn("src/Guard.php:3", entry)

    def test_hardening_entry_marks_rejected_hash(self):
        hn = self._hn()
        resolutions = {hn.sink_hash: Resolution(verdict="rejected", source="triage")}
        entry = render_hardening_entry(1, hn, resolutions=resolutions)
        self.assertIn("### Hardening 1: `src/Harden.php:30`", entry)
        self.assertIn("hardening text", entry)
        self.assertIn("Previously rejected (source: `triage`)", entry)

    def test_needs_validation_entry_no_match_no_note(self):
        entry = render_needs_validation_entry(
            1, self._nv(), resolutions={"someotherhash": Resolution(verdict="rejected")}
        )
        self.assertNotIn("Previously rejected", entry)

    def test_hardening_entry_reaffirmed_no_note(self):
        hn = self._hn()
        resolutions = {hn.sink_hash: Resolution(verdict="reaffirmed", source="triage")}
        entry = render_hardening_entry(1, hn, resolutions=resolutions)
        self.assertNotIn("Previously rejected", entry)

    def test_needs_validation_entry_resolutions_none_is_back_compat(self):
        entry = render_needs_validation_entry(1, self._nv())
        self.assertNotIn("Previously rejected", entry)

    def test_marks_survive_write_split_report_index(self):
        """Red-if-turned-into-a-filter guard for the split-report path: the
        wiring bug this feature fixes was `write_split_report` dropping
        `resolutions` before it ever reached `render_index_report` -- so this
        must go through the real entry point, not just the leaf renderer."""
        nv = self._nv()
        hn = self._hn()
        resolutions = {
            nv.sink_hash: Resolution(verdict="rejected", source="triage"),
            hn.sink_hash: Resolution(verdict="rejected", source="triage"),
        }
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "REPORT.md"
            details = Path(td) / "REPORT"
            write_split_report(
                [], [], out, details,
                unmatched_needs_validation=[nv],
                unmatched_hardening=[hn],
                resolutions=resolutions,
            )
            index_text = out.read_text(encoding="utf-8")
        self.assertIn("## Needs validation", index_text)
        self.assertIn("## Hardening notes", index_text)
        self.assertEqual(index_text.count("Previously rejected"), 2)

    def test_marks_survive_single_file_report(self):
        nv = self._nv()
        resolutions = {nv.sink_hash: Resolution(verdict="rejected", source="triage")}
        text = render_report(
            [], [], unmatched_needs_validation=[nv], resolutions=resolutions,
        )
        self.assertIn("Previously rejected", text)

    def _mk_project(self, td: Path) -> Path:
        project_root = td / "project"
        guard = project_root / "src" / "Guard.php"
        guard.parent.mkdir(parents=True)
        guard.write_text(
            "\n".join(["<?php", "function check() {", "    deny_unless(hasRole('admin'));", "}"]),
            encoding="utf-8",
        )
        return project_root

    def test_invalidated_rejection_shows_no_mark_on_standalone_entries(self):
        """Evidence-hash invalidation (state.active_rejections) must protect
        standalone entries exactly as it already protects confirmed findings:
        a positive control (evidence unchanged -> mark) plus the regression
        (evidence changed -> no mark), both driven through the real
        `active_rejections` filter the pipeline uses, not a hand-rolled dict."""
        nv = self._nv()
        hn = self._hn()
        with tempfile.TemporaryDirectory() as td:
            project_root = self._mk_project(Path(td))
            evidence_hash = compute_evidence_hash("src/Guard.php", 3, project_root)
            raw_resolutions = {
                nv.sink_hash: Resolution(
                    verdict="rejected", evidence_hash=evidence_hash,
                    refute_file="src/Guard.php", refute_line=3, source="refute",
                ),
                hn.sink_hash: Resolution(
                    verdict="rejected", evidence_hash=evidence_hash,
                    refute_file="src/Guard.php", refute_line=3, source="refute",
                ),
            }

            # Positive control: evidence untouched -> active -> mark renders.
            active = active_rejections(raw_resolutions, project_root)
            nv_entry = render_needs_validation_entry(1, nv, resolutions=active)
            hn_entry = render_hardening_entry(1, hn, resolutions=active)
            self.assertIn("Previously rejected", nv_entry)
            self.assertIn("Previously rejected", hn_entry)

            # Protection removed at the cited line -> evidence_hash changes
            # -> active_rejections drops it -> no mark, without touching
            # resolutions itself (mirrors test_findings_state.py's scenario).
            (project_root / "src" / "Guard.php").write_text(
                "\n".join(["<?php", "function check() {", "    // no check anymore", "}"]),
                encoding="utf-8",
            )
            active_after = active_rejections(raw_resolutions, project_root)
            nv_entry_after = render_needs_validation_entry(1, nv, resolutions=active_after)
            hn_entry_after = render_hardening_entry(1, hn, resolutions=active_after)
            self.assertNotIn("Previously rejected", nv_entry_after)
            self.assertNotIn("Previously rejected", hn_entry_after)


class AttachedResolutionAnnotationTests(unittest.TestCase):
    """A resolution can also apply to a record ATTACHED to a confirmed
    finding (`attach_side_records`) rather than standalone. Two tiers behave
    differently:

    - tier-1 (exact `sink_hash` match): the attached record shares the
      parent finding's hash, so `render_finding`'s own `resolutions` lookup
      (on `f.sink_hash`) already renders the note once, above the attached
      block. Marking the attached copy too would duplicate it.
    - tier-2/3 (`FLAG_ATTACHED_WITHOUT_HASH`, bound by location): the record
      keeps its OWN, different `sink_hash`, which the parent's lookup never
      sees -- only a mark keyed on the record's own hash can cover it. It
      renders as a `* **previously_rejected**: ...` field line (the attached
      form is already built entirely from field lines, not a `raw_body`
      replay or a blockquote -- see the module note above
      `_render_attached_needs_validation` -- so this is a safe field-line
      addition, not the blockquote-reflow case `render_finding`'s
      `[REFUTE_CLAIMED]`/`resolutions` blockquote branch has to avoid)."""

    def _nv(self, sink_snippet, **kwargs) -> NeedsValidation:
        defaults = dict(
            sink_file="src/A.php", sink_line=10,
            claimed_root_cause="claimed cause",
            raw_body="* **claimed_root_cause**: claimed cause\n",
            source_file="W1.md", slice_id="W1",
        )
        defaults.update(kwargs)
        return NeedsValidation(sink_snippet=sink_snippet, **defaults)

    def _hn(self, sink_snippet, **kwargs) -> HardeningNote:
        defaults = dict(
            sink_file="src/A.php", sink_line=10,
            text="hardening text",
            raw_body="* **text**: hardening text\n",
            source_file="W1.md", slice_id="W1",
        )
        defaults.update(kwargs)
        return HardeningNote(sink_snippet=sink_snippet, **defaults)

    def test_tier2_needs_validation_own_rejection_gets_field_line_mark(self):
        mf = _mk_merged(sink_snippet="code", sink_kind="dql_concat")
        nv = self._nv(
            "a different quotation of the same line",
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
        )
        attach_side_records([mf], [nv], [])
        self.assertNotEqual(nv.sink_hash, mf.primary.sink_hash)  # tier-2/3, own hash
        resolutions = {nv.sink_hash: Resolution(
            verdict="rejected", refute_file="src/Guard.php", refute_line=3, source="refute",
        )}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertIn("**Needs validation (attached):**", body)
        self.assertIn("* **previously_rejected**: Previously rejected; evidence at "
                       "`src/Guard.php:3`", body)

    def test_tier2_hardening_own_rejection_gets_field_line_mark(self):
        mf = _mk_merged(sink_snippet="code", sink_kind="dql_concat")
        hn = self._hn(
            "a different quotation of the same line",
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
        )
        attach_side_records([mf], [], [hn])
        self.assertNotEqual(hn.sink_hash, mf.primary.sink_hash)
        resolutions = {hn.sink_hash: Resolution(verdict="rejected", source="triage")}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertIn("**Hardening notes (attached):**", body)
        self.assertIn("* **previously_rejected**: Previously rejected (source: `triage`)", body)

    def test_tier1_exact_bind_does_not_duplicate_the_parents_note(self):
        """The attached record shares the parent's hash -- only the parent's
        own note (rendered above the attached block) should show; the
        attached field-line form must not repeat it."""
        mf = _mk_merged(sink_snippet="code")
        nv = self._nv("code")  # same snippet -> same sink_hash as the parent
        attach_side_records([mf], [nv], [])
        self.assertEqual(nv.sink_hash, mf.primary.sink_hash)
        resolutions = {mf.primary.sink_hash: Resolution(verdict="rejected", source="triage")}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertEqual(body.count("Previously rejected"), 1)
        self.assertNotIn("* **previously_rejected**:", body)

    def test_tier2_reaffirmed_own_hash_no_mark(self):
        mf = _mk_merged(sink_snippet="code", sink_kind="dql_concat")
        nv = self._nv(
            "a different quotation of the same line",
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
        )
        attach_side_records([mf], [nv], [])
        resolutions = {nv.sink_hash: Resolution(verdict="reaffirmed", source="triage")}
        body = render_finding(1, mf, resolutions=resolutions)
        self.assertNotIn("Previously rejected", body)

    def test_tier2_no_matching_resolution_no_mark(self):
        mf = _mk_merged(sink_snippet="code", sink_kind="dql_concat")
        nv = self._nv(
            "a different quotation of the same line",
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
        )
        attach_side_records([mf], [nv], [])
        body = render_finding(1, mf, resolutions={"someotherhash": Resolution(verdict="rejected")})
        self.assertNotIn("Previously rejected", body)

    def test_resolutions_none_is_back_compat_no_mark(self):
        mf = _mk_merged(sink_snippet="code", sink_kind="dql_concat")
        nv = self._nv(
            "a different quotation of the same line",
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
        )
        attach_side_records([mf], [nv], [])
        body = render_finding(1, mf)
        self.assertNotIn("Previously rejected", body)


if __name__ == "__main__":
    unittest.main()
