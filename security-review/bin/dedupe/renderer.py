"""Rendering of deduplicated findings into markdown reports.

Supports two output modes:
  - Single-file (legacy): all findings inline.
  - Split: index file + per-family detail files + manual_review.md.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .models import (
    FLAG_CROSS_SINK_MERGE,
    FLAG_MERGED_DESPITE_HASH_MISMATCH,
    FLAG_PARSE_FAILED,
    FLAG_REFUTE_CLAIMED,
    SEVERITY_RANK,
    MergedFinding,
)
from .reflow import reflow_markdown


# ---------------------------------------------------------------------------
# Plugin root resolution.
#
# `_default_plugin_root()` mirrors `plan_waves._default_plugin_root()`:
# parent of `bin/`. Used for normalizing absolute checklist paths in the
# `## Checklist coverage` block to plugin-root-relative form.
# ---------------------------------------------------------------------------


def _default_plugin_root() -> Path:
    # renderer.py lives in bin/dedupe/, so bin/ is parent.parent and plugin
    # root is parent.parent.parent.
    return Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Field manipulation in raw body.
# ---------------------------------------------------------------------------


def _replace_field(body: str, field_name: str, new_value: str) -> str:
    """Replace `* **FieldName**: ...` with a new single-line value."""
    pattern = re.compile(
        rf"^(\*\s+\*\*{re.escape(field_name)}\*\*\s*:).*$",
        re.MULTILINE,
    )
    return pattern.sub(rf"\1 {new_value}", body, count=1)


def _append_field(body: str, field_name: str, value: str) -> str:
    """Append a new field line at the end of the metadata block."""
    return body.rstrip() + f"\n* **{field_name}**: {value}\n"


# ---------------------------------------------------------------------------
# Title helpers.
# ---------------------------------------------------------------------------


def _title_category(mf: MergedFinding) -> str:
    """Compact category label for the finding title.

    Multi-merge can produce 4-6 long category strings; the title just needs
    a primary label + overflow count. Full list lives in the body.
    """
    cats = list(mf.categories) or ([mf.primary.category] if mf.primary.category else [])
    if not cats:
        return ""
    if len(cats) == 1:
        return cats[0]
    return f"{cats[0]} (+{len(cats) - 1} more)"


# ---------------------------------------------------------------------------
# Individual finding rendering.
# ---------------------------------------------------------------------------


def render_finding(idx: int, mf: MergedFinding) -> str:
    """Render finding by replaying the primary's raw_body."""
    f = mf.primary
    # `[REFUTE_CLAIMED]` is rendered with the refute_file:refute_line tail to
    # make the audit trail visible inline (operator sees where the rationale
    # was anchored without scrolling to refute_invalid.md).
    visible_flags: list[str] = []
    for fl in mf.flags:
        if fl == FLAG_REFUTE_CLAIMED and (mf.refute_file or mf.refute_line):
            visible_flags.append(
                f"{fl} {mf.refute_file}:{mf.refute_line}"
            )
        else:
            visible_flags.append(fl)
    flag_suffix = f" {' '.join(visible_flags)}" if visible_flags else ""
    title = (
        f"# Vulnerability {idx}: [{_title_category(mf)}]: "
        f"`{f.sink_file}:{f.sink_line}`{flag_suffix}"
    )

    body = (f.raw_body or "").strip()
    body = _replace_field(body, "Severity", mf.severity)
    body = _replace_field(body, "Confidence", f"{mf.confidence}/10")
    if mf.categories:
        body = _replace_field(body, "Category", ", ".join(mf.categories))
    if "**sink_hash**" not in body:
        body = _append_field(body, "sink_hash", f.sink_hash)
    else:
        body = _replace_field(body, "sink_hash", f.sink_hash)

    out = [title, "", body]

    if mf.alternative_sink_kinds:
        out.append("")
        out.append(
            f"**Alternative sink_kinds (from {FLAG_CROSS_SINK_MERGE}):** "
            f"{', '.join(mf.alternative_sink_kinds)}"
        )
    if mf.alternative_root_cause_families:
        out.append(
            f"**Alternative root_cause_families (from {FLAG_CROSS_SINK_MERGE}):** "
            f"{', '.join(mf.alternative_root_cause_families)}"
        )
    if mf.slice_ids:
        out.append("")
        out.append(f"**Discovered in slices:** {', '.join(mf.slice_ids)}")
    if mf.merged_from:
        sources = sorted({x.source_file for x in mf.merged_from if x.source_file})
        if sources:
            out.append(f"**Also detected in:** {', '.join(sources)}")
    if mf.related:
        out.append(f"**Related to:** {', '.join(mf.related)}")
    if FLAG_REFUTE_CLAIMED in mf.flags and mf.refute_rationale:
        out.append("")
        out.append(
            f"> Refute claim: {mf.refute_rationale} "
            f"(confidence {mf.refute_confidence})"
        )
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------


def _normalize_checklist_path(p: str, plugin_root: Path) -> str:
    """Return checklist path relative to plugin_root, falling back to original.

    waves_plan emits absolute paths (resolve_checklists). For readability in
    REPORT.md we strip the plugin-root prefix. If a path is not under
    plugin_root (e.g. tests passing custom paths) we return it unchanged.
    """
    try:
        rel = Path(p).resolve().relative_to(plugin_root.resolve())
        return rel.as_posix()
    except (ValueError, OSError):
        return p


def _checklist_stack(rel_path: str) -> str | None:
    """Infer stack folder from a normalized relative checklist path.

    `checklists/stacks/<stack>/<theme>.md` → <stack>;
    `checklists/core/<theme>.md` or anything else → None.
    """
    parts = rel_path.split("/")
    if (
        len(parts) >= 4
        and parts[0] == "checklists"
        and parts[1] == "stacks"
        and parts[2]
    ):
        return parts[2]
    return None


def _list_all_on_disk_checklists(plugin_root: Path) -> list[str]:
    """Return all `*.md` files under `plugin_root/checklists/` excluding meta
    helpers (prefix `_`) — paths are plugin-root-relative POSIX.
    """
    root = plugin_root / "checklists"
    if not root.is_dir():
        return []
    out: list[str] = []
    for p in sorted(root.rglob("*.md")):
        if p.name.startswith("_"):
            continue
        try:
            rel = p.relative_to(plugin_root).as_posix()
        except ValueError:
            continue
        out.append(rel)
    return out


def _findings_per_checklist(merged: Iterable[MergedFinding]) -> dict[str, int]:
    """Count merged findings whose `discovered_via` references each checklist.

    Format the worker emits: `checklist:<file>` (see agents/security.md).
    Workers may write either an absolute path or a plugin-root-relative one;
    both are normalized to a path-tail match against the relative form so
    coverage attribution lines up regardless of which form the worker used.
    Multi-checklist references separated by commas/whitespace are counted
    against each checklist mentioned.
    """
    counts: dict[str, int] = {}
    for mf in merged:
        dv = (mf.primary.discovered_via or "").strip()
        if not dv:
            continue
        # Tokenize on commas / whitespace so workers may list multiple sources.
        for token in re.split(r"[,\s]+", dv):
            if not token.startswith("checklist:"):
                continue
            tail = token.split(":", 1)[1].strip()
            if not tail:
                continue
            # Normalize: strip leading './', any absolute prefix becomes the
            # checklists/... suffix when present.
            tail = tail.removeprefix("./")
            idx = tail.find("checklists/")
            if idx >= 0:
                tail = tail[idx:]
            counts[tail] = counts.get(tail, 0) + 1
    return counts


def _render_checklist_coverage(
    waves_plan: list[dict] | None,
    merged: list[MergedFinding],
    plugin_root: Path,
) -> list[str]:
    """Build the `## Checklist coverage` block.

    Three states per checklist:
      - active + N findings: in waves_plan AND ≥1 finding references it.
      - active + 0 findings: in waves_plan AND no finding references it.
      - inactive: on disk under checklists/ but absent from waves_plan; tagged
        with the stack folder it belongs to (so the operator immediately sees
        why it wasn't activated for the current run's stack).

    waves_plan=None → returns [] (back-compat).
    """
    if waves_plan is None:
        return []

    # Collect activated checklists from the plan, normalized + ordered by first
    # appearance.
    activated: list[str] = []
    seen_active: set[str] = set()
    waves_per_checklist: dict[str, list[str]] = {}
    for slc in waves_plan:
        wave_id = slc.get("wave_id") or slc.get("slice_id") or ""
        for raw in slc.get("checklists") or []:
            if not isinstance(raw, str) or not raw:
                continue
            rel = _normalize_checklist_path(raw, plugin_root)
            if rel not in seen_active:
                seen_active.add(rel)
                activated.append(rel)
            if isinstance(wave_id, str) and wave_id:
                waves_per_checklist.setdefault(rel, [])
                if wave_id not in waves_per_checklist[rel]:
                    waves_per_checklist[rel].append(wave_id)

    finding_counts = _findings_per_checklist(merged)

    # On-disk inventory minus activated → "not activated" set.
    on_disk = _list_all_on_disk_checklists(plugin_root)
    inactive = [rel for rel in on_disk if rel not in seen_active]

    if not activated and not inactive:
        return []

    lines = ["## Checklist coverage", ""]

    for rel in activated:
        waves = waves_per_checklist.get(rel) or []
        wave_label = f" ({', '.join(waves)})" if waves else ""
        n = finding_counts.get(rel, 0)
        if n > 0:
            lines.append(f"- `{rel}`{wave_label}: activated, {n} findings")
        else:
            lines.append(f"- `{rel}`{wave_label}: activated, 0 findings ← was empty")

    for rel in inactive:
        stack = _checklist_stack(rel)
        suffix = f" (stack: {stack})" if stack else ""
        lines.append(f"- `{rel}`: not activated{suffix}")

    lines.append("")
    return lines


def _render_coverage_gaps(coverage_gaps: list[str] | None) -> list[str]:
    """Render a `## Coverage Gaps` section for the executive summary.

    Surfaces coverage reductions from two sources: recon-level (e.g. console
    enrichment skipped because the project is containerized and no
    `--console-cmd` was supplied) AND wave-dispatch execution gaps (a worker
    that produced no findings file — crash / timeout / missing write). The
    preamble is phrased generally to cover both. Empty / None → no section
    (clean runs stay noise-free).
    """
    if not coverage_gaps:
        return []
    lines = [
        "## Coverage Gaps",
        "",
        "> ⚠️ Parts of the audit coverage or execution did not complete "
        "(recon surface not fully enumerated and/or one or more analysis waves "
        "produced no findings file). Findings below may be incomplete in the "
        "affected areas.",
        "",
    ]
    for gap in coverage_gaps:
        lines.append(f"- {gap}")
    lines.append("")
    return lines


def _render_diff_block(diff) -> list[str]:
    """Render a `## Diff vs previous run` section for the executive summary.

    `diff` is a `dedupe.state.FindingsDiff`. Returns [] when no diff is provided
    (first run) or when there were truly no closed/new findings (cosmetic noise).
    Recurring count is always reported alongside as a sanity check.
    """
    if diff is None:
        return []
    new_count = len(diff.new)
    recurring_count = len(diff.recurring)
    closed_count = len(diff.closed)
    lines = [
        "## Diff vs previous run",
        "",
        f"- New findings (not in previous state): {new_count}",
        f"- Recurring (also in previous state): {recurring_count}",
        f"- Closed (in previous state, gone now): {closed_count}",
        "",
    ]
    if diff.closed:
        lines.append("### Closed since previous run")
        lines.append("")
        for s in sorted(diff.closed, key=lambda x: (x.sink_file, x.sink_line)):
            location = f"{s.sink_file}:{s.sink_line}" if s.sink_file else s.sink_kind
            severity = s.severity or "?"
            kind = s.sink_kind or "?"
            lines.append(f"- `{s.sink_hash}` {severity} `{kind}` — {location}")
        lines.append("")
    return lines


def render_summary(
    merged: list[MergedFinding],
    manual: list[MergedFinding],
    *,
    details_dirname: str | None = None,
    diff=None,
    cost=None,
    refute_summary: dict[str, int] | None = None,
    waves_plan: list[dict] | None = None,
    plugin_root: Path | None = None,
    coverage_gaps: list[str] | None = None,
    incomplete: bool = False,
) -> str:
    total_counted = len(merged) + len(manual)
    by_sev: dict[str, int] = {}
    for m in merged:
        by_sev[m.severity] = by_sev.get(m.severity, 0) + 1
    parse_failed_count = sum(1 for m in manual if FLAG_PARSE_FAILED in m.flags)
    custom_sink_count = len(manual) - parse_failed_count
    lines = [
        "# SECURITY_REVIEW_RESULTS",
        "",
    ]
    if incomplete:
        # Prominent marker directly under the H1 — NOT a buried Coverage-Gaps
        # bullet (Claude M2 / DeepSeek #15). One or more analysis waves produced
        # no findings file, so the audit is not exhaustive.
        lines.append(
            "> 🚨 **INCOMPLETE AUDIT** — one or more analysis waves did not "
            "produce findings (see `## Coverage Gaps`). Treat the results below "
            "as a partial review, not a clean bill of health."
        )
        lines.append("")
    lines.extend([
        "## Executive Summary",
        "",
        f"- Total findings: {total_counted}",
        f"- After dedup: {len(merged)}",
        f"- Manual review required: {len(manual)}"
        + (
            f" (custom sink: {custom_sink_count}, parse failed: {parse_failed_count})"
            if parse_failed_count
            else ""
        ),
    ])
    for sev in ("Critical", "High", "Medium"):
        lines.append(f"- {sev}: {by_sev.get(sev, 0)}")

    # Dedup-quality stat: aggregate counts of heuristic flags across both
    # merged and manual collections. Surfaced only when at least one is
    # non-zero — keeps clean runs noise-free.
    all_findings = list(merged) + list(manual)
    hash_mismatch_merges = sum(
        1 for f in all_findings if FLAG_MERGED_DESPITE_HASH_MISMATCH in f.flags
    )
    cross_sink_merges = sum(
        1 for f in all_findings if FLAG_CROSS_SINK_MERGE in f.flags
    )
    parse_failures = sum(
        1 for f in all_findings if FLAG_PARSE_FAILED in f.flags
    )
    if hash_mismatch_merges or cross_sink_merges or parse_failures:
        lines.append(
            f"- Dedup quality: {hash_mismatch_merges} hash-mismatch merges, "
            f"{cross_sink_merges} cross-sink merges, "
            f"{parse_failures} parse failures"
        )
    if refute_summary:
        # Shown only when adversarial pass actually ran (refute_summary != None).
        # `confirmed` = main findings without [REFUTE_CLAIMED];
        # `refute_claimed` = main findings refuted with valid evidence;
        # `refute_invalid` = refute records that failed auto-validation;
        # `manual_review` mirrors the manual_review.md count for completeness;
        # `parse_failed` derived locally from manual flags (so the renderer
        # owns the count semantics, not refute.py).
        lines.append("")
        lines.append("### Adversarial refute pass — by state")
        lines.append("")
        lines.append(f"- Confirmed (no refute claim): {refute_summary.get('confirmed', 0)}")
        lines.append(
            f"- Refute claimed (valid evidence, [REFUTE_CLAIMED] tag): "
            f"{refute_summary.get('refute_claimed', 0)}"
        )
        lines.append(
            f"- Refute invalid (rejected, see `{details_dirname}/refute_invalid.md`): "
            f"{refute_summary.get('refute_invalid', 0)}"
            if details_dirname
            else f"- Refute invalid (rejected, see refute_invalid.md): "
            f"{refute_summary.get('refute_invalid', 0)}"
        )
        lines.append(f"- Manual review: {refute_summary.get('manual_review', 0)}")
        lines.append(f"- Parse failed: {parse_failed_count}")
    lines.append("")
    if manual:
        manual_ref = (
            f"`{details_dirname}/manual_review.md`" if details_dirname else "manual_review section below"
        )
        lines.append(
            f"> ⚠️ **Action required:** {len(manual)} finding(s) need manual inspection — "
            f"see {manual_ref}. These did not auto-promote (custom sink_kind or parse "
            f"failures) but may still encode real vulnerabilities."
        )
        lines.append("")
    lines.extend(_render_coverage_gaps(coverage_gaps))
    coverage_lines = _render_checklist_coverage(
        waves_plan, merged, plugin_root or _default_plugin_root()
    )
    lines.extend(coverage_lines)
    lines.extend(_render_diff_block(diff))
    from .cost import render_cost_block
    lines.extend(render_cost_block(cost))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Single-file (legacy) report.
# ---------------------------------------------------------------------------


def render_report(
    merged: list[MergedFinding],
    manual: list[MergedFinding],
    *,
    diff=None,
    cost=None,
    refute_summary: dict[str, int] | None = None,
    waves_plan: list[dict] | None = None,
    plugin_root: Path | None = None,
    coverage_gaps: list[str] | None = None,
    incomplete: bool = False,
) -> str:
    """Legacy single-file report (all findings inline)."""
    out = [render_summary(
        merged, manual,
        diff=diff,
        cost=cost,
        refute_summary=refute_summary,
        waves_plan=waves_plan,
        plugin_root=plugin_root,
        coverage_gaps=coverage_gaps,
        incomplete=incomplete,
    )]
    out.append("## Findings")
    out.append("")
    for idx, mf in enumerate(merged, start=1):
        out.append(render_finding(idx, mf))
    if manual:
        out.append("## Manual review required")
        out.append("")
        out.append(
            "Findings that could not be automatically deduped (custom "
            "sink kinds, unknown enclosing symbols, or parse failures). "
            "Inspect each — these may include real vulnerabilities."
        )
        out.append("")
        for idx, mf in enumerate(manual, start=1):
            out.append(render_finding(idx, mf))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Split-report rendering (index + per-family details).
# ---------------------------------------------------------------------------


def _family_slug(family: str) -> str:
    """Map root_cause_family to a filesystem-safe slug for detail files."""
    if not family:
        return "uncategorized"
    slug = re.sub(r"[^a-z0-9_]+", "_", family.lower()).strip("_")
    return slug or "uncategorized"


def _group_by_family(findings: list[MergedFinding]) -> dict[str, list[MergedFinding]]:
    groups: dict[str, list[MergedFinding]] = {}
    for mf in findings:
        family = mf.primary.root_cause_family or "uncategorized"
        if family.startswith("other:"):
            family = family.split(":", 1)[1].strip() or "uncategorized"
        groups.setdefault(family, []).append(mf)
    return groups


def render_index_report(
    merged: list[MergedFinding],
    manual: list[MergedFinding],
    details_dirname: str,
    *,
    diff=None,
    cost=None,
    refute_summary: dict[str, int] | None = None,
    waves_plan: list[dict] | None = None,
    plugin_root: Path | None = None,
    coverage_gaps: list[str] | None = None,
    incomplete: bool = False,
) -> str:
    """Executive summary + index table linking to per-family detail files."""
    out = [
        render_summary(
            merged,
            manual,
            details_dirname=details_dirname,
            diff=diff,
            cost=cost,
            refute_summary=refute_summary,
            waves_plan=waves_plan,
            plugin_root=plugin_root,
            coverage_gaps=coverage_gaps,
            incomplete=incomplete,
        )
    ]
    out.append("## Findings by category")
    out.append("")

    if not merged and not manual:
        out.append("_No findings._")
        out.append("")
    else:
        groups = _group_by_family(merged)
        if groups:
            out.append("| Severity | File:Line | Category | sink_kind | Details |")
            out.append("|---|---|---|---|---|")
            for mf in sorted(
                merged,
                key=lambda m: (-SEVERITY_RANK[m.severity], m.primary.sink_file, m.primary.sink_line),
            ):
                family = mf.primary.root_cause_family or "uncategorized"
                if family.startswith("other:"):
                    family = family.split(":", 1)[1].strip() or "uncategorized"
                family_slug = _family_slug(family)
                category = (", ".join(mf.categories) or mf.primary.category or "—").replace("|", "\\|")
                file_loc = f"`{mf.primary.sink_file}:{mf.primary.sink_line}`"
                kind_text = mf.primary.sink_kind or "—"
                if mf.alternative_sink_kinds:
                    kind_text += f" (+{len(mf.alternative_sink_kinds)} alt)"
                detail_link = f"[{family}]({details_dirname}/{family_slug}.md)"
                out.append(f"| {mf.severity} | {file_loc} | {category} | `{kind_text}` | {detail_link} |")
            out.append("")

        if manual:
            parse_failed = sum(1 for m in manual if FLAG_PARSE_FAILED in m.flags)
            breakdown = ""
            if parse_failed:
                breakdown = f" (custom sink: {len(manual) - parse_failed}, parse failed: {parse_failed})"
            out.append(f"### Manual review: {len(manual)} finding(s){breakdown}")
            out.append("")
            out.append(f"See [`{details_dirname}/manual_review.md`]({details_dirname}/manual_review.md).")
            out.append("")

    return "\n".join(out)


def render_family_detail(family: str, findings: list[MergedFinding]) -> str:
    """Per-family detail file with full finding bodies."""
    out = [f"# SECURITY_REVIEW_RESULTS — {family}", ""]
    out.append(f"Findings grouped by `root_cause_family={family}`.")
    out.append(f"Total: {len(findings)}. Ordered by severity desc.")
    out.append("")
    sorted_findings = sorted(
        findings,
        key=lambda m: (-SEVERITY_RANK[m.severity], m.primary.sink_file, m.primary.sink_line),
    )
    for idx, mf in enumerate(sorted_findings, start=1):
        out.append(render_finding(idx, mf))
    return "\n".join(out)


def render_manual_review_file(manual: list[MergedFinding]) -> str:
    out = ["# SECURITY_REVIEW_RESULTS — Manual review", ""]
    out.append(
        "Findings that require manual inspection. Two categories:"
    )
    out.append("")
    out.append(
        "1. **Custom sink kinds / unknown symbols** — could not be automatically "
        "deduped AND did not meet auto-promote criteria (severity≥High + "
        "confidence≥8 + known symbol). Each may still be a real vulnerability."
    )
    out.append(
        f"2. **Parse failures** (flag `{FLAG_PARSE_FAILED}`) — worker output lacked "
        "`sink_file`, so the dedup pipeline could not assign a stable key. "
        "Read each one — the vulnerability description may be valid even if "
        "the navigation metadata is broken."
    )
    out.append("")
    for idx, mf in enumerate(manual, start=1):
        out.append(render_finding(idx, mf))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# File output.
# ---------------------------------------------------------------------------


def _write_reflowed(path: Path, text: str) -> None:
    path.write_text(reflow_markdown(text), encoding="utf-8")


def write_split_report(
    merged: list[MergedFinding],
    manual: list[MergedFinding],
    output_path: Path,
    details_dir: Path,
    *,
    diff=None,
    cost=None,
    refute_summary: dict[str, int] | None = None,
    waves_plan: list[dict] | None = None,
    plugin_root: Path | None = None,
    coverage_gaps: list[str] | None = None,
    incomplete: bool = False,
) -> list[Path]:
    """Write index + per-family detail files. Returns list of written paths."""
    details_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    relname = details_dir.name
    _write_reflowed(
        output_path,
        render_index_report(
            merged, manual, relname,
            diff=diff,
            cost=cost,
            refute_summary=refute_summary,
            waves_plan=waves_plan,
            plugin_root=plugin_root,
            coverage_gaps=coverage_gaps,
            incomplete=incomplete,
        ),
    )
    written.append(output_path)

    groups = _group_by_family(merged)
    for family, group in sorted(groups.items()):
        slug = _family_slug(family)
        detail_path = details_dir / f"{slug}.md"
        _write_reflowed(detail_path, render_family_detail(family, group))
        written.append(detail_path)

    if manual:
        mr_path = details_dir / "manual_review.md"
        _write_reflowed(mr_path, render_manual_review_file(manual))
        written.append(mr_path)

    return written
