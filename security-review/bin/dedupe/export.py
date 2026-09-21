"""Serializer for `<review_root>/findings.json` — the public inter-plugin
contract (Stage 2 / P2.4, see memory/cloudflare-borrow-plan/03-verdict-buckets.md).

A second plugin (`fr-audit-triage`, Stage 4) reads this file via `json.load`,
not by regexing REPORT.md. That makes it a public contract, so this module
enforces three rules the prose-only REPORT.md never had to:

  1. **`schema_version`** lets a consumer tell "no file" apart from
     "different schema" — bump it on any incompatible shape change.
  2. **No field varies run-to-run for unchanged inputs.** No run id, no
     timestamp, nothing derived from wall-clock time. `findings.json` must be
     byte-identical across repeated `dedupe_findings.py` runs over the same
     wave files (unlike REPORT.md, whose `## Diff vs previous run` section
     differs between the first and later runs).
  3. **Every constituent `Finding` is exported, including ones absorbed
     into a `MergedFinding.merged_from` list** — not just the winning
     `primary`. `dedupe()` passes 2/3 can pick a different primary run to
     run (tie-break on confidence + body length), so a consumer building a
     `sink_hash` *set* across two runs must see the whole constituent
     multiset, or the set silently shrinks/changes on a primary-selection
     coin toss (this is exactly the live-validation metric in the Stage-2
     plan: `confirmed ∪ needs_validation` must be a superset of the baseline
     `confirmed` set).

`flags` on a `confirmed` entry is the *merge group's* `MergedFinding.flags`
(e.g. `[MERGED_DESPITE_HASH_MISMATCH]`, `[REFUTE_CLAIMED]`), replicated
identically on every constituent row of that group (primary and every
`merged_from` item) — it is not a per-Finding value, even though it sits on
a per-Finding row. A consumer joining rows by `primary_sink_hash` sees the
same `flags` on all of them by construction.

The output path is fixed at `<review_root>/findings.json` by
`write_findings_json` — deliberately no `--flag` for it in the CLI. The
public contract's location is not configurable surface: a stray flag value
could scatter it outside review_root the same way `--review-root=src` once
clobbered a project's `.gitignore` (see CLAUDE.md "review-root is
output-only").
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, HardeningNote, MergedFinding, NeedsValidation

SCHEMA_VERSION = 1

FINDINGS_JSON_NAME = "findings.json"


def _confirmed_entry(
    f: Finding, *, is_primary: bool, primary_sink_hash: str, review_bucket: str, group_flags: list[str]
) -> dict:
    return {
        "verdict": "confirmed",
        "sink_hash": f.sink_hash,
        "primary_sink_hash": primary_sink_hash,
        "is_primary": is_primary,
        "review_bucket": review_bucket,
        "sink_file": f.sink_file,
        "sink_line": f.sink_line,
        "sink_kind": f.sink_kind,
        "root_cause_family": f.root_cause_family,
        "enclosing_symbol": f.enclosing_symbol,
        "severity": f.severity,
        "confidence": f.confidence,
        "category": f.category,
        "condition_keys": list(f.condition_keys),
        "discovered_via": f.discovered_via,
        "source_file": f.source_file,
        "slice_id": f.slice_id,
        "flags": list(group_flags),
    }


def _confirmed_entries(group: list[MergedFinding], review_bucket: str) -> list[dict]:
    """One entry per constituent `Finding` (primary + every `merged_from`
    item), in `dedupe()`'s own deterministic group/list order — see the
    module docstring rule 3 for why the losers are not dropped."""
    out: list[dict] = []
    for mf in group:
        primary_hash = mf.primary.sink_hash
        out.append(
            _confirmed_entry(
                mf.primary, is_primary=True, primary_sink_hash=primary_hash,
                review_bucket=review_bucket, group_flags=mf.flags,
            )
        )
        for extra in mf.merged_from:
            out.append(
                _confirmed_entry(
                    extra, is_primary=False, primary_sink_hash=primary_hash,
                    review_bucket=review_bucket, group_flags=mf.flags,
                )
            )
    return out


def _nv_entry(nv: NeedsValidation, *, matched_to: str | None) -> dict:
    return {
        "verdict": "needs_validation",
        "sink_hash": nv.sink_hash,
        "matched_to": matched_to,
        "sink_file": nv.sink_file,
        "sink_line": nv.sink_line,
        "sink_kind": nv.sink_kind,
        "root_cause_family": nv.root_cause_family,
        "enclosing_symbol": nv.enclosing_symbol,
        "claimed_root_cause": nv.claimed_root_cause,
        "blockers": list(nv.blockers),
        "condition_keys": list(nv.condition_keys),
        "source_file": nv.source_file,
        "slice_id": nv.slice_id,
        "flags": list(nv.flags),
    }


def _hardening_entry(hn: HardeningNote, *, matched_to: str | None) -> dict:
    return {
        "verdict": "hardening",
        "sink_hash": hn.sink_hash,
        "matched_to": matched_to,
        "sink_file": hn.sink_file,
        "sink_line": hn.sink_line,
        "sink_kind": hn.sink_kind,
        "root_cause_family": hn.root_cause_family,
        "enclosing_symbol": hn.enclosing_symbol,
        "text": hn.text,
        "condition_keys": list(hn.condition_keys),
        "source_file": hn.source_file,
        "slice_id": hn.slice_id,
        "flags": list(hn.flags),
    }


def build_findings_export(
    merged: list[MergedFinding],
    manual: list[MergedFinding],
    unmatched_needs_validation: list[NeedsValidation],
    unmatched_hardening: list[HardeningNote],
) -> dict:
    """Build the `findings.json` payload as a plain dict (json-serializable).

    `merged`/`manual` must already carry `attach_side_records` annotations
    (`.needs_validation`/`.hardening`) — this function only reads them, it
    does not call `attach_side_records` itself. `matched_to` on an attached
    needs_validation/hardening entry is the *group's* `primary_sink_hash`,
    the same value a `confirmed` entry from that group carries — a consumer
    can join the three lists on it without re-deriving `sink_hash` matching.
    """
    confirmed = _confirmed_entries(merged, "main") + _confirmed_entries(manual, "manual_review")

    needs_validation: list[dict] = []
    hardening: list[dict] = []
    for mf in list(merged) + list(manual):
        primary_hash = mf.primary.sink_hash
        for nv in mf.needs_validation:
            needs_validation.append(_nv_entry(nv, matched_to=primary_hash))
        for hn in mf.hardening:
            hardening.append(_hardening_entry(hn, matched_to=primary_hash))

    # Same ordering as `renderer._render_needs_validation_section` /
    # `_render_hardening_section` for the standalone (unmatched) entries —
    # both are sorted (source_file, sink_file, sink_line) rather than left in
    # whatever order the caller collected them, "required for the run-2-vs
    # -run-3 byte-identity idempotency contract" per that module's own note.
    for nv in sorted(unmatched_needs_validation, key=lambda x: (x.source_file, x.sink_file, x.sink_line)):
        needs_validation.append(_nv_entry(nv, matched_to=None))
    for hn in sorted(unmatched_hardening, key=lambda x: (x.source_file, x.sink_file, x.sink_line)):
        hardening.append(_hardening_entry(hn, matched_to=None))

    return {
        "schema_version": SCHEMA_VERSION,
        "confirmed": confirmed,
        "needs_validation": needs_validation,
        "hardening": hardening,
    }


def write_findings_json(
    review_root: Path,
    merged: list[MergedFinding],
    manual: list[MergedFinding],
    unmatched_needs_validation: list[NeedsValidation],
    unmatched_hardening: list[HardeningNote],
) -> Path:
    """Write the public contract to `<review_root>/findings.json` and return
    its path. Overwrites unconditionally, same idempotency convention as
    `recon_inventory.py`/`dedupe_findings.py`'s other outputs (CLAUDE.md:
    "Idempotency in recon and dedup" — no append-only side effects)."""
    payload = build_findings_export(merged, manual, unmatched_needs_validation, unmatched_hardening)
    out_path = Path(review_root) / FINDINGS_JSON_NAME
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path
