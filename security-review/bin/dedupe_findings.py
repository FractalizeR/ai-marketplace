#!/usr/bin/env python3
"""Deduplicate security findings across per-wave output files.

CLI entry point. All logic lives in the `dedupe` package.

stdlib only. No external dependencies.

Usage:
    # v3 layout — primary
    dedupe_findings.py --input-glob "<review_root>/waves/*.md" \
                       --output "<review_root>/REPORT.md"

    # Legacy v2 layout — supported via fallback regex
    dedupe_findings.py --input-glob "SECURITY_REVIEW_RESULTS_*.md" \
                       --output SECURITY_REVIEW_RESULTS.md

Besides REPORT.md (+ per-family detail files), every run also writes
<review_root>/findings.json — the schema_version-gated public inter-plugin
contract listing every constituent finding across all three worker verdicts
(confirmed / needs_validation / hardening); see dedupe/export.py. --verdicts-in
folds externally-produced verdicts back in, validated against a prior run's
findings.json by content hash.
"""

from __future__ import annotations

import argparse
import glob as globmod
import hashlib
import json
import sys
from pathlib import Path

# Allow running as standalone script: add bin/ to sys.path so `import dedupe`
# resolves to the local package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dedupe.cost import estimate_cost  # noqa: E402
from dedupe.export import FINDINGS_JSON_NAME, SCHEMA_VERSION as FINDINGS_SCHEMA_VERSION, write_findings_json  # noqa: E402
from dedupe.models import FLAG_PARSE_FAILED  # noqa: E402
from dedupe.parser import parse_wave  # noqa: E402
from dedupe.pipeline import attach_side_records, dedupe  # noqa: E402
from dedupe.renderer import _write_reflowed, render_report, write_split_report  # noqa: E402
import validate_context as _vc  # noqa: E402
from dedupe.state import (  # noqa: E402
    VerdictsInError,
    active_rejections,
    load_resolutions,
    load_verdicts_in,
    save_state,
)


def _waves_balanced_models() -> dict[str, str]:
    """Return `{wave_id: balanced_model}` from plan_waves.

    Imported lazily so that cost estimation never breaks dedupe in environments
    where `plan_waves` is unavailable (e.g. third-party invocations bundling
    dedupe alone). Returns `{}` on any import failure — `estimate_cost` then
    classifies every slice as unmapped, which is harmless.
    """
    try:
        import plan_waves  # type: ignore  # bin/ already on sys.path
    except Exception:
        return {}
    out: dict[str, str] = {}
    for wave in plan_waves.WAVES:
        out[wave.wave_id] = wave.balanced_model
    out["WINF"] = plan_waves._winf_spec().balanced_model  # noqa: SLF001
    # Literal, not read from plan_waves: the gap wave is defined there and must
    # agree (a parity test pins it), but cost estimation must not depend on it.
    out["WGAP"] = "opus"
    return out


def collect_input_paths(inputs: list[str], input_glob: str | None) -> list[Path]:
    paths: list[Path] = []
    for inp in inputs:
        p = Path(inp)
        if p.is_file():
            paths.append(p)
    if input_glob:
        for match in globmod.glob(input_glob):
            mp = Path(match)
            if mp.is_file() and mp not in paths:
                paths.append(mp)
    return sorted(set(paths))


# The bare tokens recon writes into `console_gap_reason` read, in a report, as
# if the tool had made the call. Naming who asked keeps a reader from filing an
# operator's deliberate static-only run as a defect (and vice versa).
_GAP_REASON_PROSE = {
    "console_disabled_by_flag": (
        "console_disabled_by_flag (--no-console was passed; static-only run requested)"
    ),
}


def read_coverage_gaps(review_root: Path) -> list[str]:
    """Best-effort: surface recon-level coverage gaps from <review_root>/CONTEXT.md.

    Reads `frontmatter.environment.console_gap` (set by recon_inventory when
    console enrichment was applicable but did not run — containerized project
    with no `--console-cmd`, or `--no-console`). Returns human-readable lines
    for the REPORT.md `## Coverage Gaps` section. Any failure (no CONTEXT.md,
    parse error, missing block) → `[]` so dedupe never breaks on it.
    """
    ctx = review_root / "CONTEXT.md"
    if not ctx.is_file():
        return []
    try:
        text = ctx.read_text(encoding="utf-8")
        m = _vc.FRONTMATTER_RE.match(text)
        if not m:
            return []
        fm = _vc.parse_yaml_subset(m.group(1))
    except Exception:
        return []
    env = fm.get("environment") if isinstance(fm, dict) else None
    if not isinstance(env, dict) or not env.get("console_gap"):
        return []
    reason = env.get("console_gap_reason") or "console enrichment not performed"
    reason = _GAP_REASON_PROSE.get(reason, reason)
    mode = env.get("console_mode", "disabled")
    return [
        f"Console enrichment not performed (console_mode={mode}): {reason}. "
        "Dynamically registered routes / CLI commands may be missing from the "
        "attack surface; re-run with `--console-cmd` to enumerate them."
    ]


RECON_GAPS_NAME = "recon_gaps.json"
RECON_GAPS_SCHEMA_VERSION = 1
_NOT_REVIEWED_PREVIEW = 5

_RECON_GAP_HEADS = {
    "coverage": "Recon enumerated fewer entities than the source contains",
    "extractor_failed": "Recon extractor failed",
    "uninterpreted": "Recon found configuration it could not interpret",
}


def _plan_target_files(waves_plan: list[dict] | None) -> set[str] | None:
    """Union of `target_files` over every planned slice; None without a plan."""
    if waves_plan is None:
        return None
    out: set[str] = set()
    for entry in waves_plan:
        files = entry.get("target_files")
        if isinstance(files, list):
            out.update(f for f in files if isinstance(f, str))
    return out


def read_recon_gaps(review_root: Path, waves_plan: list[dict] | None) -> list[str]:
    """Surface recon-level gaps from `<review_root>/recon_gaps.json` (written by
    `validate_context.py --sanity --gaps-out`).

    Each entry's `files` are split into "routed to review" (listed in some
    slice's `target_files` of `waves_plan`; says nothing about whether that
    slice ran) and "NOT routed" (cut by the gap-wave
    cap, `--scope`, vendor/tests filtering, ...). Without a plan the split is
    undefined and only the file count is reported. Missing / corrupt file or
    empty `items` -> `[]`; an unknown `schema_version` -> warning + `[]`.
    """
    path = review_root / RECON_GAPS_NAME
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    if data.get("schema_version") != RECON_GAPS_SCHEMA_VERSION:
        print(
            f"Warning: {path} has schema_version {data.get('schema_version')!r} "
            f"(supported: {RECON_GAPS_SCHEMA_VERSION}); recon gaps are not reported",
            file=sys.stderr,
        )
        return []
    items = [i for i in (data.get("items") or []) if isinstance(i, dict)] if isinstance(data.get("items"), list) else []
    items.sort(key=lambda i: (str(i.get("kind", "")), str(i.get("section_path", "")), str(i.get("label", ""))))

    planned = _plan_target_files(waves_plan)
    lines: list[str] = []
    for item in items:
        kind = str(item.get("kind", ""))
        label = str(item.get("label", "")) or "?"
        section = str(item.get("section_path", "")) or "?"
        head = _RECON_GAP_HEADS.get(kind, "Recon gap")
        detail = f"{head}: `{label}` (section `{section}`"
        status = item.get("status")
        if status:
            detail += f", status {status}"
        detail += ")."
        reason = item.get("reason")
        if reason:
            detail += f" {reason}."
        if kind == "coverage" and item.get("declared") is not None and item.get("found") is not None:
            detail += f" Declared {item['declared']}, found {item['found']}"
            if item.get("missing_pct") is not None:
                detail += f" ({item['missing_pct']}% missing)"
            detail += "."
        raw_files = item.get("files")
        files = sorted({f for f in raw_files if isinstance(f, str)}) if isinstance(raw_files, list) else []
        if planned is None:
            detail += f" {len(files)} file(s) involved; review status unknown (no plan given)."
        else:
            routed = [f for f in files if f in planned]
            not_reviewed = [f for f in files if f not in planned]
            detail += (
                f" {len(routed)} routed to review (WGAP / focused waves), "
                f"{len(not_reviewed)} NOT routed"
            )
            if not_reviewed:
                shown = ", ".join(f"`{f}`" for f in not_reviewed[:_NOT_REVIEWED_PREVIEW])
                more = len(not_reviewed) - _NOT_REVIEWED_PREVIEW
                detail += f" ({shown}{f', +{more} more' if more > 0 else ''})"
            detail += "."
        lines.append(detail)
    return lines


def _parsed_wave_slice_ids(paths: list[Path]) -> set[str]:
    """Slice ids of wave files that exist and parse."""
    ok: set[str] = set()
    for p in paths:
        try:
            parse_wave(p)
        except Exception:
            continue
        ok.add(p.stem)
    return ok


def read_dispatch_gaps(path: Path | None, recovered: set[str] = frozenset()) -> list[str]:
    """Surface wave-dispatch execution gaps from a `dispatch_gaps.json` file.

    The file is written by `shared.dispatch.write_dispatch_gaps` (a file
    contract, no import): a JSON list of `{slice_id, reason, returncode}`. Each
    entry becomes one deterministic human line for the REPORT.md `## Coverage
    Gaps` section. None / missing / corrupt → `[]` so dedupe never breaks on it.
    A gap whose slice id is in `recovered` (its wave file was written after the
    dispatcher ran, e.g. by the orchestrator's safety net) is no longer a gap.
    """
    if path is None:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    lines: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        slice_id = entry.get("slice_id", "?")
        if slice_id in recovered:
            continue
        reason = entry.get("reason", "unknown")
        lines.append(
            f"Wave {slice_id} produced no findings file (reason: {reason}). "
            "Coverage is INCOMPLETE."
        )
    return lines


def read_reference_findings_json(review_root: Path) -> tuple[bytes, dict] | None:
    """Read `<review_root>/findings.json` AS IT EXISTS RIGHT NOW, before this
    run's `write_findings_json` overwrites it. This is the reference an
    external `--verdicts-in` file is validated against: a future ticket-
    triage tool reads a previous run's on-disk `findings.json`, hashes those
    exact bytes, and stamps that hash into the verdicts it later hands back —
    so the reference MUST be the pre-existing file, not a value freshly
    recomputed from this run's (possibly different) waves. Returns `None` on
    any absence/corruption/schema mismatch — callers treat that as "refuse
    the import", never as "proceed without it".
    """
    target = review_root / FINDINGS_JSON_NAME
    if not target.is_file():
        return None
    try:
        raw = target.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != FINDINGS_SCHEMA_VERSION:
        return None
    return raw, payload


def _sink_hashes_from_findings_payload(payload: dict) -> set[str]:
    out: set[str] = set()
    for key in ("confirmed", "needs_validation", "hardening"):
        for entry in payload.get(key) or []:
            if isinstance(entry, dict) and isinstance(entry.get("sink_hash"), str):
                out.add(entry["sink_hash"])
    return out


def load_waves_plan(path: Path | None) -> list[dict] | None:
    if path is None:
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        print(
            f"Warning: could not read --waves-plan {path}: {exc}; "
            "skipping coverage block",
            file=sys.stderr,
        )
        return None
    if not isinstance(loaded, list):
        print(
            f"Warning: --waves-plan {path} root is not a list "
            f"({type(loaded).__name__}); skipping coverage block",
            file=sys.stderr,
        )
        return None
    # Skip non-dict entries silently — defensive against minor schema drift;
    # renderer further validates per-entry shape.
    return [s for s in loaded if isinstance(s, dict)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deduplicate security findings")
    parser.add_argument("--input", action="append", default=[], help="Per-wave finding file (repeatable). v3: <review_root>/waves/<slice_id>.md")
    parser.add_argument("--input-glob", default=None, help="Glob pattern for inputs (e.g. <review_root>/waves/*.md)")
    parser.add_argument("--output", type=Path, required=True, help="Output index file (v3: <review_root>/REPORT.md)")
    parser.add_argument(
        "--details-dir",
        type=Path,
        default=None,
        help="Directory for per-family detail files. Defaults to <output_stem>/",
    )
    parser.add_argument(
        "--single-file",
        action="store_true",
        help="Emit a single monolithic report (legacy behaviour, no detail directory).",
    )
    parser.add_argument(
        "--no-state",
        action="store_true",
        help="Skip the verdict journal: remembered resolutions are neither read "
             "from nor written to .findings_state.json.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Project root that --verdicts-in evidence paths (refute_file) are "
        "resolved against. Default: cwd.",
    )
    parser.add_argument(
        "--waves-plan",
        type=Path,
        default=None,
        help="Path to waves_plan.json saved by plan_waves.py --save-plan. "
        "When supplied, renderer adds `## Checklist coverage` block to the "
        "executive summary listing each checklist's activation status.",
    )
    parser.add_argument(
        "--dispatch-gaps",
        type=Path,
        default=None,
        help="Path to dispatch_gaps.json (written by shared/dispatch.py "
        "--allow-gaps). When omitted, defaults to <output.parent>/"
        "dispatch_gaps.json. Missing/corrupt → no dispatch gaps. Each gap is "
        "folded into the `## Coverage Gaps` section and triggers a prominent "
        "INCOMPLETE marker.",
    )
    parser.add_argument(
        "--verdicts-in",
        type=Path,
        default=None,
        help="Path to a JSON file of externally-produced verdicts (e.g. from "
        "a ticket-triage plugin) to fold in as remembered resolutions. "
        "Bound to the PRE-EXISTING <review_root>/findings.json by content "
        "hash — fail-closed: any schema violation, unknown field, unknown "
        "sink_hash, duplicate, or stale hash aborts the whole run before "
        "any output is written. Requires cross-run state (incompatible with "
        "--no-state).",
    )
    args = parser.parse_args(argv)

    review_root = args.output.parent

    if args.verdicts_in is not None and args.no_state:
        print("Error: --verdicts-in requires cross-run state; cannot combine with --no-state", file=sys.stderr)
        return 2

    verdicts_in_resolutions: dict = {}
    if args.verdicts_in is not None:
        reference = read_reference_findings_json(review_root)
        if reference is None:
            print(
                f"Error: --verdicts-in given but no usable prior "
                f"{FINDINGS_JSON_NAME} found under {review_root} to validate against",
                file=sys.stderr,
            )
            return 2
        reference_bytes, reference_payload = reference
        try:
            verdicts_in_resolutions = load_verdicts_in(
                args.verdicts_in,
                valid_sink_hashes=_sink_hashes_from_findings_payload(reference_payload),
                findings_json_sha256=hashlib.sha256(reference_bytes).hexdigest(),
                project_root=args.project_root,
            )
        except VerdictsInError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    # Default the dispatch-gaps path under the output's review root. A missing
    # file is a no-op ([]), so a clean run with no dispatch_gaps.json is silent.
    dispatch_gaps_path = (
        args.dispatch_gaps
        if args.dispatch_gaps is not None
        else review_root / "dispatch_gaps.json"
    )
    paths = collect_input_paths(args.input, args.input_glob)
    dispatch_gap_lines = read_dispatch_gaps(dispatch_gaps_path, _parsed_wave_slice_ids(paths))
    incomplete = bool(dispatch_gap_lines)
    waves_plan = load_waves_plan(args.waves_plan)
    recon_gap_lines = read_recon_gaps(review_root, waves_plan)

    if not paths:
        # ZERO-INPUT PASS (Codex #9): all waves failed → no findings files, but
        # dispatch recorded gaps. Render a minimal INCOMPLETE report instead of
        # crashing with exit 2, so the operator sees the coverage gaps + marker.
        if not incomplete:
            print("Error: no input files found", file=sys.stderr)
            return 2
        coverage_gaps = read_coverage_gaps(review_root) + recon_gap_lines + dispatch_gap_lines
        details_dir = args.details_dir or args.output.parent / args.output.stem
        write_split_report(
            [],
            [],
            args.output,
            details_dir,
            coverage_gaps=coverage_gaps,
            incomplete=True,
        )
        # findings.json is the public contract (P2.4) — write it every run,
        # empty payload included, so a consumer never has to guess whether a
        # stale file from a previous run is still current.
        write_findings_json(review_root, [], [], [], [])
        print(
            f"Wrote {args.output} (INCOMPLETE: no input findings; "
            f"{len(dispatch_gap_lines)} dispatch gap(s))"
        )
        return 0

    all_findings = []
    all_needs_validation = []
    all_hardening = []
    for p in paths:
        wave = parse_wave(p)
        all_findings.extend(wave.findings)
        all_needs_validation.extend(wave.needs_validation)
        all_hardening.extend(wave.hardening)

    merged, manual = dedupe(all_findings)
    parse_failed_count = sum(1 for m in manual if FLAG_PARSE_FAILED in m.flags)

    # Verdict-bucket attachment (P2.2/P2.4). The union `merged + manual` is
    # mandatory, not just `merged`: a finding that fails custom-sink
    # auto-promotion lands in `manual`, and only this union call lets its
    # attached annotations render (see `pipeline.attach_side_records`'s own
    # docstring and `AttachSideRecordsSpyTests` in test_dedupe_findings.py).
    side_records = attach_side_records(merged + manual, all_needs_validation, all_hardening)

    # `--no-state` (or an output without a parent directory) skips the
    # load/save round-trip of remembered verdicts entirely.
    state_usable = not args.no_state and str(review_root) not in ("", ".")

    # Cross-run resolution memory (Stage 2 / P2.5): REMEMBERED rejections from
    # prior runs (--verdicts-in) that still hold —
    # `active_rejections` re-validates each one's evidence against the CURRENT
    # project tree, so a removed protection silently drops the mark rather
    # than mis-annotating a regression as "already reviewed".
    prior_resolutions = load_resolutions(review_root) if state_usable else {}
    render_resolutions = {**active_rejections(prior_resolutions, args.project_root), **verdicts_in_resolutions}

    # Resolutions to PERSIST this run: freshly-imported --verdicts-in records.
    # `save_state` merges them into history; it does not need
    # `render_resolutions`, which already carries the (possibly stale,
    # re-validated) history.
    new_resolutions = verdicts_in_resolutions

    # Coverage gaps: recon-level (console enrichment skipped, from CONTEXT.md;
    # sanity gaps, from recon_gaps.json) PLUS wave-dispatch execution gaps
    # (from dispatch_gaps.json). All render under `## Coverage Gaps`; only the
    # dispatch gaps drive the prominent INCOMPLETE marker via `incomplete`.
    coverage_gaps = read_coverage_gaps(review_root) + recon_gap_lines + dispatch_gap_lines

    cost = estimate_cost(paths, _waves_balanced_models())

    if args.single_file:
        _write_reflowed(
            args.output,
            render_report(
                merged, manual,
                cost=cost,
                waves_plan=waves_plan,
                coverage_gaps=coverage_gaps,
                incomplete=incomplete,
                unmatched_needs_validation=side_records.unmatched_needs_validation,
                unmatched_hardening=side_records.unmatched_hardening,
                resolutions=render_resolutions,
            ),
        )
        write_findings_json(
            review_root, merged, manual,
            side_records.unmatched_needs_validation,
            side_records.unmatched_hardening,
        )
        if state_usable:
            save_state(review_root, resolutions=new_resolutions)
        print(
            f"Wrote {args.output} "
            f"({len(merged)} merged, {len(manual)} manual, "
            f"{parse_failed_count} parse-failed in manual)"
        )
        return 0

    details_dir = args.details_dir or args.output.parent / args.output.stem
    written = write_split_report(
        merged,
        manual,
        args.output,
        details_dir,
        cost=cost,
        waves_plan=waves_plan,
        coverage_gaps=coverage_gaps,
        incomplete=incomplete,
        unmatched_needs_validation=side_records.unmatched_needs_validation,
        unmatched_hardening=side_records.unmatched_hardening,
        resolutions=render_resolutions,
    )
    write_findings_json(
        review_root, merged, manual,
        side_records.unmatched_needs_validation,
        side_records.unmatched_hardening,
    )
    if state_usable:
        save_state(review_root, resolutions=new_resolutions)
    print(
        f"Wrote {args.output} + {len(written) - 1} detail file(s) in {details_dir} "
        f"({len(merged)} merged, {len(manual)} manual, "
        f"{parse_failed_count} parse-failed in manual)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
