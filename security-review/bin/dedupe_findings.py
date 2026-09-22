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
from dedupe.refute import (  # noqa: E402
    apply_refute_records,
    compute_refute_summary,
    parse_refute_md,
    write_refute_invalid_md,
)
from dedupe.renderer import _write_reflowed, render_report, write_split_report  # noqa: E402
import validate_context as _vc  # noqa: E402
from dedupe.state import (  # noqa: E402
    VerdictsInError,
    active_rejections,
    compute_diff,
    compute_run_id,
    load_continuation_baseline,
    load_resolutions,
    load_state,
    load_verdicts_in,
    resolutions_from_refuted_findings,
    save_state,
    snapshots_from,
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


def read_dispatch_gaps(path: Path | None) -> list[str]:
    """Surface wave-dispatch execution gaps from a `dispatch_gaps.json` file.

    The file is written by `shared.dispatch.write_dispatch_gaps` (a file
    contract, no import): a JSON list of `{slice_id, reason, returncode}`. Each
    entry becomes one deterministic human line for the REPORT.md `## Coverage
    Gaps` section. None / missing / corrupt → `[]` so dedupe never breaks on it.
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
        help="Skip cross-run findings-state load/save (no .findings_state.json read or written).",
    )
    parser.add_argument(
        "--refute",
        type=Path,
        default=None,
        help="Path to <review_root>/refute.md emitted by security-refute agent. "
        "When supplied, refute records are applied to the merged findings (tag "
        "[REFUTE_CLAIMED] + counters in executive summary) and a "
        "refute_invalid.md audit file is emitted under --details-dir.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Project root for refute evidence validation (refute_file paths "
        "in refute.md are resolved relative to this directory). Default: cwd.",
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
    dispatch_gap_lines = read_dispatch_gaps(dispatch_gaps_path)
    incomplete = bool(dispatch_gap_lines)

    paths = collect_input_paths(args.input, args.input_glob)
    if not paths:
        # ZERO-INPUT PASS (Codex #9): all waves failed → no findings files, but
        # dispatch recorded gaps. Render a minimal INCOMPLETE report instead of
        # crashing with exit 2, so the operator sees the coverage gaps + marker.
        if not incomplete:
            print("Error: no input files found", file=sys.stderr)
            return 2
        coverage_gaps = read_coverage_gaps(review_root) + dispatch_gap_lines
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

    # Verdict-bucket attachment (P2.2/P2.4), explicitly BEFORE the refute
    # pass below. Order is not load-bearing for correctness — refute.py never
    # reconstructs a MergedFinding (no `MergedFinding(` call site in that
    # module), so attached needs_validation/hardening annotations survive a
    # later refute pass unchanged either way — but attaching first means
    # findings.json and the report reflect buckets even on a run with no
    # --refute at all. The union `merged + manual` is mandatory, not just
    # `merged`: a finding that fails custom-sink auto-promotion lands in
    # `manual`, and only this union call lets its attached annotations render
    # (see `pipeline.attach_side_records`'s own docstring and
    # `AttachSideRecordsSpyTests` in test_dedupe_findings.py).
    side_records = attach_side_records(merged + manual, all_needs_validation, all_hardening)

    # Adversarial pass: apply refute.md records on top of dedupe output.
    refute_summary: dict[str, int] | None = None
    refute_invalid_count = 0
    refute_claimed_count = 0
    refute_invalid_records: list = []
    if args.refute is not None:
        records = parse_refute_md(args.refute)
        merged, refute_invalid_records = apply_refute_records(
            merged, records, args.project_root
        )
        refute_summary = compute_refute_summary(merged, manual, refute_invalid_records)
        refute_claimed_count = refute_summary["refute_claimed"]
        refute_invalid_count = refute_summary["refute_invalid"]

    # Cross-run diff: load previous state from <review_root> = output.parent.
    # When --no-state is passed (or output happens to lack a parent on weird
    # invocations) we skip the load/save round-trip entirely.
    #
    # A second pass over the SAME wave files — the refute pass, an imported-
    # verdicts pass, a plain re-render — re-states one run rather than taking a
    # fresh look at the code. Diffing it against the state its own first pass
    # just wrote would report every finding as recurring and none as new, so it
    # inherits that pass's baseline and persists it unchanged. Sameness is
    # decided by the wave files themselves, not by which flags were passed.
    snapshots = snapshots_from(merged, manual)
    diff = None
    baseline = None
    run_id = compute_run_id(paths)
    state_usable = not args.no_state and str(review_root) not in ("", ".")
    if state_usable:
        continuation, baseline = load_continuation_baseline(review_root, run_id)
        if not continuation:
            baseline = load_state(review_root)
        diff = compute_diff(baseline, snapshots)

    # Cross-run resolution memory (Stage 2 / P2.5): REMEMBERED rejections from
    # prior runs (adversarial refute and/or --verdicts-in) that still hold —
    # `active_rejections` re-validates each one's evidence against the CURRENT
    # project tree, so a removed protection silently drops the mark rather
    # than mis-annotating a regression as "already reviewed". THIS run's own
    # fresh refute claims are NOT included here: they already render via the
    # live `[REFUTE_CLAIMED]` blockquote (see `renderer.render_finding`), so
    # folding them in too would be redundant, not wrong.
    prior_resolutions = load_resolutions(review_root) if state_usable else {}
    render_resolutions = {**active_rejections(prior_resolutions, args.project_root), **verdicts_in_resolutions}

    # Resolutions to PERSIST this run: this run's fresh refute claims plus any
    # freshly-imported --verdicts-in records (which win on a same-sink_hash
    # collision — human triage supersedes the automated pass). `save_state`
    # merges these into history; it does not need `render_resolutions`, which
    # already carries the (possibly stale, re-validated) history — persisting
    # the same rejected-but-filtered-out prior entries again would just be a
    # no-op churn on `run_seq`.
    new_resolutions = {**resolutions_from_refuted_findings(merged, args.project_root), **verdicts_in_resolutions}

    # Coverage gaps: recon-level (console enrichment skipped, from CONTEXT.md)
    # PLUS wave-dispatch execution gaps (from dispatch_gaps.json). Both render
    # under `## Coverage Gaps`; the dispatch gaps additionally drive the
    # prominent INCOMPLETE marker via `incomplete`.
    coverage_gaps = read_coverage_gaps(review_root) + dispatch_gap_lines

    cost = estimate_cost(paths, _waves_balanced_models())

    waves_plan: list[dict] | None = None
    if args.waves_plan is not None:
        try:
            text = args.waves_plan.read_text(encoding="utf-8")
            loaded = json.loads(text)
            if isinstance(loaded, list):
                # Skip non-dict entries silently — defensive against minor
                # schema drift; renderer further validates per-entry shape.
                waves_plan = [s for s in loaded if isinstance(s, dict)]
            else:
                print(
                    f"Warning: --waves-plan {args.waves_plan} root is not a list "
                    f"({type(loaded).__name__}); skipping coverage block",
                    file=sys.stderr,
                )
        except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
            print(
                f"Warning: could not read --waves-plan {args.waves_plan}: {exc}; "
                "skipping coverage block",
                file=sys.stderr,
            )

    refute_print_suffix = ""
    if args.refute is not None:
        refute_print_suffix = (
            f" + refute_claimed={refute_claimed_count}"
            f" + refute_invalid={refute_invalid_count}"
        )

    if args.single_file:
        _write_reflowed(
            args.output,
            render_report(
                merged, manual,
                diff=diff,
                cost=cost,
                refute_summary=refute_summary,
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
            save_state(snapshots, review_root, resolutions=new_resolutions, baseline=baseline, run_id=run_id)
        print(
            f"Wrote {args.output} "
            f"({len(merged)} merged, {len(manual)} manual, "
            f"{parse_failed_count} parse-failed in manual{refute_print_suffix})"
        )
        return 0

    details_dir = args.details_dir or args.output.parent / args.output.stem
    written = write_split_report(
        merged,
        manual,
        args.output,
        details_dir,
        diff=diff,
        cost=cost,
        refute_summary=refute_summary,
        waves_plan=waves_plan,
        coverage_gaps=coverage_gaps,
        incomplete=incomplete,
        unmatched_needs_validation=side_records.unmatched_needs_validation,
        unmatched_hardening=side_records.unmatched_hardening,
        resolutions=render_resolutions,
    )
    if args.refute is not None:
        # Emit audit log of refute records that failed validation. Always write
        # the file when --refute was supplied (even if empty) so operators see
        # an explicit "no invalid records" rather than missing artefact.
        write_refute_invalid_md(refute_invalid_records, details_dir / "refute_invalid.md")
    write_findings_json(
        review_root, merged, manual,
        side_records.unmatched_needs_validation,
        side_records.unmatched_hardening,
    )
    if state_usable:
        save_state(snapshots, review_root, resolutions=new_resolutions, baseline=baseline, run_id=run_id)
    print(
        f"Wrote {args.output} + {len(written) - 1} detail file(s) in {details_dir} "
        f"({len(merged)} merged, {len(manual)} manual, "
        f"{parse_failed_count} parse-failed in manual{refute_print_suffix})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
