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
"""

from __future__ import annotations

import argparse
import glob as globmod
import json
import sys
from pathlib import Path

# Allow running as standalone script: add bin/ to sys.path so `import dedupe`
# resolves to the local package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dedupe.cost import estimate_cost  # noqa: E402
from dedupe.models import FLAG_PARSE_FAILED  # noqa: E402
from dedupe.parser import parse_findings_file  # noqa: E402
from dedupe.pipeline import dedupe  # noqa: E402
from dedupe.refute import (  # noqa: E402
    apply_refute_records,
    compute_refute_summary,
    parse_refute_md,
    write_refute_invalid_md,
)
from dedupe.renderer import _write_reflowed, render_report, write_split_report  # noqa: E402
import validate_context as _vc  # noqa: E402
from dedupe.state import (  # noqa: E402
    compute_diff,
    load_state,
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
    args = parser.parse_args(argv)

    # Default the dispatch-gaps path under the output's review root. A missing
    # file is a no-op ([]), so a clean run with no dispatch_gaps.json is silent.
    dispatch_gaps_path = (
        args.dispatch_gaps
        if args.dispatch_gaps is not None
        else args.output.parent / "dispatch_gaps.json"
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
        review_root = args.output.parent
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
        print(
            f"Wrote {args.output} (INCOMPLETE: no input findings; "
            f"{len(dispatch_gap_lines)} dispatch gap(s))"
        )
        return 0

    all_findings = []
    for p in paths:
        all_findings.extend(parse_findings_file(p))

    merged, manual = dedupe(all_findings)
    parse_failed_count = sum(1 for m in manual if FLAG_PARSE_FAILED in m.flags)

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
    review_root = args.output.parent
    snapshots = snapshots_from(merged, manual)
    diff = None
    if not args.no_state and str(review_root) not in ("", "."):
        previous = load_state(review_root)
        diff = compute_diff(previous, snapshots)

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
            ),
        )
        if not args.no_state and str(review_root) not in ("", "."):
            save_state(snapshots, review_root)
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
    )
    if args.refute is not None:
        # Emit audit log of refute records that failed validation. Always write
        # the file when --refute was supplied (even if empty) so operators see
        # an explicit "no invalid records" rather than missing artefact.
        write_refute_invalid_md(refute_invalid_records, details_dir / "refute_invalid.md")
    if not args.no_state and str(review_root) not in ("", "."):
        save_state(snapshots, review_root)
    print(
        f"Wrote {args.output} + {len(written) - 1} detail file(s) in {details_dir} "
        f"({len(merged)} merged, {len(manual)} manual, "
        f"{parse_failed_count} parse-failed in manual{refute_print_suffix})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
