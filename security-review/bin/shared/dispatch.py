#!/usr/bin/env python3
"""AD4 dispatch — external-process wave fan-out (≤6) + single-process role dispatch.

`dispatch_waves` launches one external worker per plan slice (≤6 concurrent),
classifies each as success/gap by a freshness-based protocol, and either raises
(strict) or writes `dispatch_gaps.json`. `dispatch_role` runs ONE process for a
single-writer role (recon/refute) and reports presence of its role artifact.

Subprocess is the single injected seam (the `runner` callable, AD-2A2) — no test
spawns a real `opencode`/`codex`. Harness command shapes enter as command-builder
parameters (AD-2A3). Freshness (AD-2A8): planned slices' expected wave files are
deleted before fan-out so a stale prior-run file + a crashed worker is still a gap.

CLI:
    python3 <core_root>/bin/shared/dispatch.py --plan P.json --model-map M.json
        --project-root P --review-root R --core-root C
        --worker-cmd-template "<tmpl>" [--max-parallel 6] [--allow-gaps] [--timeout S]
        | --role=recon|refute --role-cmd-template "<tmpl>"
    Template fields: {model}{project_root}{review_root}{core_root}{slice_id}{capture}{slice_config}.
    exit 0 all present / 1 gaps (allow-gaps) / 2 error (incl. DispatchGapError in strict).

stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

# Engine invocation convention: put `.../bin` on sys.path for `from shared...`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.contracts import (  # noqa: E402
    DispatchConfigError,
    DispatchGapError,
    RecoverCapture,
    RoleCommandBuilder,
    Roots,
    Runner,
    RunResult,
    WaveCommandBuilder,
)
from shared.model_resolver import LABEL_TO_TIER, TierMap  # noqa: E402

MAX_PARALLEL_HARD_CAP = 6

# role -> the single artifact whose fresh presence proves the role ran (Claude M3).
ROLE_ARTIFACT = {"recon": "CONTEXT.md", "refute": "refute.md"}


# ---------------------------------------------------------------------------
# Data carriers.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WaveResult:
    slice_id: str
    returncode: int | None
    output_present: bool
    gap_reason: str | None  # None | "timeout" | "crash" | "missing_write"
    captured: str | None
    plan_index: int


@dataclass(frozen=True)
class DispatchReport:
    results: list  # list[WaveResult], sorted by plan_index
    gaps: list  # list[WaveResult]
    all_present: bool


@dataclass(frozen=True)
class RoleResult:
    role: str
    returncode: int | None
    output_present: bool
    captured: str | None


# ---------------------------------------------------------------------------
# Path helpers (single source of truth for locations).
# ---------------------------------------------------------------------------


def wave_output_path(roots: Roots, slice_id: str) -> Path:
    return roots.review_root / "waves" / f"{slice_id}.md"


def capture_path(roots: Roots, slice_id: str) -> Path | None:
    """Single source of the {capture} location; None if no capture_dir."""
    if roots.capture_dir is None:
        return None
    return roots.capture_dir / f"{slice_id}.capture.txt"


def slice_config_path(roots: Roots, slice_id: str) -> Path:
    """Single source of the per-slice {slice_config} location (L5)."""
    return roots.review_root / "waves" / f"{slice_id}.slice.json"


def _role_artifact_path(roots: Roots, role: str) -> Path:
    # recon -> CONTEXT.md, refute -> refute.md; both live at review_root.
    return roots.review_root / ROLE_ARTIFACT[role]


# ---------------------------------------------------------------------------
# Default runner (thin stdlib wrapper; tests inject a fake).
# ---------------------------------------------------------------------------


def default_runner(argv, timeout):  # pragma: no cover - thin stdlib wrapper
    """Run a child process, killing the tree on timeout (returncode None).

    A spawn failure (missing/unspawnable binary → OSError) becomes a non-zero
    `RunResult`, NOT a raised exception, so `dispatch_waves` classifies that slice
    as a `crash` gap instead of aborting the whole batch (AD-2A6/E13, review H1).
    """
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            returncode=None,
            stdout=exc.stdout if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr if isinstance(exc.stderr, str) else "",
            timed_out=True,
        )
    except OSError as exc:
        return RunResult(returncode=127, stdout="", stderr=str(exc), timed_out=False)
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        timed_out=False,
    )


# ---------------------------------------------------------------------------
# Atomic write helper.
# ---------------------------------------------------------------------------


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Per-slice config.
# ---------------------------------------------------------------------------


def write_per_slice_config(slice: Mapping, roots: Roots) -> Path:
    """Write <review_root>/waves/<slice_id>.slice.json carrying the full slice
    content the CLI fields can't (checklists/target_files/themes/...). Restores
    the parent §4 {slice_config} placeholder. Atomic."""
    slice_id = slice["slice_id"]
    path = slice_config_path(roots, slice_id)
    payload = {
        k: slice.get(k)
        for k in (
            "slice_id",
            "wave_id",
            "themes",
            "checklists",
            "relevant_section_paths",
            "entry_points_in_scope",
            "target_files",
            "model",
            "mode",
        )
        if k in slice
    }
    _atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


# ---------------------------------------------------------------------------
# Gaps file.
# ---------------------------------------------------------------------------


def write_dispatch_gaps(gaps: list, path: Path) -> None:
    """Write JSON list [{slice_id, reason, returncode}] in plan_index order. Atomic."""
    ordered = sorted(gaps, key=lambda g: g.plan_index)
    payload = [
        {"slice_id": g.slice_id, "reason": g.gap_reason, "returncode": g.returncode}
        for g in ordered
    ]
    _atomic_write_text(Path(path), json.dumps(payload, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Classification.
# ---------------------------------------------------------------------------


def _classify_reason(result: RunResult, output_present: bool) -> str | None:
    """AD-2A6 two-step. Caller already handled fresh-present-wins; this is only
    reached when the wave file is NOT fresh-present."""
    if output_present:
        return None
    if result.timed_out:
        return "timeout"
    if result.returncode is None or result.returncode != 0:
        return "crash"
    return "missing_write"


# ---------------------------------------------------------------------------
# Wave fan-out.
# ---------------------------------------------------------------------------


def dispatch_waves(
    plan: list,
    tier_map: TierMap,
    *,
    roots: Roots,
    command_builder: WaveCommandBuilder,
    runner: Runner,
    max_parallel: int = 6,
    strict: bool = True,
    timeout=None,
    recover_capture: RecoverCapture | None = None,
    gaps_path: Path | None = None,
) -> DispatchReport:
    """Fan out one worker per slice (≤6 concurrent) and classify gaps."""
    waves_dir = roots.review_root / "waves"
    waves_dir.mkdir(parents=True, exist_ok=True)

    # AD-2A8 freshness: establish a clean slate for the PLANNED slices.
    for slice in plan:
        wp = wave_output_path(roots, slice["slice_id"])
        if wp.exists():
            wp.unlink()

    # Build per-slice argv up front (validates labels deterministically).
    tasks: list[tuple[int, Mapping, list]] = []
    for idx, slice in enumerate(plan):
        slice_id = slice["slice_id"]
        write_per_slice_config(slice, roots)
        label = slice["model"]
        tier = LABEL_TO_TIER.get(label)
        if tier is None:
            raise DispatchConfigError(slice_id, label, list(LABEL_TO_TIER.keys()))
        model_id = getattr(tier_map, tier)
        argv = command_builder(slice, model_id, roots, capture_path(roots, slice_id))
        tasks.append((idx, slice, list(argv)))

    workers = max(1, min(max_parallel, MAX_PARALLEL_HARD_CAP))

    def _run_one(task):
        idx, slice, argv = task
        # Defensive: a non-conforming runner that RAISES (e.g. a live runner that
        # forgot to trap a spawn error) must not abort the whole batch — turn it
        # into a crash RunResult so this slice becomes a gap (review H1).
        try:
            result = runner(argv, timeout)
        except Exception as exc:  # noqa: BLE001 - isolate one slice's failure
            result = RunResult(returncode=127, stdout="", stderr=str(exc), timed_out=False)
        return idx, slice, result

    run_results: dict[int, RunResult] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for idx, slice, result in pool.map(_run_one, tasks):
            run_results[idx] = result

    results: list[WaveResult] = []
    gaps: list[WaveResult] = []
    for idx, slice, argv in tasks:
        slice_id = slice["slice_id"]
        result = run_results[idx]
        wp = wave_output_path(roots, slice_id)
        output_present = wp.exists()
        gap_reason = None if output_present else _classify_reason(result, False)

        # AD-2A9: capture-based recovery must materialize to the wave file.
        if gap_reason is not None and recover_capture is not None:
            recovered = recover_capture(slice_id, roots)
            if recovered is not None:
                _atomic_write_text(wp, recovered)
                output_present = wp.exists()
                if output_present:
                    gap_reason = None

        wr = WaveResult(
            slice_id=slice_id,
            returncode=result.returncode,
            output_present=output_present,
            gap_reason=gap_reason,
            captured=(result.stdout or None),
            plan_index=idx,
        )
        results.append(wr)
        if gap_reason is not None:
            gaps.append(wr)

    results.sort(key=lambda r: r.plan_index)
    gaps.sort(key=lambda r: r.plan_index)
    report = DispatchReport(results=results, gaps=gaps, all_present=(not gaps))

    # Reconcile the on-disk gaps file with THIS run regardless of `strict`, so a
    # later clean run can't leave a stale dispatch_gaps.json that makes dedupe
    # mark a healthy report INCOMPLETE (review M1). strict+gaps raises (and leaves
    # any pre-existing file for forensics); a clean run removes a stale file.
    target = gaps_path or (roots.review_root / "dispatch_gaps.json")
    if gaps and strict:
        raise DispatchGapError(gaps)
    if gaps:
        write_dispatch_gaps(gaps, target)
    elif target.exists():
        target.unlink()
    return report


# ---------------------------------------------------------------------------
# Role dispatch (single process).
# ---------------------------------------------------------------------------


def dispatch_role(
    role: str,
    *,
    command_builder: RoleCommandBuilder,
    runner: Runner,
    roots: Roots,
    timeout=None,
    recover_capture: RecoverCapture | None = None,
) -> RoleResult:
    """Run ONE external process for a single-writer role; presence = role artifact.

    The refute ≤20-batch sequencing is the CALLER's loop — this runs once.
    """
    if role not in ROLE_ARTIFACT:
        raise DispatchConfigError(role, role, list(ROLE_ARTIFACT.keys()))
    artifact_path = _role_artifact_path(roots, role)

    # Freshness for roles: remove a stale artifact before the run.
    if artifact_path.exists():
        artifact_path.unlink()

    argv = command_builder(role, roots)
    result = runner(list(argv), timeout)
    output_present = artifact_path.exists()

    if not output_present and recover_capture is not None:
        recovered = recover_capture(role, roots)
        if recovered is not None:
            _atomic_write_text(artifact_path, recovered)
            output_present = artifact_path.exists()

    return RoleResult(
        role=role,
        returncode=result.returncode,
        output_present=output_present,
        captured=(result.stdout or None),
    )


# ---------------------------------------------------------------------------
# CLI command-builder factories.
# ---------------------------------------------------------------------------


def _format_template(template: str, fields: dict) -> list:
    """Format a template string then shlex.split into argv. Missing placeholders
    in the template are simply not substituted (str.format would KeyError, so we
    pre-fill every known field with '' when absent)."""
    safe = {k: ("" if v is None else str(v)) for k, v in fields.items()}
    try:
        rendered = template.format(**safe)
    except KeyError as exc:
        raise DispatchConfigError("template", str(exc), list(fields.keys()))
    return shlex.split(rendered)


def make_wave_command_builder(template: str) -> WaveCommandBuilder:
    def builder(slice: Mapping, model_id: str, roots: Roots, cap: Path | None):
        fields = {
            "model": model_id,
            "project_root": roots.project_root,
            "review_root": roots.review_root,
            "core_root": roots.core_root,
            "slice_id": slice["slice_id"],
            "capture": cap if cap is not None else "",
            "slice_config": slice_config_path(roots, slice["slice_id"]),
        }
        return _format_template(template, fields)

    return builder


def make_role_command_builder(template: str) -> RoleCommandBuilder:
    def builder(role: str, roots: Roots):
        fields = {
            "model": "",
            "project_root": roots.project_root,
            "review_root": roots.review_root,
            "core_root": roots.core_root,
            "slice_id": role,
            "capture": "",
            "slice_config": "",
            "role": role,
        }
        return _format_template(template, fields)

    return builder


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None, *, runner: Runner | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dispatch security review waves / roles")
    parser.add_argument("--plan", type=Path, default=None, help="plan JSON (list of slices)")
    parser.add_argument("--model-map", type=Path, default=None, help=".model_map.json")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--core-root", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path, default=None)
    parser.add_argument("--worker-cmd-template", default=None)
    parser.add_argument("--role-cmd-template", default=None)
    parser.add_argument("--role", default=None, choices=sorted(ROLE_ARTIFACT.keys()))
    parser.add_argument("--max-parallel", type=int, default=6)
    parser.add_argument("--allow-gaps", action="store_true")
    parser.add_argument("--timeout", type=float, default=None)
    args = parser.parse_args(argv)

    run = runner if runner is not None else default_runner
    roots = Roots(
        project_root=args.project_root,
        review_root=args.review_root,
        core_root=args.core_root,
        capture_dir=args.capture_dir,
    )

    if args.role is not None:
        if not args.role_cmd_template:
            print("Error: --role requires --role-cmd-template", file=sys.stderr)
            return 2
        builder = make_role_command_builder(args.role_cmd_template)
        result = dispatch_role(
            args.role, command_builder=builder, runner=run, roots=roots, timeout=args.timeout
        )
        print(json.dumps({
            "role": result.role,
            "returncode": result.returncode,
            "output_present": result.output_present,
        }, indent=2))
        return 0 if result.output_present else 1

    # Wave dispatch.
    if not args.plan or not args.model_map or not args.worker_cmd_template:
        print("Error: wave dispatch needs --plan, --model-map, --worker-cmd-template",
              file=sys.stderr)
        return 2
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        if not isinstance(plan, list):
            print("Error: plan root is not a list", file=sys.stderr)
            return 2
        model_map_data = json.loads(args.model_map.read_text(encoding="utf-8"))
        tier_map = TierMap.from_dict(model_map_data)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"Error: could not load inputs: {exc}", file=sys.stderr)
        return 2

    builder = make_wave_command_builder(args.worker_cmd_template)
    try:
        report = dispatch_waves(
            plan,
            tier_map,
            roots=roots,
            command_builder=builder,
            runner=run,
            max_parallel=args.max_parallel,
            strict=not args.allow_gaps,
            timeout=args.timeout,
        )
    except DispatchConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except DispatchGapError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "all_present": report.all_present,
        "results": len(report.results),
        "gaps": [g.slice_id for g in report.gaps],
    }, indent=2))
    return 0 if report.all_present else 1


if __name__ == "__main__":
    sys.exit(main())
