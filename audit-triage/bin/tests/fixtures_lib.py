"""Shared test fixture helper: builds a REAL `<review_root>/findings.json` by
running `security-review`'s own `dedupe_findings.py` CLI (subprocess, no
imports) against the `fr-security-review` engine's own e2e wave fixtures
(`security-review/bin/tests/fixtures/e2e/SECURITY_REVIEW_RESULTS_W{1,2}.md`,
shared read-only -- this repo's audit plugin is finished code, not touched by
`fr-audit-triage`).

Not a `test_*.py` module itself -- `unittest discover` won't collect it.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent  # audit-triage/bin
REPO_ROOT = BIN_DIR.parent.parent  # ai-marketplace/

SECURITY_REVIEW_BIN = REPO_ROOT / "security-review" / "bin"
DEDUPE_FINDINGS = SECURITY_REVIEW_BIN / "dedupe_findings.py"
E2E_WAVE_FIXTURES = SECURITY_REVIEW_BIN / "tests" / "fixtures" / "e2e"

# fr-audit-triage's own synthetic wave fixture -- unlike E2E_WAVE_FIXTURES
# (borrowed read-only from the engine), this one is authored by this plugin
# specifically to provoke the two `attach_side_records` outcomes the e2e
# fixture doesn't: `[ATTACHED_WITHOUT_HASH]` binding and two
# needs_validation records sharing a sink_hash with different sink_kind. See
# fixtures/buckets/BUCKETS_W1.md and test_fixtures_buckets.py.
BUCKET_WAVE_FIXTURES = THIS_DIR / "fixtures" / "buckets"


def build_review_root(dest: Path, *, extra_args: list[str] | None = None) -> Path:
    """Copy the engine's e2e wave fixtures into `<dest>/waves/` and run the
    real `dedupe_findings.py` CLI to produce `REPORT.md` + `REPORT/*.md` +
    `findings.json` (+ `.findings_state.json`, since `--no-state` is not
    passed). Returns `dest` (the review_root). Raises `RuntimeError` on a
    non-zero exit."""
    waves_dir = dest / "waves"
    waves_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(E2E_WAVE_FIXTURES / "SECURITY_REVIEW_RESULTS_W1.md", waves_dir / "W1.md")
    shutil.copy(E2E_WAVE_FIXTURES / "SECURITY_REVIEW_RESULTS_W2.md", waves_dir / "W2.md")

    args = [
        sys.executable, str(DEDUPE_FINDINGS),
        "--input-glob", str(waves_dir / "*.md"),
        "--output", str(dest / "REPORT.md"),
        "--details-dir", str(dest / "REPORT"),
    ]
    if extra_args:
        args.extend(extra_args)
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"dedupe_findings.py failed: {result.stderr}")
    return dest


def run_dedupe(dest: Path, *extra_args: str) -> subprocess.CompletedProcess:
    """Re-run dedupe_findings.py against the same wave inputs already built by
    `build_review_root` (e.g. with `--verdicts-in=...`). Does not raise --
    callers inspect `.returncode`/`.stderr`."""
    args = [
        sys.executable, str(DEDUPE_FINDINGS),
        "--input-glob", str(dest / "waves" / "*.md"),
        "--output", str(dest / "REPORT.md"),
        "--details-dir", str(dest / "REPORT"),
        *extra_args,
    ]
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


def build_bucket_review_root(dest: Path, *, extra_args: list[str] | None = None) -> Path:
    """Like `build_review_root`, but over `fixtures/buckets/*.md` -- this
    plugin's own synthetic wave fixture -- instead of the engine's e2e
    fixtures. Copies every `*.md` under `BUCKET_WAVE_FIXTURES` into
    `<dest>/waves/` (sorted, stable names) and runs the REAL
    `dedupe_findings.py` CLI to produce `findings.json`. Returns `dest`.
    Raises `RuntimeError` on a non-zero exit."""
    waves_dir = dest / "waves"
    waves_dir.mkdir(parents=True, exist_ok=True)
    for src in sorted(BUCKET_WAVE_FIXTURES.glob("*.md")):
        shutil.copy(src, waves_dir / src.name)

    args = [
        sys.executable, str(DEDUPE_FINDINGS),
        "--input-glob", str(waves_dir / "*.md"),
        "--output", str(dest / "REPORT.md"),
        "--details-dir", str(dest / "REPORT"),
    ]
    if extra_args:
        args.extend(extra_args)
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"dedupe_findings.py failed: {result.stderr}")
    return dest


def build_project_tree(dest: Path, sink_files: list[str], *, content: str = "<?php\n// synthetic fixture placeholder\n") -> Path:
    """Build a minimal temporary "project tree" under `dest` containing one
    placeholder file per `sink_files` entry (paths relative to `dest`, same
    shape as a `Record.sink_file` / findings.json `sink_file`). For
    `resolve_project_root` / `check_project_root` tests in later packages,
    which need real files on disk to resolve against -- not a findings.json
    fixture. Returns `dest`. Idempotent: intermediate directories are
    created as needed; an existing file is left untouched (its content does
    not matter to a resolution test, only its existence)."""
    dest.mkdir(parents=True, exist_ok=True)
    for rel in sink_files:
        rel = rel.strip()
        if not rel:
            continue
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content, encoding="utf-8")
    return dest


# A grouping over the exact record_ids produced by `load()` on the fixture
# above. Covers all 11 records (6 confirmed + 3 needs_validation + 2
# hardening) exactly once. Keys are `unit_id`s of the form `[a-z0-9]+`: the
# unit_id becomes part of a dash-separated file name, so it holds no dash.
FULL_GROUPING = {
    "u1injection": ["confirmed#0", "confirmed#1", "needs_validation#0"],
    "u2crypto": ["confirmed#2", "confirmed#3", "hardening#0"],
    "triagemanual": ["confirmed#4", "confirmed#5", "needs_validation#1"],
    "triageleads": ["needs_validation#2", "hardening#1"],
}
