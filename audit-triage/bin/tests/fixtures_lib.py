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


# A grouping over the exact record_ids produced by `load()` on the fixture
# above (verified against a real run -- see module docstring). Covers all 11
# records (6 confirmed + 3 needs_validation + 2 hardening) exactly once.
FULL_GROUPING = {
    "u1-injection": ["confirmed#0", "confirmed#1", "needs_validation#0"],
    "u2-crypto": ["confirmed#2", "confirmed#3", "hardening#0"],
    "triage-manual": ["confirmed#4", "confirmed#5", "needs_validation#1"],
    "triage-leads": ["needs_validation#2", "hardening#1"],
}
