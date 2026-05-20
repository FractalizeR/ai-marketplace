#!/usr/bin/env python3
"""Detect removed security defenses in a unified-diff patch.

Used by `/security-changes` orchestrator. Scans removed lines (prefixed `-`,
not `---` file headers) for tightened patterns covering authz / middleware /
CSRF / timing-safe compare / secure RNG removal. Emits JSON suitable for
`plan_waves.py --extra-target-files=`.

Pair detection ("refactoring, not removal"): if an added line within ±10
lines of the removed line carries an equivalent defense (same API family),
the removed entry is annotated with `added_equivalent_detected: true` so the
orchestrator can skip enforcing target_files for pure refactors.

stdlib only.

Usage:
    diff_removed_defenses.py <path-to-diff.patch> [<path-to-diff2.patch> ...]
    cat full_diff.patch | diff_removed_defenses.py -

Output (stdout, JSON):
    {
      "removed_defenses": [
        {
          "removed_line": "-    #[IsGranted('ROLE_ADMIN')]",
          "file": "src/Controller/Foo.php",
          "line_in_old": 17,
          "pattern_matched": "symfony_attr_isgranted",
          "added_equivalent_detected": false
        }
      ]
    }

`removed_files` (whole-file deletes + Voter/Policy/Middleware consumer
collection) is OUT OF SCOPE for this module — it requires recon CONTEXT.md
+ project grep, which the orchestrator handles in shell. This module focuses
on the pure-diff regex part that is unit-testable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Tightened regex patterns for removed-defense detection.
#
# Keys are stable category names (used in JSON output as `pattern_matched`).
# Each pattern includes the leading `-` so it only matches deleted lines in
# unified diff format. We explicitly skip `---` file-header lines in the scan
# loop (they look like deletes but aren't).
# ---------------------------------------------------------------------------


REMOVED_DEFENSE_PATTERNS: dict[str, str] = {
    # Symfony — attribute and call form of authz.
    "symfony_attr_isgranted":
        r"^-.*#\[IsGranted\(",
    "symfony_call_denyaccess":
        r"^-.*denyAccessUnlessGranted\s*\(",

    # Laravel — Blade @can directive (not the bare word `can` in code).
    "laravel_blade_can":
        r"^-.*@can\s*\(",

    # Laravel — `->can('string'`. Excludes `$collection->can()` (no string arg).
    "laravel_can_with_string":
        r"^-.*->can\s*\(\s*['\"][^'\"]+['\"]",

    # Laravel — explicit authorize() / Gate::authorize calls.
    "laravel_authorize":
        r"^-.*(?:->authorize\s*\(|Gate::authorize\s*\()",

    # Laravel — Gate::define / Gate::before (deletion of gate definition).
    "laravel_gate_define":
        r"^-.*Gate::(?:define|before)\s*\(",

    # Middleware — `auth` (single string arg).
    "middleware_auth_single":
        r"^-.*->middleware\s*\(\s*['\"]auth['\"]",

    # Middleware — `auth` inside an array.
    "middleware_auth_array":
        r"^-.*->middleware\s*\(\s*\[[^\]]*['\"]auth['\"][^\]]*\]",

    # Middleware — `throttle:*` single + array forms.
    "middleware_throttle_single":
        r"^-.*->middleware\s*\(\s*['\"]throttle:[^'\"]*['\"]",
    "middleware_throttle_array":
        r"^-.*->middleware\s*\(\s*\[[^\]]*['\"]throttle:[^'\"]*['\"][^\]]*\]",

    # Symfony — explicit `csrf_protection => true` removal.
    "symfony_csrf_protection":
        r"^-.*['\"]csrf_protection['\"]\s*=>\s*true",

    # Crypto — timing-safe compare deletion.
    "hash_equals":
        r"^-.*hash_equals\s*\(",

    # Crypto — secure RNG deletion (random_bytes / random_int).
    "random_secure":
        r"^-.*(?:random_bytes|random_int)\s*\(",
}


# Compiled patterns (cached at module import).
_COMPILED: dict[str, re.Pattern[str]] = {
    name: re.compile(pat) for name, pat in REMOVED_DEFENSE_PATTERNS.items()
}


# Equivalence buckets — for "pair detection" within ±10 lines.
# When a removed line matches one of these buckets, we look for an added line
# that contains ANY of the bucket's substrings. Single-substring buckets
# trigger when the same API name still appears nearby.
_EQUIVALENCE_BUCKETS: dict[str, tuple[str, ...]] = {
    "symfony_attr_isgranted":     ("IsGranted", "denyAccessUnlessGranted"),
    "symfony_call_denyaccess":    ("denyAccessUnlessGranted", "IsGranted"),
    "laravel_blade_can":          ("@can(", "@cannot(", "@auth"),
    "laravel_can_with_string":    ("->can(", "->cannot(", "Gate::"),
    "laravel_authorize":          ("authorize(", "Gate::authorize"),
    "laravel_gate_define":        ("Gate::define", "Gate::before"),
    "middleware_auth_single":     ("middleware('auth", 'middleware("auth', "Auth::check"),
    "middleware_auth_array":      ("'auth'", '"auth"', "Auth::check"),
    "middleware_throttle_single": ("throttle:",),
    "middleware_throttle_array":  ("throttle:",),
    "symfony_csrf_protection":    ("csrf_protection",),
    "hash_equals":                ("hash_equals(",),
    "random_secure":              ("random_bytes(", "random_int("),
}


# Pair-detection radius: lines counted in patch buffer (not original file).
_PAIR_RADIUS = 10


# ---------------------------------------------------------------------------
# Diff parsing.
# ---------------------------------------------------------------------------


_FILE_HEADER_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@")


def _parse_diff_lines(diff_text: str) -> list[dict[str, object]]:
    """Walk a unified diff and return per-line records carrying file + old-line.

    Each record is `{file, old_line_no, raw, kind}` where `kind` ∈
    {"context", "removed", "added", "header"}. `old_line_no` is the
    1-based line in the OLD file for context+removed lines (None for
    added).

    Skips binary diffs and non-`+++ b/...` headers.
    """
    out: list[dict[str, object]] = []
    cur_file: Optional[str] = None
    old_line: Optional[int] = None
    for raw in diff_text.splitlines():
        # File header: `+++ b/<path>`. Treat `+++ /dev/null` (file deleted) as
        # transparent — we still pick up the previous `--- a/<path>` via the
        # next +++ block. For pure regex scanning we don't need both.
        m = _FILE_HEADER_RE.match(raw)
        if m:
            cur_file = m.group(1) if m.group(1) != "/dev/null" else cur_file
            old_line = None
            out.append({"file": cur_file, "old_line_no": None, "raw": raw, "kind": "header"})
            continue
        # Skip the `--- a/...` partner header as a "header" record.
        if raw.startswith("--- "):
            out.append({"file": cur_file, "old_line_no": None, "raw": raw, "kind": "header"})
            continue
        # Hunk header: reset old_line counter.
        m = _HUNK_HEADER_RE.match(raw)
        if m:
            old_line = int(m.group(1))
            out.append({"file": cur_file, "old_line_no": None, "raw": raw, "kind": "header"})
            continue
        if old_line is None:
            # Outside any hunk yet (e.g. `diff --git`, `index ...` lines).
            out.append({"file": cur_file, "old_line_no": None, "raw": raw, "kind": "header"})
            continue
        if raw.startswith("-") and not raw.startswith("---"):
            out.append({
                "file": cur_file,
                "old_line_no": old_line,
                "raw": raw,
                "kind": "removed",
            })
            old_line += 1
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            out.append({
                "file": cur_file,
                "old_line_no": None,
                "raw": raw,
                "kind": "added",
            })
            continue
        # Context line (starts with space) or empty in tail.
        out.append({
            "file": cur_file,
            "old_line_no": old_line,
            "raw": raw,
            "kind": "context",
        })
        old_line += 1
    return out


def _has_equivalent_added(records: list[dict[str, object]], idx: int, category: str) -> bool:
    """Look ±_PAIR_RADIUS records for an added line carrying equivalent defense."""
    bucket = _EQUIVALENCE_BUCKETS.get(category, ())
    if not bucket:
        return False
    lo = max(0, idx - _PAIR_RADIUS)
    hi = min(len(records), idx + _PAIR_RADIUS + 1)
    removed_file = records[idx].get("file")
    for j in range(lo, hi):
        if j == idx:
            continue
        rec = records[j]
        if rec.get("kind") != "added":
            continue
        # Same file — pair detection only across the same diff file.
        if rec.get("file") != removed_file:
            continue
        raw = rec.get("raw")
        if not isinstance(raw, str):
            continue
        # Strip the leading '+' before substring search so substrings starting
        # with '@' / quoted markers match cleanly.
        body = raw[1:] if raw.startswith("+") else raw
        for needle in bucket:
            if needle in body:
                return True
    return False


def scan_diff_for_removed_defenses(diff_text: str) -> list[dict[str, object]]:
    """Apply REMOVED_DEFENSE_PATTERNS to every removed line in `diff_text`.

    Each match becomes one entry. A removed line that triggers multiple
    categories produces one entry per category (we don't dedupe because each
    category carries different remediation hints in checklists).
    """
    records = _parse_diff_lines(diff_text)
    out: list[dict[str, object]] = []
    for idx, rec in enumerate(records):
        if rec.get("kind") != "removed":
            continue
        raw = rec.get("raw")
        if not isinstance(raw, str):
            continue
        for category, regex in _COMPILED.items():
            if regex.search(raw):
                out.append({
                    "removed_line": raw,
                    "file": rec.get("file"),
                    "line_in_old": rec.get("old_line_no"),
                    "pattern_matched": category,
                    "added_equivalent_detected": _has_equivalent_added(records, idx, category),
                })
    return out


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan a unified diff for removed security defenses",
    )
    parser.add_argument(
        "diff_paths", nargs="+", type=str,
        help="Path(s) to unified diff patches. Use '-' to read from stdin.",
    )
    args = parser.parse_args(argv)

    chunks: list[str] = []
    for p in args.diff_paths:
        try:
            if p == "-":
                chunks.append(sys.stdin.read())
            else:
                chunks.append(Path(p).read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            print(f"Error reading {p}: {exc}", file=sys.stderr)
            return 2

    diff_text = "\n".join(chunks)
    entries = scan_diff_for_removed_defenses(diff_text)

    payload = {"removed_defenses": entries}
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
