"""Adversarial second pass: parse refute records, validate evidence, apply tags.

Pipeline integration (`bin/dedupe_findings.py --refute=<path>`):

  1. `parse_refute_md(path)` reads `<review_root>/refute.md` written by the
     `security-refute` sub-agent. Format is a flat YAML-subset:

         refute_records:
           - finding_key: <sink_hash>:<sink_file>:<sink_line>:<sink_kind>
             refute_file: <relative path>
             refute_line: <int>
             rationale: <text — one line; literal block scalars not supported>
             confidence: 1-10

  2. `apply_refute_records(merged, records, project_root)` walks every record:
     - locate the `MergedFinding` whose primary matches the
       `(sink_hash, sink_file, sink_line, sink_kind)` tuple from `finding_key`;
     - run `validate_refute_evidence` against `project_root/refute_file:refute_line`;
     - on success — flag the finding `[REFUTE_CLAIMED]` and stash rationale;
     - on failure — collect a `RefuteInvalid` record for `refute_invalid.md`.

  3. `write_refute_invalid_md(invalid, path)` emits a human-readable audit log
     of refute claims that did not survive auto-validation.

The module is dependency-free (stdlib only) — pyyaml is not in the project
toolchain and we don't introduce it for a single flat schema.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import FLAG_REFUTE_CLAIMED, MergedFinding


# ---------------------------------------------------------------------------
# Data classes.
# ---------------------------------------------------------------------------


@dataclass
class RefuteRecord:
    finding_key: str
    refute_file: str
    refute_line: int
    rationale: str
    confidence: int = 0


@dataclass
class RefuteInvalid:
    finding_key: str
    refute_file: str
    refute_line: int
    rationale: str
    reason: str


# ---------------------------------------------------------------------------
# YAML mini-parser (flat schema — one list of homogeneous mappings).
#
# We support exactly the shape documented at the top of this module:
#
#     refute_records:
#       - finding_key: ...
#         refute_file: ...
#         refute_line: <int>
#         rationale: ...
#         confidence: <int>
#       - finding_key: ...
#         ...
#
# Strings may be plain or quoted with single/double quotes (no escape sequences
# beyond the matching quote — sufficient for paths and short rationales).
# `>`/`|` block scalars are NOT supported — the agent prompt instructs Sonnet
# to keep rationale on one line.
# ---------------------------------------------------------------------------


_KEY_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")
_LIST_ITEM_RE = re.compile(r"^(\s*)-\s+(.*)$")


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _coerce_int(s: str, default: int = 0) -> int:
    try:
        return int(s.strip())
    except (ValueError, TypeError):
        return default


def _parse_yaml_subset(text: str) -> dict:
    """Parse the documented refute.md schema into a dict.

    Returns `{"refute_records": [{...}, ...]}` on success; `{}` on malformed
    input. We never raise — caller treats empty result as "no refute records".
    """
    lines = text.splitlines()
    out: dict = {}
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        # Skip blank lines and YAML comments.
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = _KEY_RE.match(line)
        if not m:
            i += 1
            continue
        indent, key, value = len(m.group(1)), m.group(2), m.group(3)
        # We only care about the top-level `refute_records:` key — anything
        # else under root is ignored to keep the parser strict-by-schema.
        if indent != 0 or key != "refute_records":
            i += 1
            continue
        if value.strip():
            # Inline value (e.g. `refute_records: []`) — try empty list.
            if value.strip() in ("[]", "[ ]"):
                out["refute_records"] = []
            i += 1
            continue
        # Now collect list items at the next deeper indent.
        records: list[dict] = []
        i += 1
        current: dict | None = None
        while i < n:
            sub = lines[i]
            if not sub.strip() or sub.lstrip().startswith("#"):
                i += 1
                continue
            li = _LIST_ITEM_RE.match(sub)
            if li:
                # New record begins.
                indent_li = len(li.group(1))
                if indent_li == 0:
                    # Back at root level — stop collecting.
                    break
                if current is not None:
                    records.append(current)
                current = {}
                # First field on the same line as `-` (e.g. `- finding_key: ...`).
                inner = li.group(2)
                inner_m = _KEY_RE.match(inner)
                if inner_m:
                    k, v = inner_m.group(2), inner_m.group(3)
                    current[k] = _strip_quotes(v)
                i += 1
                continue
            # Continuation field of the current record.
            cont_m = _KEY_RE.match(sub)
            if cont_m and current is not None:
                indent_c = len(cont_m.group(1))
                # Field belongs to the current item only if its indent is
                # deeper than 0 (i.e. inside a list item). The schema is flat
                # so we don't enforce a strict indent comparison; any indented
                # `key: value` after a `- ` opener attaches to current.
                if indent_c > 0:
                    current[cont_m.group(2)] = _strip_quotes(cont_m.group(3))
                    i += 1
                    continue
                # Indent 0 — back at root, stop the list.
                break
            # Anything else — skip the line.
            i += 1
        if current is not None:
            records.append(current)
        out["refute_records"] = records
    return out


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def parse_refute_md(path: Path) -> list[RefuteRecord]:
    """Parse `<review_root>/refute.md` into a list of `RefuteRecord`.

    Returns `[]` if the file is missing or malformed — never raises.
    """
    if not path.exists() or not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    parsed = _parse_yaml_subset(text)
    items = parsed.get("refute_records") or []
    out: list[RefuteRecord] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fk = str(item.get("finding_key") or "").strip()
        rf = str(item.get("refute_file") or "").strip()
        if not fk or not rf:
            # Mandatory fields missing — skip silently; refute records are
            # informational, never block the main report.
            continue
        out.append(
            RefuteRecord(
                finding_key=fk,
                refute_file=rf,
                refute_line=_coerce_int(str(item.get("refute_line") or "0"), 0),
                rationale=str(item.get("rationale") or "").strip(),
                confidence=_coerce_int(str(item.get("confidence") or "0"), 0),
            )
        )
    return out


# Identifier: at least 3 chars, starts with letter/underscore.
_CODE_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
# Lines that are pure comments (PHP `//`, `#`, C-style `/*` `*/` `*` lead).
_COMMENT_LEAD_RE = re.compile(r"^\s*(//|#|/\*|\*/|\*)")


def _is_code_line(line: str) -> bool:
    """Heuristic: line contains a code-like identifier and is not a comment."""
    if not line.strip():
        return False
    if _COMMENT_LEAD_RE.match(line):
        return False
    return bool(_CODE_TOKEN_RE.search(line))


def validate_refute_evidence(
    record: RefuteRecord, project_root: Path
) -> tuple[bool, str | None]:
    """Auto-validate that the refute evidence at refute_file:refute_line exists.

    Returns `(ok, reason)`:
      - `(True, None)` if the file exists and the ±5 line window contains at
        least one non-comment line with a real code identifier;
      - `(False, "file_not_found")` if the file is missing;
      - `(False, "no_code_token_in_window")` for any other failure (line out
        of range, window contains only blank/comment lines).
    """
    target = project_root / record.refute_file
    if not target.exists() or not target.is_file():
        return False, "file_not_found"
    try:
        all_lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False, "file_not_found"
    if not all_lines:
        return False, "no_code_token_in_window"
    # Convert 1-indexed refute_line to 0-indexed; clamp window to file bounds.
    target_idx = max(0, record.refute_line - 1)
    lo = max(0, target_idx - 5)
    hi = min(len(all_lines), target_idx + 6)  # 5 below, inclusive of target
    window = all_lines[lo:hi]
    if any(_is_code_line(ln) for ln in window):
        return True, None
    return False, "no_code_token_in_window"


def _split_finding_key(finding_key: str) -> tuple[str, str, int, str] | None:
    """Split `<sink_hash>:<sink_file>:<sink_line>:<sink_kind>`.

    Returns `None` on shapes we can't parse. We use rsplit on the right because
    sink_file may contain `:` on Windows paths.
    """
    parts = finding_key.rsplit(":", 3)
    if len(parts) != 4:
        return None
    sink_hash, sink_file, sink_line_s, sink_kind = parts
    try:
        sink_line = int(sink_line_s)
    except ValueError:
        return None
    return sink_hash.strip(), sink_file.strip(), sink_line, sink_kind.strip()


def apply_refute_records(
    merged_findings: list[MergedFinding],
    records: list[RefuteRecord],
    project_root: Path,
) -> tuple[list[MergedFinding], list[RefuteInvalid]]:
    """Apply refute records in-place on `merged_findings`.

    For each record:
      1. Parse `finding_key` to a tuple. Bad shape → invalid (`bad_finding_key`).
      2. Find the merged finding whose primary matches the tuple. None → invalid
         (`finding_not_found`).
      3. Validate evidence on disk. Failure → invalid (with reason from
         `validate_refute_evidence`).
      4. Success → mark finding with `FLAG_REFUTE_CLAIMED`, store rationale.

    Returns the same `merged_findings` list (mutated) plus the list of invalid
    records for downstream `refute_invalid.md` rendering.
    """
    # Index by primary tuple for O(1) lookup.
    index: dict[tuple[str, str, int, str], MergedFinding] = {}
    for mf in merged_findings:
        p = mf.primary
        index[(p.sink_hash, p.sink_file, p.sink_line, p.sink_kind)] = mf

    invalid: list[RefuteInvalid] = []
    for rec in records:
        parsed = _split_finding_key(rec.finding_key)
        if parsed is None:
            invalid.append(
                RefuteInvalid(
                    finding_key=rec.finding_key,
                    refute_file=rec.refute_file,
                    refute_line=rec.refute_line,
                    rationale=rec.rationale,
                    reason="bad_finding_key",
                )
            )
            continue
        target = index.get(parsed)
        if target is None:
            invalid.append(
                RefuteInvalid(
                    finding_key=rec.finding_key,
                    refute_file=rec.refute_file,
                    refute_line=rec.refute_line,
                    rationale=rec.rationale,
                    reason="finding_not_found",
                )
            )
            continue
        ok, reason = validate_refute_evidence(rec, project_root)
        if not ok:
            invalid.append(
                RefuteInvalid(
                    finding_key=rec.finding_key,
                    refute_file=rec.refute_file,
                    refute_line=rec.refute_line,
                    rationale=rec.rationale,
                    reason=reason or "evidence_invalid",
                )
            )
            continue
        if FLAG_REFUTE_CLAIMED not in target.flags:
            target.flags.append(FLAG_REFUTE_CLAIMED)
        target.refute_rationale = rec.rationale
        target.refute_confidence = rec.confidence
        target.refute_file = rec.refute_file
        target.refute_line = rec.refute_line

    return merged_findings, invalid


def compute_refute_summary(
    merged_findings: list[MergedFinding],
    manual_findings: list[MergedFinding],
    invalid: list[RefuteInvalid],
) -> dict[str, int]:
    """Counts for the executive summary: confirmed/refute_claimed/refute_invalid/
    manual_review/parse_failed.

    `confirmed` = main findings without [REFUTE_CLAIMED].
    `refute_claimed` = main findings with [REFUTE_CLAIMED].
    `refute_invalid` = len(invalid).
    `manual_review` / `parse_failed` are derived from manual_findings flags
    by the renderer (we don't import FLAG_PARSE_FAILED here to keep the module
    surface tight); renderer fills them in at presentation time.
    """
    refute_claimed = sum(1 for mf in merged_findings if FLAG_REFUTE_CLAIMED in mf.flags)
    confirmed = len(merged_findings) - refute_claimed
    return {
        "confirmed": confirmed,
        "refute_claimed": refute_claimed,
        "refute_invalid": len(invalid),
        "manual_review": len(manual_findings),
    }


def write_refute_invalid_md(invalid: list[RefuteInvalid], path: Path) -> None:
    """Write the audit log of refute records that failed auto-validation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    out: list[str] = [
        "# Refute records — auto-validation failed",
        "",
        f"Total: {len(invalid)} record(s) emitted by `security-refute` agent that",
        "did not survive evidence validation. Each line below identifies the",
        "claim and the reason it was rejected.",
        "",
    ]
    if not invalid:
        out.append("_No invalid refute records — all claims survived validation._")
        out.append("")
    for idx, item in enumerate(invalid, start=1):
        out.append(f"## {idx}. `{item.finding_key}`")
        out.append("")
        out.append(f"- **refute_file**: `{item.refute_file}`")
        out.append(f"- **refute_line**: {item.refute_line}")
        out.append(f"- **reason**: `{item.reason}`")
        out.append(f"- **rationale**: {item.rationale}")
        out.append("")
    path.write_text("\n".join(out), encoding="utf-8")
