"""Findings state: cross-run diff tracking via `<review_root>/.findings_state.json`.

After every dedupe pipeline writes its REPORT.md, the same set of findings is
persisted as a json snapshot. The next run loads that snapshot and computes a
diff:

    new       — sink_hash present in current run, absent in previous run
    recurring — sink_hash present in both
    closed    — sink_hash present in previous run, absent in current run

The diff lands as a `## Diff vs previous run` block in the executive summary.
No machinery beyond a simple `set` comparison — it is a UX hint, not auth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dedupe.models import MergedFinding


STATE_FILENAME = ".findings_state.json"
STATE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FindingSnapshot:
    sink_hash: str
    sink_file: str
    sink_line: int
    sink_kind: str
    severity: str
    title: str

    def to_dict(self) -> dict:
        return {
            "sink_hash": self.sink_hash,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_kind": self.sink_kind,
            "severity": self.severity,
            "title": self.title,
        }


def snapshots_from(merged: list[MergedFinding], manual: list[MergedFinding]) -> list[FindingSnapshot]:
    """Flatten merged + manual into a stable, hashable per-finding snapshot list.

    A `MergedFinding`'s identity is its `primary.sink_hash`. We pull the rest of
    the visible-to-user fields from `primary`, keep severity from the merged
    accessor (max across merged_from)."""
    out: list[FindingSnapshot] = []
    for collection in (merged, manual):
        for mf in collection:
            p = mf.primary
            out.append(FindingSnapshot(
                sink_hash=p.sink_hash,
                sink_file=p.sink_file,
                sink_line=p.sink_line,
                sink_kind=p.sink_kind,
                severity=mf.severity,
                title=p.title_line,
            ))
    return out


def save_state(snapshots: list[FindingSnapshot], review_root: Path) -> Path:
    """Atomically write `.findings_state.json` under `review_root`. Returns the path."""
    review_root.mkdir(parents=True, exist_ok=True)
    target = review_root / STATE_FILENAME
    payload = {
        "schema_version": STATE_SCHEMA_VERSION,
        "findings": [s.to_dict() for s in snapshots],
    }
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(target)
    return target


def load_state(review_root: Path) -> Optional[list[FindingSnapshot]]:
    """Return previous-run snapshots, or None if absent / unreadable / wrong schema."""
    target = review_root / STATE_FILENAME
    if not target.is_file():
        return None
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("schema_version") != STATE_SCHEMA_VERSION:
        return None
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return None
    out: list[FindingSnapshot] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        try:
            out.append(FindingSnapshot(
                sink_hash=str(f.get("sink_hash", "")),
                sink_file=str(f.get("sink_file", "")),
                sink_line=int(f.get("sink_line", 0)),
                sink_kind=str(f.get("sink_kind", "")),
                severity=str(f.get("severity", "")),
                title=str(f.get("title", "")),
            ))
        except (TypeError, ValueError):
            continue
    return out


@dataclass(frozen=True)
class FindingsDiff:
    new: list[FindingSnapshot]        # in current, not in previous
    recurring: list[FindingSnapshot]  # in both
    closed: list[FindingSnapshot]     # in previous, not in current

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.closed)


def compute_diff(
    previous: Optional[list[FindingSnapshot]],
    current: list[FindingSnapshot],
) -> Optional[FindingsDiff]:
    """Compare two snapshot collections by `sink_hash`. None if no previous run.

    `nohash00` (the sentinel for findings without a usable snippet) is excluded
    from diff classification — without a stable hash, every such finding looks
    `new` on every run, which produces noise rather than signal.
    """
    if previous is None:
        return None
    prev_index = {s.sink_hash: s for s in previous if s.sink_hash and s.sink_hash != "nohash00"}
    curr_index = {s.sink_hash: s for s in current if s.sink_hash and s.sink_hash != "nohash00"}
    new = [curr_index[h] for h in curr_index if h not in prev_index]
    recurring = [curr_index[h] for h in curr_index if h in prev_index]
    closed = [prev_index[h] for h in prev_index if h not in curr_index]
    return FindingsDiff(new=new, recurring=recurring, closed=closed)
