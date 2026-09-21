#!/usr/bin/env python3
"""Assemble `<TICKETS_ROOT>/INDEX.md` and `<TICKETS_ROOT>/.work/verdicts.json`
from Phase 1's persisted records, Phase 2's grouping, and Phase 4's
`.work/verify/<unit_id>.json` sidecars (see `agents/triage-verify.md` for the
sidecar's exact shape). CLI entry point for Phase 5 of
`commands/triage-findings.md`. stdlib only -- no third-party deps.

Usage:
    build_index.py <TICKETS_ROOT>

Requires `<TICKETS_ROOT>/.work/parsed.json` (Phase 1 / `parse_findings.py`)
and `<TICKETS_ROOT>/.work/grouping.json` (Phase 2) to already exist.
`.work/verify/*.json` sidecars are optional per unit -- a unit with none is
listed as "pending verification" rather than erroring out.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from parse_findings import CONDITION_KEYS, Record  # noqa: E402

_SEVERITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}

# The exact set of fields `state.load_verdicts_in` accepts per entry
# (security-review/bin/dedupe/state.py `_VERDICTS_IN_ENTRY_KEYS`). Nothing
# else may ever reach `.work/verdicts.json` -- in particular no free-text
# rationale (`note`, `severity_change_rationale`, `fix_pattern_note` from the
# sidecars) -- because `.findings_state.json`, which stores these verdicts on
# the audit side, outlives individual runs and someone will eventually
# `git add -f` it (README.md "The verdict hand-back").
_VERDICT_ENTRY_ALLOWED_KEYS = frozenset({"sink_hash", "verdict", "source", "condition_keys", "refute_file", "refute_line"})
_VALID_CANDIDATE_VERDICTS = ("rejected", "reaffirmed")
_VERDICT_SOURCE = "audit-triage"


# ---------------------------------------------------------------------------
# emit_verdicts: Phase 5's verdict hand-back channel. Consumes ONLY the
# structural fields of each sidecar's locations[] entries (sink_hash,
# status -> verdict_candidate, condition_keys, and -- only if the sidecar
# happens to carry them as separate structured fields, never parsed out of
# `note` -- refute_file/refute_line). Free text never crosses this boundary.
# ---------------------------------------------------------------------------


def _location_verdict_entry(loc: dict) -> dict | None:
    candidate = loc.get("verdict_candidate")
    if candidate not in _VALID_CANDIDATE_VERDICTS:
        return None
    sink_hash = loc.get("sink_hash")
    if not isinstance(sink_hash, str) or not sink_hash or sink_hash == "nohash00":
        # nohash00 is a shared sentinel for "no usable snippet" -- a resolution
        # recorded against it would silently apply to every future empty-
        # snippet finding (same exclusion `state.py` applies for the same
        # reason on the refute path).
        return None

    entry: dict = {"sink_hash": sink_hash, "verdict": candidate, "source": _VERDICT_SOURCE}

    condition_keys = loc.get("condition_keys")
    if isinstance(condition_keys, list):
        valid_keys = sorted({k for k in condition_keys if isinstance(k, str) and k in CONDITION_KEYS})
        if valid_keys:
            entry["condition_keys"] = valid_keys

    if candidate == "rejected":
        refute_file = loc.get("refute_file")
        refute_line = loc.get("refute_line")
        if isinstance(refute_file, str) and refute_file and isinstance(refute_line, int) and refute_line > 0:
            entry["refute_file"] = refute_file
            entry["refute_line"] = refute_line

    assert set(entry) <= _VERDICT_ENTRY_ALLOWED_KEYS  # defensive -- enforced by construction above
    return entry


def emit_verdicts(sidecars: dict) -> dict:
    """Build `{"verdicts": [...], "conflicts": [...]}` from every unit's
    `.work/verify/<unit_id>.json` sidecar's `locations[]`.

    Collapses by `sink_hash` (a `--verdicts-in` import rejects duplicate
    hashes, and several locations/units can share one, e.g. the same
    constituent finding re-verified in more than one unit by mistake).
    Identical candidate entries for the same hash collapse silently; a
    genuine CONFLICT (different verdict/condition_keys/refute evidence for
    the same hash) drops that hash from `verdicts` entirely and lists it in
    `conflicts` (sink_hash strings only -- not free text) so the caller can
    surface it instead of silently picking a side.

    Only the fields in `_VERDICT_ENTRY_ALLOWED_KEYS` ever appear in an
    output entry -- see `test_no_free_text_leak.py` for the machine-checked
    guarantee."""
    by_hash: dict[str, dict] = {}
    conflicts: set[str] = set()
    for sidecar in sidecars.values():
        if not isinstance(sidecar, dict):
            continue
        for loc in sidecar.get("locations") or []:
            if not isinstance(loc, dict):
                continue
            entry = _location_verdict_entry(loc)
            if entry is None:
                continue
            h = entry["sink_hash"]
            if h in by_hash and by_hash[h] != entry:
                conflicts.add(h)
                continue
            by_hash[h] = entry
    for h in conflicts:
        by_hash.pop(h, None)
    verdicts = [by_hash[h] for h in sorted(by_hash)]
    return {"verdicts": verdicts, "conflicts": sorted(conflicts)}


# ---------------------------------------------------------------------------
# emit_index: INDEX.md -- the single home for everything pulled out of unit
# bodies (severity, verification status, sink_hash, trace, discovered-via).
# ---------------------------------------------------------------------------


def _sidecar_location(sidecar: dict | None, sink_hash: str) -> dict | None:
    if not sidecar:
        return None
    for loc in sidecar.get("locations") or []:
        if isinstance(loc, dict) and loc.get("sink_hash") == sink_hash:
            return loc
    return None


def _location_status_and_severity(r: Record, sidecar: dict | None) -> tuple[str, str]:
    loc = _sidecar_location(sidecar, r.sink_hash)
    if loc is not None:
        status = str(loc.get("status") or "—")
        severity = str((sidecar or {}).get("severity_after") or r.severity or "—")
        return status, severity
    if r.verdict == "confirmed":
        return "not verified", r.severity or "—"
    return "n/a", "—"


def _unit_severity(unit_records: list[Record], sidecar: dict | None) -> str:
    if sidecar and sidecar.get("severity_after"):
        return str(sidecar["severity_after"])
    confirmed = [r for r in unit_records if r.verdict == "confirmed" and r.severity in _SEVERITY_RANK]
    if not confirmed:
        return "—"
    best = max(confirmed, key=lambda r: _SEVERITY_RANK[r.severity])
    return best.severity or "—"


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def emit_index(records: list[Record], grouping: dict, sidecars: dict) -> str:
    """Build `INDEX.md`'s text: a per-unit summary table, the full
    `finding(sink_hash) -> unit` trace with per-location verification status
    and post-verification severity, and a prior-run-resolutions section.

    Every record's `sink_hash` is guaranteed to appear literally in the
    output (the traceability table has one row per record) -- this is what
    makes "every sink_hash from findings.json appears in INDEX.md" a
    grep-able invariant rather than a promise."""
    by_id = {r.record_id: r for r in records}
    unit_of: dict[str, str] = {}
    for unit_id, record_ids in grouping.items():
        for rid in record_ids:
            unit_of[rid] = unit_id

    lines: list[str] = ["# INDEX", ""]

    lines.append("## Units")
    lines.append("")
    lines.append("| Unit | Severity | Locations | Verification |")
    lines.append("|---|---|---|---|")
    for unit_id in sorted(grouping):
        record_ids = grouping[unit_id]
        unit_records = [by_id[rid] for rid in record_ids if rid in by_id]
        sidecar = sidecars.get(unit_id)
        severity = _unit_severity(unit_records, sidecar)
        status = "verified" if sidecar else "pending verification"
        lines.append(f"| `{unit_id}` | {severity} | {len(record_ids)} | {status} |")
    lines.append("")

    lines.append("## Traceability: finding -> unit")
    lines.append("")
    lines.append("| sink_hash | verdict | unit | status | severity | condition_keys | discovered_via |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in records:
        unit_id = unit_of.get(r.record_id, "(uncovered)")
        sidecar = sidecars.get(unit_id)
        loc_status, loc_severity = _location_status_and_severity(r, sidecar)
        ck = ", ".join(r.condition_keys) if r.condition_keys else "—"
        discovered = r.discovered_via or "—"
        lines.append(
            f"| `{r.sink_hash}` | {r.verdict} | `{unit_id}` | {loc_status} | {loc_severity} "
            f"| {_escape_cell(ck)} | {_escape_cell(discovered)} |"
        )
    lines.append("")

    prior = [r for r in records if r.prior_resolution]
    if prior:
        lines.append("## Prior-run resolutions")
        lines.append("")
        lines.append(
            "Marks carried over from `.findings_state.json` -- annotations to "
            "reconcile against current verification, not verdicts to copy."
        )
        lines.append("")
        for r in prior:
            res = r.prior_resolution or {}
            lines.append(
                f"- `{r.sink_hash}` — previously **{res.get('verdict', '?')}** "
                f"(source: `{res.get('source', '')}`)"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble INDEX.md + .work/verdicts.json from a triage run's .work/ artifacts."
    )
    parser.add_argument("tickets_root", type=Path)
    args = parser.parse_args(argv)

    tickets_root = args.tickets_root.resolve()
    work_dir = tickets_root / ".work"

    parsed_path = work_dir / "parsed.json"
    if not parsed_path.is_file():
        print(f"Error: {parsed_path} not found -- run parse_findings.py first (Phase 1).", file=sys.stderr)
        return 2
    try:
        parsed = json.loads(parsed_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: cannot read {parsed_path}: {exc}", file=sys.stderr)
        return 2
    records = [Record.from_dict(d) for d in parsed.get("records", [])]
    findings_sha = parsed.get("findings_json_sha256", "")

    grouping_path = work_dir / "grouping.json"
    if not grouping_path.is_file():
        print(f"Error: {grouping_path} not found -- Phase 2 grouping is required before INDEX assembly.", file=sys.stderr)
        return 2
    try:
        grouping = json.loads(grouping_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: cannot read {grouping_path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(grouping, dict):
        print(f"Error: {grouping_path}: root must be a JSON object of unit_id -> [record_id, ...]", file=sys.stderr)
        return 2

    sidecars: dict[str, dict] = {}
    verify_dir = work_dir / "verify"
    if verify_dir.is_dir():
        for p in sorted(verify_dir.glob("*.json")):
            try:
                sidecars[p.stem] = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Warning: skipping unreadable sidecar {p}: {exc}", file=sys.stderr)

    index_text = emit_index(records, grouping, sidecars)
    index_path = tickets_root / "INDEX.md"
    index_path.write_text(index_text, encoding="utf-8")

    verdicts_result = emit_verdicts(sidecars)
    verdicts_payload = {
        "schema_version": 1,
        "findings_json_sha256": findings_sha,
        "verdicts": verdicts_result["verdicts"],
    }
    verdicts_path = work_dir / "verdicts.json"
    verdicts_path.write_text(json.dumps(verdicts_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if verdicts_result["conflicts"]:
        print(
            f"Warning: {len(verdicts_result['conflicts'])} sink_hash(es) had conflicting "
            f"verdict candidates across sidecars, dropped: {verdicts_result['conflicts']}",
            file=sys.stderr,
        )

    print(f"Wrote {index_path}")
    print(f"Wrote {verdicts_path} ({len(verdicts_payload['verdicts'])} verdict(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
