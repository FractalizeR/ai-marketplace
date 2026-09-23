#!/usr/bin/env python3
"""Validate a triage run's `.work/verify/<unit_id>.json` sidecars (contract
v2, see `agents/triage-verify.md`) and assemble `<TICKETS_ROOT>/INDEX.md`
and `<TICKETS_ROOT>/.work/verdicts.json` from Phase 1's persisted records,
Phase 2's grouping, and those sidecars. CLI entry point for Phase 5 of
`commands/triage-findings.md`. stdlib only -- no third-party deps.

Usage:
    build_index.py <TICKETS_ROOT> [--config <PROJECT_ROOT>/.audit-triage.json]

Requires `<TICKETS_ROOT>/.work/parsed.json` (Phase 1 / `parse_findings.py`)
and `<TICKETS_ROOT>/.work/grouping.json` (Phase 2) to already exist.

Exit codes:
    0 -- INDEX.md + verdicts.json written. A unit with no sidecar yet is
         listed under "Pending verification" (with a stderr warning), so
         INDEX.md can be assembled piecemeal.
    2 -- a missing/unreadable input, or at least one sidecar contract
         violation. Every violation is listed on stderr; neither INDEX.md
         nor verdicts.json is written.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

from parse_findings import CONDITION_KEYS, CoverageError, Record, assert_full_coverage  # noqa: E402

SIDECAR_VERSION = 2

SEVERITIES = ("Critical", "High", "Medium", "Low")
_SEVERITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
SEVERITY_PREFIX = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low"}
TRIAGE_PREFIX = "triage"

DISPOSITIONS = ("work_unit", "triage")
LOCATION_STATUSES = ("confirmed", "changed", "false_positive", "manual_review")
# Verdicts whose verification says something about exploitability. A
# hardening note verified `confirmed` only means "the observation is
# correct", so it neither justifies a work unit nor votes on a hand-back.
SUBSTANTIVE_VERDICTS = ("confirmed", "needs_validation")
_REAL_STATUSES = ("confirmed", "changed")

_UNIT_FILE_RE = re.compile(r"^(crit|high|med|low|triage)-([a-z0-9]+)-([a-z0-9][a-z0-9-]*)\.md$")

_HEADER_KEYS = (
    "sidecar_version",
    "unit_id",
    "disposition",
    "title",
    "unit_file",
    "severity_before",
    "severity_after",
    "severity_change_rationale",
    "locations",
    "fix_pattern_note",
)
_LOCATION_KEYS = (
    "record_id",
    "sink_hash",
    "sink_file",
    "sink_line",
    "status",
    "note",
    "condition_keys",
    "verdict_candidate",
)

# The exact set of fields `state.load_verdicts_in` accepts per entry
# (security-review/bin/dedupe/state.py `_VERDICTS_IN_ENTRY_KEYS`). Nothing
# else may ever reach `.work/verdicts.json` -- in particular no free-text
# rationale (`note`, `title`, `severity_change_rationale`, `fix_pattern_note`
# from the sidecars) -- because `.findings_state.json`, which stores these
# verdicts on the audit side, outlives individual runs and someone will
# eventually `git add -f` it (README.md "The verdict hand-back").
_VERDICT_ENTRY_ALLOWED_KEYS = frozenset({"sink_hash", "verdict", "source", "condition_keys", "refute_file", "refute_line"})
_VALID_CANDIDATE_VERDICTS = ("rejected", "reaffirmed")
_VERDICT_SOURCE = "audit-triage"

# Shared sentinel for "no usable snippet": a resolution recorded against it
# would silently apply to every future empty-snippet finding.
_NOHASH = "nohash00"


def _is_int(value) -> bool:
    # bool is an int subclass; `True` would pass the engine's own
    # `isinstance(..., int)` check as line 1.
    return type(value) is int


# ---------------------------------------------------------------------------
# Sidecar v2 validation -- the single source of truth for the contract that
# agents/triage-verify.md describes in prose. Every violation is its own
# message, prefixed `<unit_id>[/<record_id>]: rule N:`, and all of them are
# collected (same enumerate-everything style as `assert_full_coverage`).
# ---------------------------------------------------------------------------


def _check_refute(loc: dict, where: str, project_root: Path | None) -> list[str]:
    """Rule 6: a `rejected` candidate must cite a line the engine can hash --
    otherwise `compute_evidence_hash` yields `nohash00` (or no evidence at
    all) and the mark is never invalidated on a later audit run."""
    errors: list[str] = []
    refute_file = loc.get("refute_file")
    refute_line = loc.get("refute_line")
    if not isinstance(refute_file, str) or not refute_file:
        errors.append(f"{where}: rule 6: rejected needs refute_file (a project_root-relative path)")
    if not _is_int(refute_line) or refute_line <= 0:
        errors.append(f"{where}: rule 6: rejected needs refute_line (a positive int)")
    if errors:
        return errors

    parts = PurePosixPath(refute_file.replace("\\", "/")).parts
    if refute_file.startswith(("/", "\\")) or Path(refute_file).is_absolute() or re.match(r"^[A-Za-z]:", refute_file):
        return [f"{where}: rule 6: refute_file {refute_file!r} must be relative to project_root"]
    if ".." in parts:
        return [f"{where}: rule 6: refute_file {refute_file!r} must not contain '..'"]
    if project_root is None:
        return [f"{where}: rule 6: project_root unknown (parsed.json has none) -- cannot check refute_file"]

    root = project_root.resolve()
    target = (root / refute_file).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return [f"{where}: rule 6: refute_file {refute_file!r} resolves outside project_root"]
    if not target.is_file():
        return [f"{where}: rule 6: refute_file {refute_file!r} does not exist under project_root"]
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [f"{where}: rule 6: refute_file {refute_file!r} unreadable: {exc}"]
    if refute_line > len(lines):
        return [f"{where}: rule 6: refute_line {refute_line} is past the end of {refute_file} ({len(lines)} lines)"]
    if not lines[refute_line - 1].strip():
        return [f"{where}: rule 6: refute_line {refute_line} of {refute_file} is blank"]
    return []


def _validate_location(loc, unit_id: str, idx: int, records_by_id: dict[str, Record], project_root: Path | None) -> list[str]:
    if not isinstance(loc, dict):
        return [f"{unit_id}: rule 2: locations[{idx}] is not an object"]
    rid = loc.get("record_id")
    where = f"{unit_id}/{rid}" if isinstance(rid, str) and rid else f"{unit_id}/locations[{idx}]"
    errors: list[str] = []

    missing = [k for k in _LOCATION_KEYS if k not in loc]
    if missing:
        errors.append(f"{where}: rule 2: missing field(s) {missing}")
    for key in ("record_id", "sink_hash", "sink_file", "note"):
        if key in loc and not isinstance(loc[key], str):
            errors.append(f"{where}: rule 2: {key} must be a string")
    if "sink_line" in loc and not _is_int(loc["sink_line"]):
        errors.append(f"{where}: rule 2: sink_line must be an int")

    # Rule 4.
    record = records_by_id.get(rid) if isinstance(rid, str) else None
    if record is not None and isinstance(loc.get("sink_hash"), str) and loc["sink_hash"] != record.sink_hash:
        errors.append(
            f"{where}: rule 4: sink_hash {loc['sink_hash']!r} != {record.sink_hash!r} of that record in findings.json"
        )
    status = loc.get("status")
    if status not in LOCATION_STATUSES:
        errors.append(f"{where}: rule 4: status {status!r} not one of {list(LOCATION_STATUSES)}")

    # Rule 7.
    keys = loc.get("condition_keys")
    if "condition_keys" in loc:
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            errors.append(f"{where}: rule 2: condition_keys must be a list of strings")
            keys = []
        else:
            unknown = sorted(set(keys) - CONDITION_KEYS)
            if unknown:
                errors.append(f"{where}: rule 7: unknown condition_keys {unknown}")
    if not isinstance(keys, list):
        keys = []

    # Rule 5.
    candidate = loc.get("verdict_candidate")
    if candidate not in (*_VALID_CANDIDATE_VERDICTS, None):
        errors.append(f"{where}: rule 5: verdict_candidate {candidate!r} not one of rejected|reaffirmed|null")
    elif status == "confirmed" and candidate != "reaffirmed":
        errors.append(f"{where}: rule 5: status confirmed needs verdict_candidate reaffirmed, got {candidate!r}")
    elif status in ("changed", "manual_review") and candidate is not None:
        errors.append(f"{where}: rule 5: status {status} needs verdict_candidate null, got {candidate!r}")
    elif status == "false_positive" and candidate == "reaffirmed":
        errors.append(f"{where}: rule 5: status false_positive needs verdict_candidate rejected or null")
    elif status == "false_positive" and candidate is None:
        # A false positive closed outside the repo: no refute line to cite,
        # so the reason has to be structured and explained instead.
        if not keys:
            errors.append(f"{where}: rule 5: false_positive with null candidate needs at least one condition_keys entry")
        if not isinstance(loc.get("note"), str) or not loc["note"].strip():
            errors.append(f"{where}: rule 5: false_positive with null candidate needs a non-empty note")

    # Rule 6.
    if candidate == "rejected":
        errors.extend(_check_refute(loc, where, project_root))
    elif "refute_file" in loc or "refute_line" in loc:
        errors.append(f"{where}: rule 6: refute_file/refute_line are allowed only with verdict_candidate rejected")

    return errors


def validate_sidecar(
    sidecar,
    *,
    unit_id: str,
    unit_records: list[Record],
    tickets_root: Path,
    project_root: Path | None,
) -> list[str]:
    """Rules 1-10 and 12 (minus rule 10's cross-sidecar uniqueness) for one unit's
    sidecar against the records `grouping.json` assigned to it. Returns
    every violation found; `[]` means valid."""
    if not isinstance(sidecar, dict):
        return [f"{unit_id}: rule 2: sidecar root must be a JSON object"]
    version = sidecar.get("sidecar_version")
    if version != SIDECAR_VERSION:
        return [
            f"{unit_id}: rule 1: sidecar_version {version!r} (v1 or unknown) -- "
            f"regenerate this unit's sidecar in the v{SIDECAR_VERSION} format"
        ]

    errors: list[str] = []

    # Rule 2.
    missing = [k for k in _HEADER_KEYS if k not in sidecar]
    if missing:
        errors.append(f"{unit_id}: rule 2: missing field(s) {missing}")
    if "unit_id" in sidecar and sidecar["unit_id"] != unit_id:
        errors.append(f"{unit_id}: rule 2: unit_id {sidecar['unit_id']!r} != sidecar file stem / grouping key {unit_id!r}")
    disposition = sidecar.get("disposition")
    if disposition not in DISPOSITIONS:
        errors.append(f"{unit_id}: rule 2: disposition {disposition!r} not one of {list(DISPOSITIONS)}")
    for key in ("title", "unit_file", "severity_change_rationale", "fix_pattern_note"):
        if key in sidecar and not isinstance(sidecar[key], str):
            errors.append(f"{unit_id}: rule 2: {key} must be a string")
    if not isinstance(sidecar.get("title"), str) or not sidecar["title"].strip():
        errors.append(f"{unit_id}: rule 2: title must be non-empty")
    for key in ("severity_before", "severity_after"):
        if key in sidecar and sidecar[key] is not None and sidecar[key] not in SEVERITIES:
            errors.append(f"{unit_id}: rule 2: {key} {sidecar[key]!r} not one of {list(SEVERITIES)} or null")
    locations = sidecar.get("locations")
    if not isinstance(locations, list):
        if "locations" in sidecar:
            errors.append(f"{unit_id}: rule 2: locations must be a list")
        locations = []

    # Rule 3.
    expected_ids = [r.record_id for r in unit_records]
    records_by_id = {r.record_id: r for r in unit_records}
    seen: dict[str, int] = {}
    for loc in locations:
        if isinstance(loc, dict) and isinstance(loc.get("record_id"), str):
            seen[loc["record_id"]] = seen.get(loc["record_id"], 0) + 1
    absent = sorted(set(expected_ids) - set(seen))
    extra = sorted(set(seen) - set(expected_ids))
    duplicated = sorted(rid for rid, n in seen.items() if n > 1)
    if absent:
        errors.append(f"{unit_id}: rule 3: no location for record_id(s) {absent}")
    if extra:
        errors.append(f"{unit_id}: rule 3: location(s) for record_id(s) not in this unit {extra}")
    if duplicated:
        errors.append(f"{unit_id}: rule 3: duplicated location(s) for record_id(s) {duplicated}")

    # Rules 4-7, per location.
    for idx, loc in enumerate(locations):
        errors.extend(_validate_location(loc, unit_id, idx, records_by_id, project_root))

    # Rules 8-9, 12: disposition <-> statuses <-> severity <-> filename prefix.
    unit_file = sidecar.get("unit_file")
    unit_file = unit_file if isinstance(unit_file, str) else ""
    m = _UNIT_FILE_RE.match(unit_file)
    prefix = m.group(1) if m else None
    severity_after = sidecar.get("severity_after")
    real_substantive = [
        (loc["record_id"], loc["status"], records_by_id[loc["record_id"]].verdict)
        for loc in locations
        if isinstance(loc, dict)
        and loc.get("status") in _REAL_STATUSES
        and isinstance(loc.get("record_id"), str)
        and loc["record_id"] in records_by_id
        and records_by_id[loc["record_id"]].verdict in SUBSTANTIVE_VERDICTS
    ]
    if disposition == "work_unit":
        if not real_substantive:
            errors.append(
                f"{unit_id}: rule 8: work_unit needs at least one confirmed or changed location on a "
                f"confirmed/needs_validation record (a hardening note does not count) -- re-file as triage"
            )
        if severity_after not in SEVERITIES:
            errors.append(f"{unit_id}: rule 8: work_unit needs severity_after in {list(SEVERITIES)}, got {severity_after!r}")
        elif prefix is not None and prefix != SEVERITY_PREFIX[severity_after]:
            errors.append(
                f"{unit_id}: rule 8: unit_file prefix {prefix!r} != {SEVERITY_PREFIX[severity_after]!r} "
                f"for severity_after {severity_after}"
            )
    elif disposition == "triage":
        if severity_after is not None:
            errors.append(f"{unit_id}: rule 9: triage needs severity_after null, got {severity_after!r}")
        if prefix is not None and prefix != TRIAGE_PREFIX:
            errors.append(f"{unit_id}: rule 9: triage unit_file prefix must be {TRIAGE_PREFIX!r}, got {prefix!r}")
        for rid, status, verdict in real_substantive:
            errors.append(
                f"{unit_id}/{rid}: rule 12: status {status} on a {verdict} record in a triage unit -- "
                f"promote it in Phase 4.5 — confirmed findings/leads may not stay in a triage bucket"
            )

    # Rule 10 (per sidecar half).
    if "unit_file" in sidecar:
        if m is None or "/" in unit_file or "\\" in unit_file:
            errors.append(f"{unit_id}: rule 10: unit_file {unit_file!r} is not a '<prefix>-<unit_id>-<slug>.md' basename")
        elif m.group(2) != unit_id:
            errors.append(f"{unit_id}: rule 10: unit_file {unit_file!r} names unit_id {m.group(2)!r}")
        elif not (Path(tickets_root) / unit_file).is_file():
            errors.append(f"{unit_id}: rule 10: unit_file {unit_file!r} does not exist in TICKETS_ROOT")

    return errors


def pending_units(sidecars: dict, grouping: dict) -> list[str]:
    return sorted(u for u in grouping if u not in sidecars)


def validate_all(
    sidecars: dict,
    grouping: dict,
    records: list[Record],
    tickets_root: Path,
    project_root: Path | None,
) -> list[str]:
    """Every sidecar through `validate_sidecar`, plus the cross-sidecar
    checks: a sidecar for a unit `grouping.json` doesn't know (rule 2), two
    sidecars claiming one unit file (rule 10), and -- only once no unit is
    pending -- a unit file on disk no sidecar claims (rule 11). A unit with
    no sidecar is pending, not a violation."""
    by_id = {r.record_id: r for r in records}
    errors: list[str] = []
    for unit_id in sorted(sidecars):
        if unit_id not in grouping:
            errors.append(f"{unit_id}: rule 2: sidecar for a unit_id not in grouping.json")
            continue
        unit_records = [by_id[rid] for rid in grouping[unit_id] if rid in by_id]
        errors.extend(
            validate_sidecar(
                sidecars[unit_id],
                unit_id=unit_id,
                unit_records=unit_records,
                tickets_root=tickets_root,
                project_root=project_root,
            )
        )

    claimed: dict[str, list[str]] = {}
    for unit_id, sidecar in sidecars.items():
        if isinstance(sidecar, dict) and isinstance(sidecar.get("unit_file"), str) and sidecar["unit_file"]:
            claimed.setdefault(sidecar["unit_file"], []).append(unit_id)
    for unit_file, owners in sorted(claimed.items()):
        if len(owners) > 1:
            errors.append(f"{', '.join(sorted(owners))}: rule 10: unit_file {unit_file!r} is claimed by more than one sidecar")

    if not pending_units(sidecars, grouping):
        # Pending units may already have written their unit file; only once
        # every unit has reported can an unclaimed file be called an orphan.
        for path in sorted(Path(tickets_root).glob("*.md")):
            if path.is_file() and path.name != "INDEX.md" and path.name not in claimed:
                errors.append(f"(tickets_root): rule 11: {path.name} is not claimed by any sidecar -- orphaned unit file")

    return errors


# ---------------------------------------------------------------------------
# emit_verdicts: Phase 5's verdict hand-back channel. `--verdicts-in` keys by
# `sink_hash`, but several records can share one (a confirmed finding and a
# needs_validation lead on the same snippet; two leads with different
# sink_kind), so a hash's verdict is decided over ALL substantive records
# carrying it -- a `rejected` NV must never mark the confirmed finding it
# shares a hash with. Hardening records sharing the hash are neutral: their
# `confirmed` means "the observation is correct", and the engine reads
# `reaffirmed` as lifting an earlier `rejected` on that hash.
# Only structural fields cross this boundary; free text never does.
# ---------------------------------------------------------------------------


def _location_index(records: list[Record], sidecars: dict) -> dict[str, dict]:
    """record_id -> its sidecar location, for locations whose record_id and
    sink_hash both match a record. Anything else counts as not verified."""
    by_id = {r.record_id: r for r in records}
    out: dict[str, dict] = {}
    for sidecar in sidecars.values():
        if not isinstance(sidecar, dict):
            continue
        for loc in sidecar.get("locations") or []:
            if not isinstance(loc, dict):
                continue
            record = by_id.get(loc.get("record_id"))
            if record is not None and loc.get("sink_hash") == record.sink_hash:
                out[record.record_id] = loc
    return out


def _condition_keys_union(locs: list[dict]) -> list[str]:
    keys: set[str] = set()
    for loc in locs:
        for k in loc.get("condition_keys") or []:
            if isinstance(k, str) and k in CONDITION_KEYS:
                keys.add(k)
    return sorted(keys)


def _decide_hash(locs: list[dict], all_verified: bool) -> tuple[str, dict | None]:
    """-> ("verdict", entry-fields) | ("conflict", None) | ("withheld", None)."""
    statuses = [loc.get("status") for loc in locs]
    rejected_refs = {
        (loc.get("refute_file"), loc.get("refute_line"))
        for loc in locs
        if loc.get("status") == "false_positive" and loc.get("verdict_candidate") == "rejected"
    }
    if any(s in ("confirmed", "changed") for s in statuses) and "false_positive" in statuses:
        return "conflict", None
    if len(rejected_refs) > 1:
        return "conflict", None
    if not all_verified:
        return "withheld", None

    keys = _condition_keys_union(locs)
    if all(s == "false_positive" and loc.get("verdict_candidate") == "rejected" for s, loc in zip(statuses, locs)):
        refute_file, refute_line = next(iter(rejected_refs))
        entry: dict = {"verdict": "rejected"}
        if keys:
            entry["condition_keys"] = keys
        if isinstance(refute_file, str) and refute_file and _is_int(refute_line) and refute_line > 0:
            entry["refute_file"] = refute_file
            entry["refute_line"] = refute_line
        return "verdict", entry
    if all(s == "confirmed" for s in statuses):
        entry = {"verdict": "reaffirmed"}
        if keys:
            entry["condition_keys"] = keys
        return "verdict", entry
    # changed / manual_review / false_positive+null, or a mix of those with
    # each other or with a rejected false_positive: nothing definitive.
    return "withheld", None


def emit_verdicts(records: list[Record], sidecars: dict) -> dict:
    """Build `{"verdicts": [...], "conflicts": [hash...], "withheld": [hash...]}`.

    Per `sink_hash` (over every confirmed/needs_validation record in
    findings.json with that hash; hardening records are ignored, and a hash
    carried only by hardening records is withheld):
    - `rejected`   -- all verified, all `false_positive` + `rejected`, one
                      refute_file/refute_line between them;
    - `reaffirmed` -- all verified and all `confirmed`;
    - conflict     -- verified records disagree (`confirmed`/`changed` vs
                      `false_positive`, or rejected with different refute);
    - withheld     -- anything else: some record not verified yet, or only
                      `changed`/`manual_review`/`false_positive`+null.
    Conflicts and withheld hashes are not sent; `nohash00` is never sent.

    Only the fields in `_VERDICT_ENTRY_ALLOWED_KEYS` ever appear in an
    output entry -- see `test_no_free_text_leak.py` for the machine-checked
    guarantee."""
    loc_of = _location_index(records, sidecars)
    by_hash: dict[str, list[Record]] = {}
    all_hashes: set[str] = set()
    for r in records:
        if not r.sink_hash or r.sink_hash == _NOHASH:
            continue
        all_hashes.add(r.sink_hash)
        if r.verdict in SUBSTANTIVE_VERDICTS:
            by_hash.setdefault(r.sink_hash, []).append(r)

    verdicts: list[dict] = []
    conflicts: list[str] = []
    withheld: list[str] = []
    for sink_hash in sorted(all_hashes):
        hash_records = by_hash.get(sink_hash, [])
        locs = [loc_of[r.record_id] for r in hash_records if r.record_id in loc_of]
        if not locs:
            withheld.append(sink_hash)
            continue
        outcome, fields = _decide_hash(locs, all_verified=len(locs) == len(hash_records))
        if outcome == "conflict":
            conflicts.append(sink_hash)
        elif outcome == "withheld":
            withheld.append(sink_hash)
        else:
            entry = {"sink_hash": sink_hash, "verdict": fields["verdict"], "source": _VERDICT_SOURCE}
            entry.update({k: v for k, v in fields.items() if k != "verdict"})
            assert set(entry) <= _VERDICT_ENTRY_ALLOWED_KEYS  # defensive -- enforced by construction above
            verdicts.append(entry)
    return {"verdicts": verdicts, "conflicts": conflicts, "withheld": withheld}


# ---------------------------------------------------------------------------
# emit_index: INDEX.md -- the single home for everything pulled out of unit
# bodies (severity, verification status, sink_hash, flags, trace).
# ---------------------------------------------------------------------------


def _cell(text) -> str:
    text = "—" if text is None or text == "" else str(text)
    return text.replace("|", "\\|").replace("\n", " ")


def _loc_str(r: Record) -> str:
    return f"{r.sink_file}:{r.sink_line}" if r.sink_file else "(no location)"


def _verified_loc_str(r: Record, loc: dict | None) -> str:
    """The audit location, plus `→ <sidecar location>` when verification
    recorded a different one (a `changed` record whose sink has moved)."""
    audit = _loc_str(r)
    if not loc:
        return audit
    sink_file, sink_line = loc.get("sink_file"), loc.get("sink_line")
    if isinstance(sink_file, str) and sink_file and _is_int(sink_line) and (sink_file, sink_line) != (r.sink_file, r.sink_line):
        return f"{audit} → {sink_file}:{sink_line}"
    return audit


def _status_counts(locs: list[dict]) -> str:
    counts: dict[str, int] = {}
    for loc in locs:
        counts[str(loc.get("status"))] = counts.get(str(loc.get("status")), 0) + 1
    return ", ".join(f"{s} {counts[s]}" for s in LOCATION_STATUSES if s in counts) or "—"


def _verified_keys(locs: list[dict]) -> list[str]:
    return sorted({k for loc in locs for k in (loc.get("condition_keys") or []) if isinstance(k, str)})


def _record_detail(r: Record) -> str:
    if r.verdict == "needs_validation":
        parts = [r.claimed_root_cause or "(no claimed root cause)"]
        if r.blockers:
            parts.append("blockers: " + "; ".join(r.blockers))
        return " — ".join(parts)
    if r.verdict == "hardening":
        return r.text or "(no text)"
    return f"{r.severity or '—'} {r.category or ''}".strip()


def emit_index(
    records: list[Record],
    grouping: dict,
    sidecars: dict,
    *,
    priority_map: dict | None = None,
    header: dict | None = None,
) -> str:
    """Build INDEX.md v2's text. Assumes `sidecars` already passed
    `validate_all` (the CLI never calls this otherwise).

    `priority_map` (from `--config`): `{"crit"|"high"|"med"|"low": <tracker
    priority>, "triage": <triage_bucket_priority>}`; the priority column
    exists only when it is given. `header`: `audit_root`,
    `findings_json_sha256`, `project_root`, `project_root_resolved`.

    Every record appears in Traceability by `record_id`, with its own status
    -- records sharing a `sink_hash` are never conflated."""
    header = header or {}
    by_id = {r.record_id: r for r in records}
    unit_of: dict[str, str] = {}
    for unit_id, record_ids in grouping.items():
        for rid in record_ids:
            unit_of[rid] = unit_id
    loc_of = _location_index(records, sidecars)
    pending = pending_units(sidecars, grouping)
    work = sorted(
        (u for u, s in sidecars.items() if u in grouping and s.get("disposition") == "work_unit"),
        key=lambda u: (-_SEVERITY_RANK.get(sidecars[u].get("severity_after"), -1), sidecars[u].get("unit_file", "")),
    )
    triage = sorted(
        (u for u, s in sidecars.items() if u in grouping and s.get("disposition") == "triage"),
        key=lambda u: sidecars[u].get("unit_file", ""),
    )

    def unit_locs(unit_id: str) -> list[dict]:
        return [loc_of[rid] for rid in grouping.get(unit_id, []) if rid in loc_of]

    def unit_detail(unit_id: str) -> list[str]:
        """Per-record block: the verifier's note can carry what the columns
        can't (extra sinks found nearby, a moved location)."""
        s = sidecars[unit_id]
        out = [f"### `{s.get('unit_file')}` — {_cell(s.get('title'))}", ""]
        for rid in grouping[unit_id]:
            r = by_id.get(rid)
            loc = loc_of.get(rid, {})
            if r is None:
                continue
            out.append(
                f"- `{r.record_id}` {r.verdict} `{_verified_loc_str(r, loc)}` {_cell(r.sink_kind)} — {_cell(_record_detail(r))} "
                f"— **{_cell(loc.get('status'))}**: {_cell(loc.get('note'))}"
            )
        out.append("")
        return out

    lines: list[str] = ["# INDEX", ""]

    # 1. Header.
    counts = {"confirmed": 0, "needs_validation": 0, "hardening": 0}
    for r in records:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    project_root = header.get("project_root")
    resolved = header.get("project_root_resolved")
    root_line = f"`{project_root}`" if project_root else "unknown"
    if isinstance(resolved, list) and len(resolved) == 2:
        root_line += f" (sink files resolved: {resolved[0]}/{resolved[1]})"
    lines += [
        f"- audit_root: `{header.get('audit_root') or 'unknown'}`",
        f"- findings_json_sha256: `{header.get('findings_json_sha256') or 'unknown'}`",
        f"- project_root: {root_line}",
        "- records: " + ", ".join(f"{v} {counts[v]}" for v in counts),
        f"- units: work_unit {len(work)}, triage {len(triage)}, pending {len(pending)}",
        "",
    ]

    # 2. Work units.
    lines += ["## Work units", ""]
    if work:
        cols = ["File", "Topic", "Severity (before → after)"]
        if priority_map is not None:
            cols.append("Priority")
        cols += ["Locations", "condition_keys"]
        lines.append("| " + " | ".join(cols) + " |")
        lines.append("|" + "---|" * len(cols))
        for u in work:
            s = sidecars[u]
            locs = unit_locs(u)
            row = [f"`{s.get('unit_file')}`", _cell(s.get("title")), f"{s.get('severity_before') or '—'} → {s.get('severity_after')}"]
            if priority_map is not None:
                row.append(_cell(priority_map.get(SEVERITY_PREFIX.get(s.get("severity_after"), ""))))
            row += [_status_counts(locs), _cell(", ".join(_verified_keys(locs)))]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        for u in work:
            lines += unit_detail(u)
    else:
        lines += ["None.", ""]

    # 3. Triage.
    lines += ["## Triage", ""]
    if triage:
        if priority_map is not None:
            lines += [f"Tracker priority: {_cell(priority_map.get(TRIAGE_PREFIX))}", ""]
        lines += ["| File | Topic | Records | Statuses |", "|---|---|---|---|"]
        for u in triage:
            s = sidecars[u]
            lines.append(f"| `{s.get('unit_file')}` | {_cell(s.get('title'))} | {len(grouping[u])} | {_status_counts(unit_locs(u))} |")
        lines.append("")
        for u in triage:
            lines += unit_detail(u)
    else:
        lines += ["None.", ""]

    # 4. Severity history.
    lines += ["## Severity history", ""]
    changed = [u for u in work + triage if sidecars[u].get("severity_before") != sidecars[u].get("severity_after")]
    if changed:
        lines += ["| File | Before | After | Rationale |", "|---|---|---|---|"]
        for u in changed:
            s = sidecars[u]
            lines.append(
                f"| `{s.get('unit_file')}` | {_cell(s.get('severity_before'))} | {_cell(s.get('severity_after'))} "
                f"| {_cell(s.get('severity_change_rationale'))} |"
            )
    else:
        lines.append("None.")
    lines.append("")

    # 5. Traceability.
    lines += [
        "## Traceability: record -> unit",
        "",
        "| record_id | sink_hash | verdict | location (audit → actual) | unit file | status "
        "| condition_keys (audit → verified) | flags | matched_to | discovered_via |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in records:
        unit_id = unit_of.get(r.record_id)
        sidecar = sidecars.get(unit_id) if unit_id else None
        if unit_id is None:
            unit_cell = "(uncovered)"
        elif sidecar is None:
            unit_cell = f"`{unit_id}` (pending)"
        else:
            unit_cell = f"`{sidecar.get('unit_file')}`"
        loc = loc_of.get(r.record_id)
        status = loc.get("status") if loc else "pending"
        verified_keys = ", ".join(_verified_keys([loc])) if loc else ""
        ck = f"{_cell(', '.join(r.condition_keys))} → {_cell(verified_keys)}"
        lines.append(
            f"| `{r.record_id}` | `{r.sink_hash}` | {r.verdict} | `{_cell(_verified_loc_str(r, loc))}` | {unit_cell} "
            f"| {_cell(status)} | {ck} "
            f"| {_cell(' '.join(r.flags))} | {_cell(r.matched_to)} | {_cell(r.discovered_via)} |"
        )
    lines.append("")

    # 6. Pending verification.
    lines += ["## Pending verification", ""]
    if pending:
        for u in pending:
            lines.append(f"- `{u}` — {len(grouping[u])} record(s): {', '.join(f'`{rid}`' for rid in grouping[u])}")
    else:
        lines.append("None.")
    lines.append("")

    # 7. Prior-run resolutions.
    prior = [r for r in records if r.prior_resolution]
    if prior:
        lines += [
            "## Prior-run resolutions",
            "",
            "Marks carried over from `.findings_state.json` -- annotations to "
            "reconcile against current verification, not verdicts to copy.",
            "",
        ]
        for r in prior:
            res = r.prior_resolution or {}
            lines.append(
                f"- `{r.record_id}` `{r.sink_hash}` — previously **{res.get('verdict', '?')}** "
                f"(source: `{res.get('source', '')}`)"
            )
        lines.append("")

    # 8. Verdict hand-back.
    hand_back = emit_verdicts(records, sidecars)
    by_verdict: dict[str, int] = {}
    for e in hand_back["verdicts"]:
        by_verdict[e["verdict"]] = by_verdict.get(e["verdict"], 0) + 1
    lines += [
        "## Verdict hand-back",
        "",
        f"- Sent: {len(hand_back['verdicts'])}"
        + (f" ({', '.join(f'{v} {n}' for v, n in sorted(by_verdict.items()))})" if by_verdict else ""),
        f"- **Conflicts (not sent -- verified records of one sink_hash disagree)**: {len(hand_back['conflicts'])}",
    ]
    hash_rids: dict[str, list[str]] = {}
    for r in records:
        hash_rids.setdefault(r.sink_hash, []).append(r.record_id)
    for h in hand_back["conflicts"]:
        lines.append(f"  - `{h}`: {', '.join(f'`{rid}`' for rid in hash_rids.get(h, []))}")
    lines.append(f"- Withheld (not sent, not an error): {len(hand_back['withheld'])}")
    for h in hand_back["withheld"]:
        lines.append(f"  - `{h}`: {', '.join(f'`{rid}`' for rid in hash_rids.get(h, []))}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# --config: the project's `.audit-triage.json` (see .audit-triage.example.json).
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    pass


def load_priority_map(path: Path) -> dict:
    """-> `{"crit", "high", "med", "low", "triage"}` -> tracker priority name.
    `$`-prefixed keys (`$comment`) are ignored. Raises `ConfigError` listing
    every missing/invalid value -- an explicit `--config` is fail-closed."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: root must be a JSON object")
    problems: list[str] = []
    mapping = payload.get("severity_to_priority")
    if not isinstance(mapping, dict):
        problems.append("severity_to_priority must be an object")
        mapping = {}
    out: dict[str, str] = {}
    for key in SEVERITY_PREFIX.values():
        value = mapping.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"severity_to_priority.{key} must be a non-empty string")
        else:
            out[key] = value
    unknown = sorted(k for k in mapping if not k.startswith("$") and k not in SEVERITY_PREFIX.values())
    if unknown:
        problems.append(f"severity_to_priority has unknown key(s) {unknown} (expected crit/high/med/low)")
    triage_priority = payload.get("triage_bucket_priority")
    if not isinstance(triage_priority, str) or not triage_priority.strip():
        problems.append("triage_bucket_priority must be a non-empty string")
    else:
        out[TRIAGE_PREFIX] = triage_priority
    if problems:
        raise ConfigError(f"{path}: " + "; ".join(problems))
    return out


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _read_json(path: Path, what: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {what} {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate sidecars, then assemble INDEX.md + .work/verdicts.json from a triage run's .work/ artifacts."
    )
    parser.add_argument("tickets_root", type=Path)
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="The project's .audit-triage.json: severity_to_priority / triage_bucket_priority "
        "fill INDEX.md's priority column (absent without this flag).",
    )
    args = parser.parse_args(argv)

    tickets_root = args.tickets_root.resolve()
    work_dir = tickets_root / ".work"

    parsed_path = work_dir / "parsed.json"
    if not parsed_path.is_file():
        print(f"Error: {parsed_path} not found -- run parse_findings.py first (Phase 1).", file=sys.stderr)
        return 2
    grouping_path = work_dir / "grouping.json"
    if not grouping_path.is_file():
        print(f"Error: {grouping_path} not found -- Phase 2 grouping is required before INDEX assembly.", file=sys.stderr)
        return 2
    try:
        parsed = _read_json(parsed_path, "parsed records")
        grouping = _read_json(grouping_path, "grouping")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if not isinstance(grouping, dict):
        print(f"Error: {grouping_path}: root must be a JSON object of unit_id -> [record_id, ...]", file=sys.stderr)
        return 2
    records = [Record.from_dict(d) for d in parsed.get("records", [])]

    # grouping.json may have been edited after Phase 3 validated it (Phase
    # 4.5). This also vets each value's shape (a non-empty list of strings);
    # nothing below may iterate grouping before it passes.
    try:
        assert_full_coverage(records, grouping)
    except CoverageError as exc:
        print(f"Error: coverage check failed: {exc}", file=sys.stderr)
        return 2

    priority_map = None
    if args.config is not None:
        try:
            priority_map = load_priority_map(args.config)
        except ConfigError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    raw_root = parsed.get("project_root")
    project_root = Path(raw_root) if isinstance(raw_root, str) and raw_root else None

    violations: list[str] = []
    sidecars: dict[str, dict] = {}
    verify_dir = work_dir / "verify"
    if verify_dir.is_dir():
        for p in sorted(verify_dir.glob("*.json")):
            try:
                sidecars[p.stem] = _read_json(p, "sidecar")
            except ValueError as exc:
                violations.append(f"{p.stem}: rule 2: {exc}")
    violations += validate_all(sidecars, grouping, records, tickets_root, project_root)
    if violations:
        print(f"Error: {len(violations)} sidecar contract violation(s); INDEX.md and verdicts.json not written:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 2

    pending = pending_units(sidecars, grouping)
    if pending:
        print(f"Warning: {len(pending)} unit(s) pending verification (no sidecar yet): {pending}", file=sys.stderr)

    header = {
        "audit_root": parsed.get("audit_root"),
        "findings_json_sha256": parsed.get("findings_json_sha256"),
        "project_root": raw_root,
        "project_root_resolved": parsed.get("project_root_resolved"),
    }
    index_text = emit_index(records, grouping, sidecars, priority_map=priority_map, header=header)
    verdicts_result = emit_verdicts(records, sidecars)
    verdicts_payload = {
        "schema_version": 1,
        "findings_json_sha256": parsed.get("findings_json_sha256", ""),
        "verdicts": verdicts_result["verdicts"],
    }

    index_path = tickets_root / "INDEX.md"
    index_path.write_text(index_text, encoding="utf-8")
    verdicts_path = work_dir / "verdicts.json"
    verdicts_path.write_text(json.dumps(verdicts_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if verdicts_result["conflicts"]:
        print(
            f"Warning: {len(verdicts_result['conflicts'])} sink_hash(es) with conflicting verification "
            f"across their records, not handed back: {verdicts_result['conflicts']}",
            file=sys.stderr,
        )
    print(f"Wrote {index_path}")
    print(
        f"Wrote {verdicts_path} ({len(verdicts_payload['verdicts'])} verdict(s), "
        f"{len(verdicts_result['conflicts'])} conflict(s), {len(verdicts_result['withheld'])} withheld)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
