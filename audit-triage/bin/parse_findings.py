#!/usr/bin/env python3
"""Parse `<AUDIT_ROOT>/findings.json` into normalized triage `Record`s.

CLI entry point for Phase 1 (parse) and Phase 3 (bundle) of
`commands/triage-findings.md`. stdlib only -- no third-party deps.

`findings.json` is the `fr-security-review` public contract (see
`security-review/bin/dedupe/export.py`): it carries identity/verdict/
classification fields only, never finding *bodies*. This module never
regexes `REPORT.md`/`REPORT/*.md` as structured data -- it reads
`findings.json` via `json.load` and validates `schema_version` up front
(loud, noisy refusal on mismatch, per Principle "verify against the
contract, don't guess a different shape"). Finding bodies are fetched from
`REPORT/<root_cause_family>.md` only for `confirmed` records, and only by
`bundle()`, on demand, keyed by the `* **sink_hash**: \\`<hex8>\\`` line
`security-refute` already uses for the same lookup.

Two-call protocol across the orchestrator's phases (separate `python3`
subprocesses -- no shared interpreter state):

    Phase 0.3: parse_findings.py <AUDIT_ROOT> --tickets-root <TICKETS_ROOT> --check-only
        -> only runs the TICKETS_ROOT guard (`check_tickets_root`) and prints
           its verdict; writes nothing.

    Phase 1: parse_findings.py <AUDIT_ROOT> --tickets-root <TICKETS_ROOT> \\
                 --project-root <PROJECT_ROOT> [--archive-previous]
        -> guard -> (archive) -> resolve PROJECT_ROOT -> check that the
           audit's sink_files resolve under it -> only then persists
           <TICKETS_ROOT>/.work/parsed.json (records + findings_json_sha256 +
           project_root), prints counts to stdout.

    Phase 2: the orchestrator (an LLM, not a script) does the fix-pattern
        grouping itself and writes <TICKETS_ROOT>/.work/grouping.json as
        {"<unit_id>": ["<record_id>", ...], ...}.

    Phase 3: parse_findings.py <AUDIT_ROOT> --tickets-root <TICKETS_ROOT> \\
                 --grouping <TICKETS_ROOT>/.work/grouping.json
        -> validates full coverage first (Principle 3: zero orphans, zero
           duplicates, unit_id form, non-empty lists of record_ids) -- a
           failure exits 2 before anything is archived or written -- then
           resumes Phase 1's run (PROJECT_ROOT comes back from parsed.json),
           re-parses (idempotent), writes one bundle
           file per unit under <TICKETS_ROOT>/.work/bundles/<unit_id>.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

FINDINGS_JSON_NAME = "findings.json"
EXPECTED_SCHEMA_VERSION = 1
STATE_FILENAME = ".findings_state.json"

# Closed enum, mirrored from `security-review/bin/dedupe/models.py:CONDITION_KEYS`.
# The two plugins must stay in sync the same way the audit plugin's own
# sink_kind/root_cause_family enums do (README.md "Configuration"); see
# `tests/test_condition_keys_sync.py` for the machine-checked mirror.
CONDITION_KEYS: frozenset[str] = frozenset(
    {
        "internal_network_only",
        "admin_only",
        "needs_trusted_integration_compromise",
        "needs_separate_primitive",
        "deployment_control_not_in_source",
        "requires_victim_interaction",
        "requires_attacker_owned_account",
    }
)

_RESOLUTION_VERDICTS = ("rejected", "reaffirmed")

UNIT_ID_RE = re.compile(r"[a-z0-9]+")


class FindingsContractError(Exception):
    """Raised for a missing / unparseable / schema-mismatched findings.json.

    Callers must abort loudly -- never fall back to parsing REPORT.md /
    REPORT/*.md as structured data (Phase 0.1's explicit prohibition)."""


class ProjectRootError(Exception):
    """Raised by `resolve_project_root` when a resumed run is handed an
    explicit PROJECT_ROOT that contradicts the one persisted in parsed.json."""


class TicketsRootError(Exception):
    """Raised when TICKETS_ROOT cannot be written or archived safely: it
    holds a symlink (a write or a move could land outside TICKETS_ROOT), or
    git could not tell in time whether it holds tracked files."""


class CoverageError(Exception):
    """Raised by `assert_full_coverage` -- lists every orphan, duplicate,
    unknown record_id, malformed unit_id and malformed unit value (not a
    list, empty, non-string element) in one message, not just the first (same
    fail-closed, enumerate-everything style as `state.load_verdicts_in`)."""


# ---------------------------------------------------------------------------
# Record: one normalized row from findings.json's confirmed / needs_validation
# / hardening lists. A single dataclass shape for all three verdicts (rather
# than three types) mirrors Phase 1's own "normalized in-memory index" framing
# in commands/triage-findings.md; fields that don't apply to a given verdict
# are left at their default (None / empty tuple).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Record:
    record_id: str  # unique by construction: "<verdict>#<index-in-that-bucket>"
    verdict: str  # "confirmed" | "needs_validation" | "hardening"
    sink_hash: str  # NOT unique across records -- see module docstring / export.py
    sink_file: str
    sink_line: int
    sink_kind: str
    root_cause_family: str
    enclosing_symbol: str
    condition_keys: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    source_file: str = ""
    slice_id: str = ""

    # confirmed-only
    primary_sink_hash: str | None = None
    is_primary: bool | None = None
    review_bucket: str | None = None  # "main" | "manual_review"
    severity: str | None = None
    confidence: int | None = None
    category: str | None = None
    discovered_via: str | None = None

    # needs_validation / hardening only
    matched_to: str | None = None  # primary_sink_hash of the group it's attached to, or None if standalone
    claimed_root_cause: str | None = None  # needs_validation only
    blockers: tuple[str, ...] = ()  # needs_validation only
    text: str | None = None  # hardening only

    # cross-run memory (Phase 0.1 "prior-run resolutions") -- the
    # `.findings_state.json` resolutions entry for this sink_hash, if any.
    # `None` if there is no previous-run mark. This is a MARK to reconcile
    # (Principle 6), never an instruction to obey.
    prior_resolution: dict | None = None

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["condition_keys"] = list(self.condition_keys)
        d["flags"] = list(self.flags)
        d["blockers"] = list(self.blockers)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Record":
        kwargs = dict(d)
        kwargs["condition_keys"] = tuple(d.get("condition_keys") or ())
        kwargs["flags"] = tuple(d.get("flags") or ())
        kwargs["blockers"] = tuple(d.get("blockers") or ())
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in kwargs.items() if k in known})


# ---------------------------------------------------------------------------
# findings.json loading.
# ---------------------------------------------------------------------------


def findings_json_path(review_root: Path) -> Path:
    return Path(review_root) / FINDINGS_JSON_NAME


def read_findings_json_bytes(review_root: Path) -> bytes:
    """Read findings.json's raw bytes, or raise a loud FindingsContractError.

    Missing file -> this audit predates the contract; don't fall back to
    parsing REPORT.md."""
    path = findings_json_path(review_root)
    if not path.is_file():
        raise FindingsContractError(
            f"{path} not found. This audit run predates the findings.json "
            f"contract (schema_version={EXPECTED_SCHEMA_VERSION}, shipped from "
            f"fr-security-review >= 4.3.0). Re-run the audit with a newer "
            f"fr-security-review version -- do not fall back to parsing "
            f"REPORT.md / REPORT/*.md."
        )
    return path.read_bytes()


def findings_json_sha256(review_root: Path) -> str:
    """sha256 of findings.json's exact on-disk bytes -- the same reference
    hash `dedupe_findings.py --verdicts-in` binds an external verdicts file
    to (see `state.read_reference_findings_json`)."""
    return hashlib.sha256(read_findings_json_bytes(review_root)).hexdigest()


def _load_payload(review_root: Path) -> dict:
    raw = read_findings_json_bytes(review_root)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FindingsContractError(f"{findings_json_path(review_root)}: cannot parse JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise FindingsContractError(f"{findings_json_path(review_root)}: root must be a JSON object")
    found_version = payload.get("schema_version")
    if found_version != EXPECTED_SCHEMA_VERSION:
        raise FindingsContractError(
            f"{findings_json_path(review_root)}: unsupported schema_version "
            f"{found_version!r} (expected {EXPECTED_SCHEMA_VERSION}). Refusing "
            f"to guess a different shape -- re-run the audit with a "
            f"fr-security-review version that emits schema {EXPECTED_SCHEMA_VERSION}."
        )
    return payload


def _load_resolutions(review_root: Path) -> dict[str, dict]:
    """Lenient read of `<review_root>/.findings_state.json`'s `resolutions`
    map. Absent / corrupt / no resolutions key -> `{}` (this is the audit
    engine's own file, same trust level as the rest of the repo -- not the
    fail-closed `--verdicts-in` path)."""
    path = Path(review_root) / STATE_FILENAME
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    raw = payload.get("resolutions")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    for sink_hash, entry in raw.items():
        if (
            isinstance(sink_hash, str)
            and isinstance(entry, dict)
            and entry.get("verdict") in _RESOLUTION_VERDICTS
        ):
            out[sink_hash] = entry
    return out


def _tuple_of_str(value) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(v) for v in value if isinstance(v, str))


def _record_from_confirmed(idx: int, entry: dict, resolutions: dict[str, dict]) -> Record:
    sink_hash = str(entry.get("sink_hash", ""))
    confidence = entry.get("confidence")
    return Record(
        record_id=f"confirmed#{idx}",
        verdict="confirmed",
        sink_hash=sink_hash,
        sink_file=str(entry.get("sink_file", "")),
        sink_line=int(entry.get("sink_line") or 0),
        sink_kind=str(entry.get("sink_kind", "")),
        root_cause_family=str(entry.get("root_cause_family", "")),
        enclosing_symbol=str(entry.get("enclosing_symbol", "")),
        condition_keys=_tuple_of_str(entry.get("condition_keys")),
        flags=_tuple_of_str(entry.get("flags")),
        source_file=str(entry.get("source_file", "")),
        slice_id=str(entry.get("slice_id", "")),
        primary_sink_hash=str(entry.get("primary_sink_hash") or "") or None,
        is_primary=bool(entry.get("is_primary", False)),
        review_bucket=str(entry.get("review_bucket") or "") or None,
        severity=str(entry.get("severity") or "") or None,
        confidence=int(confidence) if isinstance(confidence, int) else None,
        category=str(entry.get("category") or "") or None,
        discovered_via=str(entry.get("discovered_via") or "") or None,
        prior_resolution=resolutions.get(sink_hash),
    )


def _record_from_needs_validation(idx: int, entry: dict, resolutions: dict[str, dict]) -> Record:
    sink_hash = str(entry.get("sink_hash", ""))
    return Record(
        record_id=f"needs_validation#{idx}",
        verdict="needs_validation",
        sink_hash=sink_hash,
        sink_file=str(entry.get("sink_file", "")),
        sink_line=int(entry.get("sink_line") or 0),
        sink_kind=str(entry.get("sink_kind", "")),
        root_cause_family=str(entry.get("root_cause_family", "")),
        enclosing_symbol=str(entry.get("enclosing_symbol", "")),
        condition_keys=_tuple_of_str(entry.get("condition_keys")),
        flags=_tuple_of_str(entry.get("flags")),
        source_file=str(entry.get("source_file", "")),
        slice_id=str(entry.get("slice_id", "")),
        matched_to=str(entry.get("matched_to") or "") or None,
        claimed_root_cause=str(entry.get("claimed_root_cause") or "") or None,
        blockers=_tuple_of_str(entry.get("blockers")),
        prior_resolution=resolutions.get(sink_hash),
    )


def _record_from_hardening(idx: int, entry: dict, resolutions: dict[str, dict]) -> Record:
    sink_hash = str(entry.get("sink_hash", ""))
    return Record(
        record_id=f"hardening#{idx}",
        verdict="hardening",
        sink_hash=sink_hash,
        sink_file=str(entry.get("sink_file", "")),
        sink_line=int(entry.get("sink_line") or 0),
        sink_kind=str(entry.get("sink_kind", "")),
        root_cause_family=str(entry.get("root_cause_family", "")),
        enclosing_symbol=str(entry.get("enclosing_symbol", "")),
        condition_keys=_tuple_of_str(entry.get("condition_keys")),
        flags=_tuple_of_str(entry.get("flags")),
        source_file=str(entry.get("source_file", "")),
        slice_id=str(entry.get("slice_id", "")),
        matched_to=str(entry.get("matched_to") or "") or None,
        text=str(entry.get("text") or "") or None,
        prior_resolution=resolutions.get(sink_hash),
    )


def load(review_root: Path) -> list[Record]:
    """Load `<review_root>/findings.json` (via `json.load`, schema-gated)
    into a flat list of `Record`s, in findings.json's own deterministic
    order (confirmed, then needs_validation, then hardening; each in its own
    list order). Cross-references `.findings_state.json` resolutions by
    `sink_hash` (Phase 0.1's "prior-run resolutions").

    Raises `FindingsContractError` -- never falls back to parsing markdown."""
    payload = _load_payload(review_root)
    resolutions = _load_resolutions(review_root)
    records: list[Record] = []
    for idx, entry in enumerate(payload.get("confirmed") or []):
        if isinstance(entry, dict):
            records.append(_record_from_confirmed(idx, entry, resolutions))
    for idx, entry in enumerate(payload.get("needs_validation") or []):
        if isinstance(entry, dict):
            records.append(_record_from_needs_validation(idx, entry, resolutions))
    for idx, entry in enumerate(payload.get("hardening") or []):
        if isinstance(entry, dict):
            records.append(_record_from_hardening(idx, entry, resolutions))
    return records


def summarize(records: list[Record]) -> dict:
    counts: dict[str, int] = {"confirmed": 0, "needs_validation": 0, "hardening": 0}
    for r in records:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# assert_full_coverage: Principle 3, "100% coverage, zero loss" -- machine
# checked, not a prose promise. Every Record (all three verdicts -- Phase 1
# routes needs_validation/hardening to the triage bucket too, they are not
# exempt from tracing) must appear in exactly one unit's record_id list.
# ---------------------------------------------------------------------------


def assert_full_coverage(records: list[Record], grouping: dict) -> None:
    """Verify `grouping` (`{unit_id: [record_id, ...]}`) covers every record
    in `records` exactly once: zero orphans (a record in no unit), zero
    duplicates (a record in more than one unit), zero unknown references (a
    record_id in `grouping` that doesn't exist in `records`) -- and that
    every `unit_id` has the form `[a-z0-9]+` (it becomes part of the unit's
    file name `<prefix>-<unit_id>-<slug>.md`, split on dashes).

    The grouping's shape is checked too, in the same error: every value must
    be a non-empty list of strings (a unit emptied by moving its only record
    elsewhere must be deleted, not left behind as an empty bucket).

    Raises `CoverageError` enumerating every violation found, not just the
    first -- never a `TypeError` on a malformed grouping."""
    known_ids = {r.record_id for r in records}
    seen: dict[str, int] = {}
    unknown: set[str] = set()
    not_lists: list[str] = []
    empty_units: list[str] = []
    non_string: list[str] = []
    for unit_id, record_ids in grouping.items():
        if not isinstance(record_ids, list):
            not_lists.append(f"{unit_id} ({type(record_ids).__name__})")
            continue
        if not record_ids:
            empty_units.append(str(unit_id))
            continue
        for rid in record_ids:
            if not isinstance(rid, str):
                non_string.append(f"{unit_id}: {rid!r}")
                continue
            if rid not in known_ids:
                unknown.add(rid)
                continue
            seen[rid] = seen.get(rid, 0) + 1

    orphans = sorted(known_ids - set(seen))
    duplicates = sorted(rid for rid, n in seen.items() if n > 1)
    unknown_sorted = sorted(unknown)
    bad_ids = sorted(str(u) for u in grouping if not (isinstance(u, str) and UNIT_ID_RE.fullmatch(u)))

    if orphans or duplicates or unknown_sorted or bad_ids or not_lists or empty_units or non_string:
        parts = []
        if not_lists:
            parts.append(f"{len(not_lists)} unit(s) whose value is not a list of record_ids: {sorted(not_lists)}")
        if empty_units:
            parts.append(f"{len(empty_units)} empty unit(s) with no record_id: {sorted(empty_units)}")
        if non_string:
            parts.append(f"{len(non_string)} non-string record_id(s): {sorted(non_string)}")
        if orphans:
            parts.append(f"{len(orphans)} orphan record(s) in no unit: {orphans}")
        if duplicates:
            parts.append(f"{len(duplicates)} duplicate record(s) in more than one unit: {duplicates}")
        if unknown_sorted:
            parts.append(f"{len(unknown_sorted)} unknown record_id(s) referenced by grouping: {unknown_sorted}")
        if bad_ids:
            parts.append(f"{len(bad_ids)} unit_id(s) not matching [a-z0-9]+: {bad_ids}")
        raise CoverageError("; ".join(parts))


# ---------------------------------------------------------------------------
# bundle: Phase 3 -- one bundle file per unit, so Phase 4 agents read the
# bundle instead of re-parsing REPORT.md/REPORT/*.md.
#
# Only `confirmed` records need a REPORT/<family>.md lookup -- findings.json
# already carries full text for needs_validation/hardening entries
# (claimed_root_cause / blockers / text), per Phase 0.1's contract note.
# ---------------------------------------------------------------------------

_BLOCK_HEADING_RE = re.compile(r"(?m)^#{1,3}\s+(?:Vulnerability|Needs validation|Hardening)\s+\d+:.*$")
_SINK_HASH_FIELD_RE = re.compile(r"\*\*sink_hash\*\*:\s*`?([0-9a-f]{8}|nohash00)`?")


def _split_blocks(text: str) -> list[str]:
    positions = [m.start() for m in _BLOCK_HEADING_RE.finditer(text)]
    if not positions:
        return []
    positions.append(len(text))
    return [text[positions[i] : positions[i + 1]].strip("\n") for i in range(len(positions) - 1)]


def _find_block_by_hash(text: str, sink_hash: str, *, loc_hint: str = "") -> str | None:
    """Locate the `# Vulnerability N: ...` block whose `* **sink_hash**:`
    field matches. `nohash00` (the empty-snippet sentinel) can legitimately
    match several blocks -- `loc_hint` (the `` `file:line` `` substring from
    the block's own title line) disambiguates when there's more than one
    candidate."""
    candidates = []
    for b in _split_blocks(text):
        m = _SINK_HASH_FIELD_RE.search(b)
        if m and m.group(1) == sink_hash:
            candidates.append(b)
    if not candidates:
        return None
    if len(candidates) == 1 or not loc_hint:
        return candidates[0]
    for b in candidates:
        if loc_hint in b.splitlines()[0]:
            return b
    return candidates[0]


def _family_slug(family: str) -> str:
    """Mirrors `security-review/bin/dedupe/renderer.py:_family_slug` +
    `_group_by_family`'s `other:` stripping (both applied before the detail
    file is looked up by name)."""
    family = family or ""
    if family.startswith("other:"):
        family = family.split(":", 1)[1].strip()
    if not family:
        return "uncategorized"
    slug = re.sub(r"[^a-z0-9_]+", "_", family.lower()).strip("_")
    return slug or "uncategorized"


def _render_bucket_record(r: Record) -> str:
    """Render a needs_validation/hardening record straight from its
    findings.json fields -- no REPORT.md lookup needed (see module note)."""
    loc = f"{r.sink_file}:{r.sink_line}" if r.sink_file else "(no location)"
    lines = [f"### {r.verdict}: `{loc}` (sink_hash={r.sink_hash})", ""]
    lines.append(f"* **sink_kind**: {r.sink_kind or '—'}")
    lines.append(f"* **root_cause_family**: {r.root_cause_family or '—'}")
    lines.append(f"* **enclosing_symbol**: {r.enclosing_symbol or '—'}")
    if r.verdict == "needs_validation":
        lines.append(f"* **claimed_root_cause**: {r.claimed_root_cause or '(none given)'}")
        if r.blockers:
            lines.append(f"* **blockers**: {'; '.join(r.blockers)}")
    else:
        lines.append(f"* **text**: {r.text or '(none given)'}")
    if r.condition_keys:
        lines.append(f"* **condition_keys**: {', '.join(r.condition_keys)}")
    if r.flags:
        lines.append(f"* **flags**: {' '.join(r.flags)}")
    lines.append(f"* **matched_to**: {r.matched_to or '(standalone)'}")
    src = r.source_file + (f" ({r.slice_id})" if r.slice_id else "")
    lines.append(f"* **source**: {src}")
    if r.prior_resolution:
        lines.append(
            f"* **prior_resolution**: {r.prior_resolution.get('verdict')} "
            f"(source: {r.prior_resolution.get('source', '')})"
        )
    return "\n".join(lines)


def _manifest_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _render_manifest(unit_records: list[Record]) -> str:
    """One row per record of the unit -- including merge-group constituents
    whose body is collapsed into their primary's block, which would
    otherwise be invisible in the bundle."""
    lines = [
        "## Manifest",
        "",
        "| record_id | verdict | sink_hash | file:line | sink_kind | flags | matched_to |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in unit_records:
        loc = f"{r.sink_file}:{r.sink_line}" if r.sink_file else "(no location)"
        cells = [
            r.record_id,
            r.verdict,
            r.sink_hash,
            loc,
            r.sink_kind or "—",
            " ".join(r.flags) or "—",
            r.matched_to or "—",
        ]
        lines.append("| " + " | ".join(_manifest_cell(c) for c in cells) + " |")
    return "\n".join(lines)


def bundle(
    records: list[Record],
    grouping: dict,
    *,
    review_root: Path,
    out_dir: Path,
) -> None:
    """Write one bundle file per unit (`<out_dir>/<unit_id>.md`): a
    manifest of every record in the unit, then the full body text of each
    merge group with a `confirmed` record in the unit (fetched from
    `<review_root>/REPORT/<family>.md` -- or `REPORT/manual_review.md` for
    `review_bucket == "manual_review"` -- by `primary_sink_hash` plus the
    primary's `file:line`, once per group, not once per constituent) plus every needs_validation/
    hardening record's own fields. Every block is preceded by a
    `covers: <record_id>, ...` line naming the unit's records it stands for.

    Does NOT call `assert_full_coverage` itself -- callers should call it
    first (the CLI does)."""
    by_id = {r.record_id: r for r in records}
    report_dir = Path(review_root) / "REPORT"
    file_cache: dict[Path, str] = {}

    def _read(path: Path) -> str | None:
        if path not in file_cache:
            file_cache[path] = path.read_text(encoding="utf-8") if path.is_file() else None
        return file_cache[path]

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # One body block per merge group. `primary_sink_hash` alone does not
    # identify a group: two independent groups can share a hash (same
    # snippet, different file), so each `is_primary` record anchors its own
    # block, located by hash plus the primary's `file:line` (the REPORT block
    # title carries it). A constituent's candidate groups are every primary
    # with its `primary_sink_hash`, across all units -- narrowed to the one
    # at the constituent's own `file:line` when exactly one sits there. A
    # constituent still matching several groups cannot be pinned from
    # findings.json, so it is listed under every candidate's block.
    primaries_by_hash: dict[str, list[Record]] = {}
    for r in records:
        if r.verdict == "confirmed" and r.is_primary:
            primaries_by_hash.setdefault(r.sink_hash, []).append(r)

    def _candidate_primaries(r: Record) -> list[Record]:
        candidates = primaries_by_hash.get(r.primary_sink_hash or r.sink_hash, [])
        same_loc = [p for p in candidates if (p.sink_file, p.sink_line) == (r.sink_file, r.sink_line)]
        return same_loc if len(same_loc) == 1 else candidates

    for unit_id, record_ids in grouping.items():
        unit_records = [by_id[rid] for rid in record_ids if rid in by_id]

        anchors: dict[str, Record] = {}  # block key -> record whose location/family locate the body
        covers: dict[str, list[str]] = {}
        slots: list[str | Record] = []  # a block key, or a bucket record rendered on its own; unit order
        for r in unit_records:
            if r.verdict != "confirmed":
                slots.append(r)
                continue
            primary_hash = r.primary_sink_hash or r.sink_hash
            if r.is_primary:
                targets = [(f"primary:{r.record_id}", r)]
            elif _candidate_primaries(r):
                targets = [(f"primary:{p.record_id}", p) for p in _candidate_primaries(r)]
            else:
                # No primary in findings.json for this hash: locate the body
                # by the constituent's own hash lookup and location.
                targets = [(f"hash:{primary_hash}", r)]
            for key, anchor in targets:
                if key not in anchors:
                    anchors[key] = anchor
                    covers[key] = []
                    slots.append(key)
                covers[key].append(r.record_id)

        parts: list[str] = [_render_manifest(unit_records)]
        for slot in slots:
            if isinstance(slot, Record):
                parts.append(f"covers: {slot.record_id}\n\n{_render_bucket_record(slot)}")
                continue
            r = anchors[slot]
            primary_hash = r.primary_sink_hash or r.sink_hash
            cover_line = f"covers: {', '.join(covers[slot])}"
            filename = "manual_review.md" if r.review_bucket == "manual_review" else f"{_family_slug(r.root_cause_family)}.md"
            text = _read(report_dir / filename)
            loc_hint = f"`{r.sink_file}:{r.sink_line}`"
            block = _find_block_by_hash(text, primary_hash, loc_hint=loc_hint) if text is not None else None
            if block is None:
                block = (
                    f"[bundle: could not locate body for sink_hash={primary_hash} "
                    f"in REPORT/{filename} -- verify manually against {r.sink_file}:{r.sink_line}]"
                )
            parts.append(f"{cover_line}\n\n{block}")
        (out_dir / f"{unit_id}.md").write_text("\n\n---\n\n".join(parts) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# TICKETS_ROOT guard + PROJECT_ROOT resolution. Phase 0.3 calls the guard with
# --check-only before it writes `.work/` + `.gitignore`; Phase 1/3 re-run it
# for real. Nothing is written under TICKETS_ROOT until the guard passed AND
# PROJECT_ROOT resolved at least one sink_file.
# ---------------------------------------------------------------------------

PARSED_NAME = "parsed.json"
ARCHIVE_PREFIX = "prev-"
_FOUND_LISTING_CAP = 50


@dataclass(frozen=True)
class Verdict:
    kind: str  # "ok" | "resume" | "stale" | "foreign"
    found: tuple[str, ...] = ()  # TICKETS_ROOT-relative files that make it non-empty
    existing_parsed: dict | None = None
    symlinks: tuple[str, ...] = ()  # TICKETS_ROOT-relative symlinks (or "." for TICKETS_ROOT itself)


def _is_archive_dir(rel: Path) -> bool:
    return len(rel.parts) >= 2 and rel.parts[0] == ".work" and rel.parts[1].startswith(ARCHIVE_PREFIX)


def _content_files(tickets_root: Path) -> list[str]:
    """Files that make TICKETS_ROOT non-empty. Empty directories don't count
    (Phase 0.3 creates an empty `.work/` before Phase 1 runs), nor does the
    root `.gitignore` (also 0.3's), nor `.work/prev-*` (an archive from an
    earlier `--archive-previous` -- otherwise a Phase 1 that archived and then
    failed its PROJECT_ROOT check could never be re-run without archiving
    again). A symlink always counts, whatever its name -- see `_symlinks`."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(tickets_root):
        rel_dir = Path(dirpath).relative_to(tickets_root)
        linked_dirs = sorted(d for d in dirnames if (Path(dirpath) / d).is_symlink())
        found.extend((rel_dir / d).as_posix() for d in linked_dirs)
        dirnames[:] = sorted(d for d in dirnames if d not in linked_dirs and not _is_archive_dir(rel_dir / d))
        for name in sorted(filenames):
            rel = rel_dir / name
            if rel == Path(".gitignore") and not (Path(dirpath) / name).is_symlink():
                continue
            found.append(rel.as_posix())
    return found


def _symlinks(tickets_root: Path) -> list[str]:
    """Every symlink under TICKETS_ROOT, TICKETS_ROOT-relative (`.` when
    TICKETS_ROOT itself is one), archives included. `os.walk` never descends
    a linked directory, so a linked `.work` looks empty to `_content_files`
    while parsed.json writes, bundle writes and `archive_previous` would all
    follow it out of TICKETS_ROOT."""
    tickets_root = Path(tickets_root)
    if tickets_root.is_symlink():
        return ["."]
    if not tickets_root.is_dir():
        return []
    links: list[str] = []
    for dirpath, dirnames, filenames in os.walk(tickets_root):
        rel_dir = Path(dirpath).relative_to(tickets_root)
        for name in sorted(dirnames) + sorted(filenames):
            if (Path(dirpath) / name).is_symlink():
                links.append((rel_dir / name).as_posix())
    return sorted(links)


def _describe_symlinks(tickets_root: Path, links: list[str]) -> tuple[str, ...]:
    return tuple(
        f"{rel} -> {os.readlink(Path(tickets_root) / rel)} (symlink)" for rel in links
    )


def _read_parsed(tickets_root: Path) -> dict | None:
    path = tickets_root / ".work" / PARSED_NAME
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if not isinstance(payload.get("audit_root"), str) or not isinstance(payload.get("findings_json_sha256"), str):
        return None
    return payload


def check_tickets_root(tickets_root: Path, audit_root: Path, findings_sha: str) -> Verdict:
    """Classify TICKETS_ROOT before anything is written into it:

    - ok      -- missing, or empty (see `_content_files`);
    - resume  -- its parsed.json is for the same audit_root AND the same
                 findings.json bytes (a Phase 1/3 re-run, Phase 4.5);
    - stale   -- same audit_root, different findings.json (audit re-run);
    - foreign -- anything else non-empty (no/unreadable parsed.json, or one
                 for another audit_root): someone else's output. Also any
                 TICKETS_ROOT that is, or contains, a symlink -- decided before
                 parsed.json is read, since that read could follow the link.

    Pass the path unresolved: resolving it first hides a TICKETS_ROOT that is
    itself a symlink.
    """
    tickets_root = Path(tickets_root)
    links = _symlinks(tickets_root)
    if links:
        return Verdict("foreign", found=_describe_symlinks(tickets_root, links), symlinks=tuple(links))
    if not tickets_root.exists():
        return Verdict("ok")
    if not tickets_root.is_dir():
        return Verdict("foreign", found=(tickets_root.name,))
    found = tuple(_content_files(tickets_root))
    if not found:
        return Verdict("ok")
    parsed = _read_parsed(tickets_root)
    if parsed is None or parsed["audit_root"] != str(Path(audit_root).resolve()):
        return Verdict("foreign", found=found, existing_parsed=parsed)
    if parsed["findings_json_sha256"] != findings_sha:
        return Verdict("stale", found=found, existing_parsed=parsed)
    return Verdict("resume", found=found, existing_parsed=parsed)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def archive_previous(tickets_root: Path) -> Path | None:
    """Move everything in TICKETS_ROOT except the root `.gitignore` and
    existing `.work/prev-*` archives into `.work/prev-<N>/` (N = next free
    number), keeping relative paths. Returns the archive dir, or None when
    there was nothing to move.

    Raises `TicketsRootError` without moving anything when TICKETS_ROOT is,
    or contains, a symlink."""
    tickets_root = Path(tickets_root)
    links = _symlinks(tickets_root)
    if links:
        raise TicketsRootError(
            f"refusing to archive {tickets_root}: it holds symlink(s) that could move files from "
            f"outside it: {', '.join(_describe_symlinks(tickets_root, links))}"
        )
    if not _content_files(tickets_root):
        return None
    work_dir = tickets_root / ".work"
    taken = [0]
    if work_dir.is_dir():
        for child in work_dir.iterdir():
            suffix = child.name[len(ARCHIVE_PREFIX):]
            if child.name.startswith(ARCHIVE_PREFIX) and suffix.isdigit():
                taken.append(int(suffix))
    dest = work_dir / f"{ARCHIVE_PREFIX}{max(taken) + 1}"

    moves: list[tuple[Path, Path]] = []
    for child in sorted(tickets_root.iterdir()):
        if child.name == ".gitignore":
            continue
        if child.name == ".work" and child.is_dir():
            for sub in sorted(child.iterdir()):
                if not sub.name.startswith(ARCHIVE_PREFIX):
                    moves.append((sub, dest / ".work" / sub.name))
            continue
        moves.append((child, dest / child.name))

    for src, target in moves:
        target.parent.mkdir(parents=True, exist_ok=True)
        src.rename(target)
    return dest


_GIT_TIMEOUT_SECONDS = 30


def git_tracked_files(tickets_root: Path) -> list[str] | None:
    """TICKETS_ROOT-relative files git tracks under TICKETS_ROOT that
    `archive_previous` would move (the root `.gitignore` and `.work/prev-*`
    stay put, so they don't count). None when the check can't run: no `git`
    binary, or TICKETS_ROOT is not inside a git work tree -- then there is
    nothing tracked to break.

    Raises `TicketsRootError` when git does not answer in time: an
    unverified TICKETS_ROOT is not archived."""
    try:
        result = subprocess.run(
            ["git", "-C", str(tickets_root), "ls-files", "-z"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired as exc:
        raise TicketsRootError(
            f"refusing to archive {tickets_root}: `git ls-files` did not answer within "
            f"{_GIT_TIMEOUT_SECONDS}s, so it is unknown whether it holds tracked files"
        ) from exc
    if result.returncode != 0:
        return None
    tracked = []
    for rel in sorted(name for name in result.stdout.split("\0") if name):
        rel_path = Path(rel)
        if rel_path == Path(".gitignore") or _is_archive_dir(rel_path):
            continue
        tracked.append(rel)
    return tracked


def resolve_project_root(arg: Path | None, verdict: str, existing_parsed: dict | None) -> Path:
    """A resumed run keeps the PROJECT_ROOT persisted in its parsed.json and
    rejects an explicit one that contradicts it. Otherwise: explicit
    argument, else cwd. A resumed parsed.json written before project_root was
    persisted falls through to the non-resume rule."""
    explicit = Path(arg).resolve() if arg is not None else None
    saved = (existing_parsed or {}).get("project_root") if verdict == "resume" else None
    if isinstance(saved, str) and saved:
        saved_path = Path(saved).resolve()
        if explicit is not None and explicit != saved_path:
            raise ProjectRootError(
                f"--project-root {explicit} contradicts the PROJECT_ROOT {saved_path} this run was "
                f"started with (persisted in parsed.json). Drop the flag to resume, or start over "
                f"with --archive-previous."
            )
        return saved_path
    return explicit if explicit is not None else Path.cwd().resolve()


def check_project_root(records: list[Record], project_root: Path) -> tuple[int, int]:
    """(resolved, total) over the unique non-empty `sink_file`s of every
    record, all verdicts. `sink_file` is project_root-relative by the audit's
    contract; an absolute one counts only if it lies under project_root."""
    project_root = Path(project_root)
    sink_files = {r.sink_file for r in records if r.sink_file}
    resolved = 0
    for sink_file in sink_files:
        path = Path(sink_file)
        if path.is_absolute():
            ok = _is_within(path, project_root) and path.is_file()
        else:
            ok = (project_root / path).is_file()
        resolved += ok
    return resolved, len(sink_files)


def _format_found(found: tuple[str, ...]) -> str:
    shown = list(found[:_FOUND_LISTING_CAP])
    more = len(found) - len(shown)
    return ", ".join(shown) + (f", ... and {more} more" if more > 0 else "")


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Parse <AUDIT_ROOT>/findings.json into normalized triage records."
    )
    parser.add_argument("audit_root", type=Path, help="fr-security-review's <review_root> (contains findings.json).")
    parser.add_argument(
        "--tickets-root",
        type=Path,
        required=True,
        help="This triage run's <TICKETS_ROOT> -- .work/parsed.json is written under it.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="Root of the audited codebase (sink_files are relative to it). Defaults to cwd; "
        "a resumed run reuses the one persisted in parsed.json and rejects a different one.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only run the TICKETS_ROOT guard and print its verdict (ok|resume|stale|foreign); write nothing.",
    )
    parser.add_argument(
        "--archive-previous",
        action="store_true",
        help="Move TICKETS_ROOT's previous contents (all but .gitignore and .work/prev-*) into "
        ".work/prev-<N>/ and start fresh. Only with the user's explicit consent.",
    )
    parser.add_argument(
        "--grouping",
        type=Path,
        default=None,
        help="Phase 2 grouping.json ({unit_id: [record_id, ...]}). When given, also "
        "validates full coverage and writes one bundle file per unit under "
        "<TICKETS_ROOT>/.work/bundles/.",
    )
    args = parser.parse_args(argv)

    if args.check_only and args.archive_previous:
        print("Error: --check-only never writes; pass --archive-previous on the Phase 1 run instead.", file=sys.stderr)
        return 2

    audit_root = args.audit_root.resolve()
    # The guard sees the path unresolved: resolve() would follow a TICKETS_ROOT
    # that is itself a symlink and hide it. Past the guard (and its refusals)
    # the last component is known not to be a link, so resolving is safe.
    tickets_root_arg = Path(os.path.abspath(args.tickets_root))
    tickets_root = tickets_root_arg.resolve()

    try:
        records = load(audit_root)
        sha256 = findings_json_sha256(audit_root)
    except FindingsContractError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    # Validated before anything is archived or written: a malformed grouping
    # must leave Phase 1's parsed.json as it was.
    grouping: dict | None = None
    if args.grouping is not None and not args.check_only:
        try:
            grouping = json.loads(args.grouping.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"Error: cannot read grouping file {args.grouping}: {exc}", file=sys.stderr)
            return 2
        if not isinstance(grouping, dict):
            print(f"Error: {args.grouping}: root must be a JSON object of unit_id -> [record_id, ...]", file=sys.stderr)
            return 2
        try:
            assert_full_coverage(records, grouping)
        except CoverageError as exc:
            print(f"Error: coverage check failed: {exc}", file=sys.stderr)
            return 2

    verdict = check_tickets_root(tickets_root_arg, audit_root, sha256)
    blocked = verdict.kind in ("stale", "foreign")

    if args.check_only:
        print(json.dumps({"verdict": verdict.kind, "tickets_root": str(tickets_root), "found": list(verdict.found)}, indent=2))
        if blocked:
            print(f"Error: {tickets_root} is {verdict.kind}: {_format_found(verdict.found)}", file=sys.stderr)
        return 2 if blocked else 0

    archived: Path | None = None
    if args.archive_previous:
        candidate_root = args.project_root.resolve() if args.project_root is not None else Path.cwd().resolve()
        for label, path in (("AUDIT_ROOT", audit_root), ("PROJECT_ROOT", candidate_root)):
            if _is_within(path, tickets_root):
                print(
                    f"Error: refusing --archive-previous: {label} {path} lies inside TICKETS_ROOT "
                    f"{tickets_root} and would be moved with it.",
                    file=sys.stderr,
                )
                return 2
        if verdict.symlinks:
            print(
                f"Error: refusing --archive-previous: {tickets_root_arg} is or holds a symlink, and moving "
                f"it could pull in files from outside: {_format_found(verdict.found)}. Remove the link(s) "
                f"or pick another --tickets-root.",
                file=sys.stderr,
            )
            return 2
        try:
            tracked = git_tracked_files(tickets_root)
        except TicketsRootError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        if tracked:
            print(
                f"Error: refusing --archive-previous: {tickets_root} holds file(s) tracked by git, which "
                f"looks like a source tree, not triage output: {_format_found(tuple(tracked))}. "
                f"Pick another --tickets-root.",
                file=sys.stderr,
            )
            return 2
        try:
            archived = archive_previous(tickets_root)
        except TicketsRootError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        verdict = Verdict("ok")
    elif blocked:
        print(
            f"Error: {tickets_root} is {verdict.kind} "
            + (
                "(its parsed.json is for the same audit_root but a different findings.json -- the audit was re-run)"
                if verdict.kind == "stale"
                else "(not empty, and not a resumable run of this audit)"
            )
            + f"; found: {_format_found(verdict.found)}. Pick another --tickets-root, or re-run with "
            f"--archive-previous once the user agreed to move these into .work/{ARCHIVE_PREFIX}<N>/.",
            file=sys.stderr,
        )
        return 2

    try:
        project_root = resolve_project_root(args.project_root, verdict.kind, verdict.existing_parsed)
    except ProjectRootError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    resolved, total = check_project_root(records, project_root)
    if total > 0 and resolved == 0:
        print(
            f"Error: none of the audit's {total} sink_file(s) exist under PROJECT_ROOT {project_root}. "
            f"Re-run with the right --project-root; nothing was written.",
            file=sys.stderr,
        )
        return 2

    work_dir = tickets_root / ".work"
    work_dir.mkdir(parents=True, exist_ok=True)
    parsed_payload = {
        "schema_version": 1,
        "audit_root": str(audit_root),
        "findings_json_sha256": sha256,
        "project_root": str(project_root),
        "project_root_resolved": [resolved, total],
        "records": [r.to_dict() for r in records],
    }
    parsed_path = work_dir / PARSED_NAME
    parsed_path.write_text(json.dumps(parsed_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary = {
        "counts": summarize(records),
        "findings_json_sha256": sha256,
        "tickets_root_verdict": verdict.kind,
        "project_root": str(project_root),
        "project_root_resolved": [resolved, total],
        "parsed": str(parsed_path),
    }
    if resolved < total:
        summary["project_root_warning"] = (
            f"only {resolved} of {total} sink_file(s) exist under PROJECT_ROOT -- "
            f"the rest will need manual location during verification"
        )
    if archived is not None:
        summary["archived_previous_to"] = str(archived)
    print(json.dumps(summary, indent=2))

    if grouping is not None:
        bundles_dir = work_dir / "bundles"
        bundle(records, grouping, review_root=audit_root, out_dir=bundles_dir)
        print(f"Wrote {len(grouping)} bundle file(s) under {bundles_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
