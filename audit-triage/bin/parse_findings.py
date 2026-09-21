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

    Phase 1: parse_findings.py <AUDIT_ROOT> --tickets-root <TICKETS_ROOT>
        -> loads findings.json, persists <TICKETS_ROOT>/.work/parsed.json
           (records + findings_json_sha256), prints counts to stdout.

    Phase 2: the orchestrator (an LLM, not a script) does the fix-pattern
        grouping itself and writes <TICKETS_ROOT>/.work/grouping.json as
        {"<unit_id>": ["<record_id>", ...], ...}.

    Phase 3: parse_findings.py <AUDIT_ROOT> --tickets-root <TICKETS_ROOT> \\
                 --grouping <TICKETS_ROOT>/.work/grouping.json
        -> re-parses (idempotent), validates full coverage (Principle 3:
           zero orphans, zero duplicates), writes one bundle file per unit
           under <TICKETS_ROOT>/.work/bundles/<unit_id>.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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


class FindingsContractError(Exception):
    """Raised for a missing / unparseable / schema-mismatched findings.json.

    Callers must abort loudly -- never fall back to parsing REPORT.md /
    REPORT/*.md as structured data (Phase 0.1's explicit prohibition)."""


class CoverageError(Exception):
    """Raised by `assert_full_coverage` -- lists every orphan, duplicate and
    unknown record_id it found in one message, not just the first (same
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
    record_id in `grouping` that doesn't exist in `records`).

    Raises `CoverageError` enumerating every violation found, not just the
    first."""
    known_ids = {r.record_id for r in records}
    seen: dict[str, int] = {}
    unknown: set[str] = set()
    for unit_id, record_ids in grouping.items():
        for rid in record_ids:
            if rid not in known_ids:
                unknown.add(rid)
                continue
            seen[rid] = seen.get(rid, 0) + 1

    orphans = sorted(known_ids - set(seen))
    duplicates = sorted(rid for rid, n in seen.items() if n > 1)
    unknown_sorted = sorted(unknown)

    if orphans or duplicates or unknown_sorted:
        parts = []
        if orphans:
            parts.append(f"{len(orphans)} orphan record(s) in no unit: {orphans}")
        if duplicates:
            parts.append(f"{len(duplicates)} duplicate record(s) in more than one unit: {duplicates}")
        if unknown_sorted:
            parts.append(f"{len(unknown_sorted)} unknown record_id(s) referenced by grouping: {unknown_sorted}")
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


def bundle(
    records: list[Record],
    grouping: dict,
    *,
    review_root: Path,
    out_dir: Path,
) -> None:
    """Write one bundle file per unit (`<out_dir>/<unit_id>.md`): the full
    body text of each constituent `confirmed` finding (fetched from
    `<review_root>/REPORT/<family>.md` -- or `REPORT/manual_review.md` for
    `review_bucket == "manual_review"` -- by `primary_sink_hash`, once per
    merge group, not once per constituent) plus every needs_validation/
    hardening record's own fields.

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

    for unit_id, record_ids in grouping.items():
        parts: list[str] = []
        seen_primary: set[str] = set()
        for rid in record_ids:
            r = by_id.get(rid)
            if r is None:
                continue
            if r.verdict == "confirmed":
                primary_hash = r.primary_sink_hash or r.sink_hash
                if primary_hash in seen_primary:
                    continue
                seen_primary.add(primary_hash)
                filename = "manual_review.md" if r.review_bucket == "manual_review" else f"{_family_slug(r.root_cause_family)}.md"
                text = _read(report_dir / filename)
                loc_hint = f"`{r.sink_file}:{r.sink_line}`"
                block = _find_block_by_hash(text, primary_hash, loc_hint=loc_hint) if text is not None else None
                if block is None:
                    parts.append(
                        f"[bundle: could not locate body for sink_hash={primary_hash} "
                        f"in REPORT/{filename} -- verify manually against {r.sink_file}:{r.sink_line}]"
                    )
                else:
                    parts.append(block)
            else:
                parts.append(_render_bucket_record(r))
        (out_dir / f"{unit_id}.md").write_text("\n\n---\n\n".join(parts) + "\n", encoding="utf-8")


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
        "--grouping",
        type=Path,
        default=None,
        help="Phase 2 grouping.json ({unit_id: [record_id, ...]}). When given, also "
        "validates full coverage and writes one bundle file per unit under "
        "<TICKETS_ROOT>/.work/bundles/.",
    )
    args = parser.parse_args(argv)

    audit_root = args.audit_root.resolve()
    tickets_root = args.tickets_root.resolve()

    try:
        records = load(audit_root)
        sha256 = findings_json_sha256(audit_root)
    except FindingsContractError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    work_dir = tickets_root / ".work"
    work_dir.mkdir(parents=True, exist_ok=True)
    parsed_payload = {
        "schema_version": 1,
        "audit_root": str(audit_root),
        "findings_json_sha256": sha256,
        "records": [r.to_dict() for r in records],
    }
    parsed_path = work_dir / "parsed.json"
    parsed_path.write_text(json.dumps(parsed_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "counts": summarize(records),
                "findings_json_sha256": sha256,
                "parsed": str(parsed_path),
            },
            indent=2,
        )
    )

    if args.grouping is not None:
        try:
            grouping = json.loads(args.grouping.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
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
        bundles_dir = work_dir / "bundles"
        bundle(records, grouping, review_root=audit_root, out_dir=bundles_dir)
        print(f"Wrote {len(grouping)} bundle file(s) under {bundles_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
