"""Cross-run findings state: `<review_root>/.findings_state.json`.

After every dedupe pipeline writes its REPORT.md, the same set of findings is
persisted as a json snapshot. The next run loads that snapshot and computes a
diff:

    new       — sink_hash present in current run, absent in previous run
    recurring — sink_hash present in both
    closed    — sink_hash present in previous run, absent in current run

The diff lands as a `## Diff vs previous run` block in the executive summary.
No machinery beyond a simple `set` comparison — it is a UX hint, not auth.

Stage 2 / P2.5 adds a second, independent piece of cross-run memory:
`resolutions` — a `sink_hash -> Resolution` map recording external triage-tool
verdicts (`--verdicts-in`) so a rejected false positive is not re-discovered
and re-argued on every run. Design rules:

  - A resolution ANNOTATES a finding, it never removes it from the report
    (recall-first). `active_rejections` + the renderer only ever ADD a note.
  - `evidence_hash` is a hash of the *content* at `refute_file:refute_line`
    (the same normalize-then-sha256 the pipeline already uses for
    `sink_hash`, via `models._sink_hash_from_snippet`) — not of the path. A
    resolution whose cited evidence line has since changed (protection
    removed, code moved) silently stops rendering; this is the mechanism
    that keeps a regression from hiding behind a stale "already reviewed"
    mark. See `compute_evidence_hash`.
  - `run_seq` is an audit trail *inside* this file only. It is never read by
    the renderer and never reaches REPORT.md / findings.json — leaking it
    would couple external consumers to run-count, breaking the idempotency
    contract those files already guarantee (CLAUDE.md "Idempotency in recon
    and dedup").
  - Free-text rationale is deliberately NOT persisted here — state.py
    only carries the structured fields needed to reproduce/validate the
    mark: verdict, evidence location, and provenance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import CONDITION_KEYS, MergedFinding, _sink_hash_from_snippet


STATE_FILENAME = ".findings_state.json"
STATE_SCHEMA_VERSION = 2

# Schema versions this build can still READ. Schema 1 (pre-Stage-2) has no
# `verdict`/`condition_keys` on findings and no `resolutions` key at all —
# both are backfilled with defaults by the parsing helpers below, so a
# schema-1 file migrates in place instead of being discarded (CLAUDE.md:
# "миграция, не сброс" is the P2.5 plan's explicit correction of the old
# exact-version-match behaviour, which silently dropped the whole file and
# showed every finding as New on the first post-upgrade run).
#
# `baseline` / `run_id` were added WITHOUT moving the version: they are purely
# additive, and the reader that needs them detects their absence by key, not by
# version. Moving it would make a build that predates them reject the whole
# file — and `resolutions`, the one accumulated, non-idempotent part of this
# state, would be silently reset on the first run after any rollback.
_READABLE_SCHEMA_VERSIONS = (1, 2)

_RESOLUTION_VERDICTS = ("rejected", "reaffirmed")

_NO_HASH = _sink_hash_from_snippet("")


# Evidence-content hash: the cross-run invalidation key for a remembered
# rejection. A hash of the CONTENT at file:line, not of the location — a
# location-only key never changes when the cited protection is removed, so it
# could not catch the regression it exists to catch. Reuses the
# normalize-then-sha256 that derives `sink_hash`.
#
# The window is the single cited line: dropping a mark too eagerly only shows
# an already-reviewed finding again, while keeping one too eagerly hides a
# regression, so the narrow window is the conservative choice.


def compute_evidence_hash(refute_file: str, refute_line: int, project_root: Path) -> str:
    """Hash of the normalized single line of code at
    `project_root/refute_file:refute_line`.

    Returns the shared "no usable content" sentinel (`nohash00`) when the file
    is unreadable or the line is out of range.
    """
    target = project_root / refute_file
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return _sink_hash_from_snippet("")
    idx = refute_line - 1
    if idx < 0 or idx >= len(lines):
        return _sink_hash_from_snippet("")
    return _sink_hash_from_snippet(lines[idx])



@dataclass(frozen=True)
class FindingSnapshot:
    sink_hash: str
    sink_file: str
    sink_line: int
    sink_kind: str
    severity: str
    title: str
    # Stage 2 / P2.5 additions — defaulted so existing positional
    # construction (6 args, see test_findings_state.py / test_renderer.py)
    # keeps working unchanged. `verdict` is always "confirmed" today:
    # `snapshots_from` only ever sees `merged`/`manual` (the confirmed
    # bucket); the field exists so a schema-1 snapshot round-trips through
    # the same shape rather than needing a second type.
    verdict: str = "confirmed"
    condition_keys: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "sink_hash": self.sink_hash,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_kind": self.sink_kind,
            "severity": self.severity,
            "title": self.title,
            "verdict": self.verdict,
            "condition_keys": list(self.condition_keys),
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
                condition_keys=tuple(p.condition_keys),
            ))
    return out


# ---------------------------------------------------------------------------
# Resolutions: cross-run external-triage verdicts.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Resolution:
    """One remembered verdict on a `sink_hash`, keyed by that hash in the
    `resolutions` map (the hash is the dict key, not duplicated as a field —
    see the module docstring).

    `condition_keys` is a tuple (not list) so the dataclass stays hashable
    like the rest of this module's frozen types.
    """

    verdict: str                              # "rejected" | "reaffirmed"
    condition_keys: tuple[str, ...] = ()
    evidence_hash: str = ""                   # "" = no code evidence to re-check (e.g. external triage with no citation)
    refute_file: str = ""
    refute_line: int = 0
    source: str = ""                          # free-text tool identifier, NOT an enum — see module docstring
    run_seq: int = 0

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "condition_keys": list(self.condition_keys),
            "evidence_hash": self.evidence_hash,
            "refute_file": self.refute_file,
            "refute_line": self.refute_line,
            "source": self.source,
            "run_seq": self.run_seq,
        }


def active_rejections(resolutions: dict[str, Resolution], project_root: Path) -> dict[str, Resolution]:
    """Filter a resolutions map down to the ones that should still annotate a
    finding on THIS run: verdict is `rejected`, and — for any resolution that
    cites code evidence (`refute_file` set) — the content at that location
    still hashes to what it did when the resolution was recorded.

    A `reaffirmed` resolution (e.g. a human later overrode an earlier
    `rejected` via `--verdicts-in`) is excluded here by construction — there is nothing to
    render for it; it exists purely to cancel a prior `rejected` entry for
    the same sink_hash (the merge in `save_state` keeps only the latest
    verdict per hash).

    A resolution with no `refute_file` (external triage with no code
    citation) has no evidence to go stale, so it is never auto-invalidated —
    it stays active until superseded by a newer resolution for the same hash.
    """
    out: dict[str, Resolution] = {}
    for sink_hash, res in resolutions.items():
        if res.verdict != "rejected":
            continue
        if res.refute_file:
            current = compute_evidence_hash(res.refute_file, res.refute_line, project_root)
            if current != res.evidence_hash:
                continue
        out[sink_hash] = res
    return out


def _parse_resolutions(payload: dict) -> dict[str, Resolution]:
    """Parse the `resolutions` block of a state payload. Lenient (skip
    malformed entries silently) — this is OUR OWN previously-written file,
    not untrusted external input; `load_verdicts_in` below is the
    fail-closed path for external data."""
    raw = payload.get("resolutions")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Resolution] = {}
    for sink_hash, entry in raw.items():
        if not isinstance(sink_hash, str) or not isinstance(entry, dict):
            continue
        verdict = entry.get("verdict")
        if verdict not in _RESOLUTION_VERDICTS:
            continue
        try:
            condition_keys = tuple(
                str(k) for k in (entry.get("condition_keys") or []) if isinstance(k, str)
            )
            out[sink_hash] = Resolution(
                verdict=verdict,
                condition_keys=condition_keys,
                evidence_hash=str(entry.get("evidence_hash", "")),
                refute_file=str(entry.get("refute_file", "")),
                refute_line=int(entry.get("refute_line", 0)),
                source=str(entry.get("source", "")),
                run_seq=int(entry.get("run_seq", 0)),
            )
        except (TypeError, ValueError):
            continue
    return out


def _read_payload(review_root: Path) -> Optional[dict]:
    """Read and version-gate the raw state payload. `None` on any absence /
    corruption / unreadable schema_version — callers treat that uniformly as
    "no usable previous state"."""
    target = review_root / STATE_FILENAME
    if not target.is_file():
        return None
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("schema_version") not in _READABLE_SCHEMA_VERSIONS:
        return None
    return payload


def save_state(
    snapshots: list[FindingSnapshot],
    review_root: Path,
    resolutions: dict[str, Resolution] | None = None,
    baseline: Optional[list[FindingSnapshot]] = None,
    run_id: str = "",
) -> Path:
    """Atomically write `.findings_state.json` under `review_root`. Returns the path.

    `findings` is a full overwrite each run (same idempotency convention as
    the rest of the pipeline — CLAUDE.md "Idempotency in recon and dedup").
    `resolutions` is the deliberate exception: a **read-modify-write merge**,
    keyed by sink_hash, `resolutions=None`/`{}` leaves the persisted history
    untouched. A hash present in `resolutions` overwrites whatever this file
    already had for it (latest verdict per hash wins) and is stamped with a
    fresh `run_seq` = 1 + the highest `run_seq` already on disk; hashes not
    mentioned in this call keep their existing `run_seq` unchanged, so
    `run_seq` only advances on runs that actually add/update a verdict.

    `baseline` is what THIS write compared against, and `run_id` identifies the
    inputs it was computed from — persisted so a later pass over the same
    inputs (imported verdicts, a plain re-render) diffs against the
    real previous run instead of against the snapshot its own first pass just
    wrote. `None` baseline is recorded as `null`, meaning "there was no
    previous run", which is distinct from the key being absent (a file written
    before these two keys existed).
    """
    review_root.mkdir(parents=True, exist_ok=True)
    target = review_root / STATE_FILENAME
    existing_payload = _read_payload(review_root)
    existing_resolutions = _parse_resolutions(existing_payload) if existing_payload else {}

    merged_resolutions = dict(existing_resolutions)
    if resolutions:
        next_seq = max((r.run_seq for r in existing_resolutions.values()), default=0) + 1
        for sink_hash, res in resolutions.items():
            merged_resolutions[sink_hash] = Resolution(
                verdict=res.verdict,
                condition_keys=tuple(res.condition_keys),
                evidence_hash=res.evidence_hash,
                refute_file=res.refute_file,
                refute_line=res.refute_line,
                source=res.source,
                run_seq=next_seq,
            )

    payload = {
        "schema_version": STATE_SCHEMA_VERSION,
        "findings": [s.to_dict() for s in snapshots],
        "baseline": None if baseline is None else [s.to_dict() for s in baseline],
        "run_id": run_id,
        "resolutions": {h: r.to_dict() for h, r in sorted(merged_resolutions.items())},
    }
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(target)
    return target


def _snapshots_from_payload(raw) -> Optional[list[FindingSnapshot]]:
    if not isinstance(raw, list):
        return None
    out: list[FindingSnapshot] = []
    for f in raw:
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
                verdict=str(f.get("verdict", "confirmed")),
                condition_keys=tuple(
                    str(k) for k in (f.get("condition_keys") or []) if isinstance(k, str)
                ),
            ))
        except (TypeError, ValueError):
            continue
    return out


def load_state(review_root: Path) -> Optional[list[FindingSnapshot]]:
    """Return previous-run snapshots, or None if absent / unreadable / on an
    unrecognized schema. Accepts schema 1 (migrated: `verdict="confirmed"`,
    `condition_keys=()`), schema 2 and schema 3."""
    payload = _read_payload(review_root)
    if payload is None:
        return None
    return _snapshots_from_payload(payload.get("findings"))


def compute_run_id(input_paths: list[Path]) -> str:
    """Identify a dedupe run by the wave files it reads — names plus content.

    Two invocations over the same wave files are the same run: an imported-verdicts
    pass, a plain re-render. A later audit writes different
    wave content and so gets a different id. Unreadable files are folded in by
    name alone rather than skipped, so a file that disappears still changes the
    id. Empty input → "", which never matches a recorded id.
    """
    if not input_paths:
        return ""
    h = hashlib.sha256()
    for path in sorted(input_paths, key=lambda p: p.as_posix()):
        h.update(path.name.encode("utf-8", "replace"))
        h.update(b"\0")
        try:
            h.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
        except OSError:
            h.update(b"unreadable")
        h.update(b"\0")
    return h.hexdigest()[:16]


def load_continuation_baseline(
    review_root: Path, run_id: str
) -> tuple[bool, Optional[list[FindingSnapshot]]]:
    """Return `(is_continuation, baseline)` for a dedupe pass over `run_id`.

    A pass continues the run that wrote the state file when the two ids match;
    it then reuses that pass's baseline rather than diffing against the
    snapshot that pass just wrote. Anything else — no state file, a file
    written before `run_id` existed, a different id, a baseline that is present
    but not a list — is not a continuation, and the caller falls back to the
    stored findings. A recorded baseline of `None` is a real answer: the run
    being continued was itself the first one.
    """
    payload = _read_payload(review_root)
    if payload is None or not run_id:
        return False, None
    if payload.get("run_id") != run_id:
        return False, None
    if "baseline" not in payload:
        return False, None
    raw = payload.get("baseline")
    if raw is None:
        return True, None
    snapshots = _snapshots_from_payload(raw)
    if snapshots is None:
        # Present but malformed. Treating it as "no findings last run" would
        # silently call every finding New; fall back to the stored snapshot.
        return False, None
    return True, snapshots


def load_resolutions(review_root: Path) -> dict[str, Resolution]:
    """Return the persisted `resolutions` map (`{}` if absent / no previous
    state / schema-1 file, which predates resolutions entirely)."""
    payload = _read_payload(review_root)
    if payload is None:
        return {}
    return _parse_resolutions(payload)


# ---------------------------------------------------------------------------
# `--verdicts-in`: fail-closed import of externally-produced verdicts (the
# future ticket-triage plugin's feedback channel into the audit pipeline).
#
# Unlike `_parse_resolutions` above (our own previously-written file), this
# is untrusted external input, so every violation refuses the WHOLE import —
# never a partial apply (see module docstring / the plan's
# "любое поле вне схемы → отказ импорта целиком").
# ---------------------------------------------------------------------------


class VerdictsInError(Exception):
    """Raised for any `--verdicts-in` schema/content violation. The caller
    must abort the run before any REPORT.md / findings.json / state write —
    see `dedupe_findings.py`."""


_VERDICTS_IN_SCHEMA_VERSION = 1
_VERDICTS_IN_TOP_KEYS = frozenset({"schema_version", "findings_json_sha256", "verdicts"})
_VERDICTS_IN_REQUIRED_ENTRY_KEYS = frozenset({"sink_hash", "verdict", "source"})
_VERDICTS_IN_OPTIONAL_ENTRY_KEYS = frozenset({"condition_keys", "refute_file", "refute_line"})
_VERDICTS_IN_ENTRY_KEYS = _VERDICTS_IN_REQUIRED_ENTRY_KEYS | _VERDICTS_IN_OPTIONAL_ENTRY_KEYS


def _is_unsafe_evidence_path(rel: str) -> bool:
    if rel.startswith(("/", "\\")) or (len(rel) > 1 and rel[1] == ":"):
        return True
    return ".." in rel.replace("\\", "/").split("/")


def load_verdicts_in(
    path: Path,
    *,
    valid_sink_hashes: set[str],
    findings_json_sha256: str,
    project_root: Path,
) -> dict[str, Resolution]:
    """Fail-closed parse of a `--verdicts-in` file.

    `findings_json_sha256` must be the hash of the `findings.json` the
    verdicts were produced against (the caller hashes the PRE-EXISTING
    on-disk file before this run overwrites it — see `dedupe_findings.py`).
    `valid_sink_hashes` is the sink_hash universe of that same reference
    file. `sink_hash`/`verdict`/`source` are required per record;
    `condition_keys` is optional (validated against the closed
    `models.CONDITION_KEYS` enum); `refute_file`/`refute_line` are optional
    but must be given together — when given, `evidence_hash` is computed
    immediately (current file content) so the mark can later be
    auto-invalidated by `active_rejections` when the cited line changes.

    Raises `VerdictsInError` on any schema violation, unknown field, unknown
    or sentinel sink_hash, duplicate sink_hash, a stale `findings_json_sha256`,
    or cited evidence that is an absolute / `..` path or cannot be located.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerdictsInError(f"{path}: cannot read/parse: {exc}") from exc
    if not isinstance(raw, dict):
        raise VerdictsInError(f"{path}: root must be a JSON object")

    extra_top = sorted(set(raw) - _VERDICTS_IN_TOP_KEYS)
    if extra_top:
        raise VerdictsInError(f"{path}: unknown top-level field(s): {extra_top}")
    if raw.get("schema_version") != _VERDICTS_IN_SCHEMA_VERSION:
        raise VerdictsInError(
            f"{path}: unsupported schema_version {raw.get('schema_version')!r} "
            f"(expected {_VERDICTS_IN_SCHEMA_VERSION})"
        )
    if raw.get("findings_json_sha256") != findings_json_sha256:
        raise VerdictsInError(
            f"{path}: findings_json_sha256 does not match the current "
            f"findings.json on disk -- stale verdicts file, refusing import"
        )
    verdicts = raw.get("verdicts")
    if not isinstance(verdicts, list):
        raise VerdictsInError(f"{path}: 'verdicts' must be a list")

    parsed: list[tuple[str, Resolution]] = []
    for i, entry in enumerate(verdicts):
        if not isinstance(entry, dict):
            raise VerdictsInError(f"{path}: verdicts[{i}] is not an object")
        extra = sorted(set(entry) - _VERDICTS_IN_ENTRY_KEYS)
        if extra:
            raise VerdictsInError(f"{path}: verdicts[{i}] has unknown field(s): {extra}")
        missing = sorted(_VERDICTS_IN_REQUIRED_ENTRY_KEYS - set(entry))
        if missing:
            raise VerdictsInError(f"{path}: verdicts[{i}] missing required field(s): {missing}")

        sink_hash = entry["sink_hash"]
        verdict = entry["verdict"]
        source = entry["source"]
        condition_keys = entry.get("condition_keys", [])
        has_evidence = "refute_file" in entry or "refute_line" in entry

        if not isinstance(sink_hash, str) or not sink_hash:
            raise VerdictsInError(f"{path}: verdicts[{i}].sink_hash missing/invalid")
        if sink_hash == _NO_HASH:
            # Collision key shared by every finding without a usable snippet:
            # a verdict on it would annotate all of them.
            raise VerdictsInError(
                f"{path}: verdicts[{i}].sink_hash is the {_NO_HASH!r} sentinel, not a real finding identity"
            )
        if verdict not in _RESOLUTION_VERDICTS:
            raise VerdictsInError(
                f"{path}: verdicts[{i}].verdict must be one of {_RESOLUTION_VERDICTS}, got {verdict!r}"
            )
        if not isinstance(source, str) or not source:
            raise VerdictsInError(f"{path}: verdicts[{i}].source missing/invalid (free-text tool identifier)")
        if not isinstance(condition_keys, list) or not all(isinstance(k, str) for k in condition_keys):
            raise VerdictsInError(f"{path}: verdicts[{i}].condition_keys must be a list of strings")
        unknown_keys = sorted(k for k in condition_keys if k not in CONDITION_KEYS)
        if unknown_keys:
            raise VerdictsInError(f"{path}: verdicts[{i}].condition_keys has unknown key(s): {unknown_keys}")

        refute_file = ""
        refute_line = 0
        evidence_hash = ""
        if has_evidence:
            if "refute_file" not in entry or "refute_line" not in entry:
                raise VerdictsInError(
                    f"{path}: verdicts[{i}]: refute_file and refute_line must be given together"
                )
            refute_file = entry["refute_file"]
            refute_line = entry["refute_line"]
            if not isinstance(refute_file, str) or not refute_file:
                raise VerdictsInError(f"{path}: verdicts[{i}].refute_file missing/invalid")
            if not isinstance(refute_line, int) or refute_line <= 0:
                raise VerdictsInError(f"{path}: verdicts[{i}].refute_line must be a positive int")
            if _is_unsafe_evidence_path(refute_file):
                raise VerdictsInError(
                    f"{path}: verdicts[{i}].refute_file must be a relative path inside the project "
                    f"(no absolute path, no '..'): {refute_file!r}"
                )
            evidence_hash = compute_evidence_hash(refute_file, refute_line, project_root)
            if evidence_hash == _NO_HASH:
                # The sentinel would equal itself on every later run, so the
                # mark could never be invalidated by a change in the code.
                raise VerdictsInError(
                    f"{path}: verdicts[{i}]: no code at {refute_file}:{refute_line} "
                    f"(missing file, out-of-range or blank line) -- evidence cannot be located"
                )

        parsed.append((sink_hash, Resolution(
            verdict=verdict,
            condition_keys=tuple(condition_keys),
            evidence_hash=evidence_hash,
            refute_file=refute_file,
            refute_line=refute_line,
            source=source,
            run_seq=0,
        )))

    seen: dict[str, int] = {}
    for sink_hash, _ in parsed:
        seen[sink_hash] = seen.get(sink_hash, 0) + 1
    dupes = sorted(h for h, n in seen.items() if n > 1)
    if dupes:
        raise VerdictsInError(f"{path}: duplicate sink_hash(es) in verdicts: {dupes}")

    unknown_hashes = sorted({h for h, _ in parsed if h not in valid_sink_hashes})
    if unknown_hashes:
        raise VerdictsInError(
            f"{path}: unknown sink_hash(es) not present in the reference findings.json: {unknown_hashes}"
        )

    return dict(parsed)


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
