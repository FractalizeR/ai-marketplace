"""Markdown parser for SECURITY_REVIEW_RESULTS_*.md files.

Extracts Finding objects from the structured markdown format produced by
security review workers.
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path
from typing import Literal

from .models import (
    FLAG_NV_INCOMPLETE,
    FLAG_VERDICT_HAS_SEVERITY,
    KNOWN_SINK_KINDS,
    WAVE_FORMAT_VERSION,
    Finding,
    HardeningNote,
    NeedsValidation,
    ParsedWave,
)


class WaveFormatError(ValueError):
    """A wave file declares a `wave_format` this build does not know how to
    parse. A loud refusal, not a silent partial parse: an unversioned file
    is legacy (parsed under pre-Stage-2 rules), but a *declared* version this
    build does not recognize must not be guessed at."""


def validate_sink_kind(kind: str) -> Literal["known", "custom_other", "unknown_typo"]:
    """Classify a `sink_kind` string against the closed enum.

    - `kind` starting with `other:` → `custom_other` (worker-declared custom).
    - empty string → `unknown_typo` (degenerate; treated as a typo case for tests).
    - kind in `KNOWN_SINK_KINDS` → `known`.
    - anything else (typo, legacy name, fabricated identifier) → `unknown_typo`.

    Used by the parser to emit a `UserWarning` for `unknown_typo` so that runs
    surface mistakes early. The downstream `is_custom_sink` property promotes
    typos to `[CUSTOM_SINK]` regardless, so they never silently merge with
    canonical findings.
    """
    if kind.startswith("other:"):
        return "custom_other"
    if not kind:
        return "unknown_typo"
    if kind in KNOWN_SINK_KINDS:
        return "known"
    return "unknown_typo"

# ---------------------------------------------------------------------------
# Regexes.
# ---------------------------------------------------------------------------

FINDING_HEADER_RE = re.compile(r"^#\s+Vulnerability\s+\d+[^\n]*$", re.MULTILINE)

# Closed set of the three verdict-block header types (Stage 2 / wave_format 2).
# `Needs validation` / `Hardening` are new; `Vulnerability` keeps its legacy
# spelling. Used only for wave_format=2 files -- files without the marker
# keep using `FINDING_HEADER_RE` alone (see `parse_wave`).
_VERDICT_TYPE_WORD_RE = r"(Vulnerability|Needs validation|Hardening)"
VERDICT_HEADER_RE = re.compile(
    rf"^#\s+{_VERDICT_TYPE_WORD_RE}\s+\d+[^\n]*$", re.MULTILINE | re.IGNORECASE
)
_VERDICT_TYPE_MAP = {
    "vulnerability": "confirmed",
    "needs validation": "needs_validation",
    "hardening": "hardening",
}

# First non-empty line of a wave file, exactly: `<!-- wave_format: N -->`.
# Deliberately not searched for elsewhere in the file -- see `_detect_wave_format`.
_WAVE_FORMAT_MARKER_RE = re.compile(r"^<!--\s*wave_format:\s*(\d+)\s*-->$")

FIELD_RE = re.compile(r"^\*\s+\*\*([^\*]+?)\*\*\s*:\s*(.*)$")

TITLE_LOC_RE = re.compile(r"`([^`:]+):(\d+)`")
TITLE_LOC_FALLBACK_RE = re.compile(r"`([^`]+)`")
_FILE_PATH_IN_TEXT_RE = re.compile(r"([\w./-]+\.\w{1,10})\b")


def _detect_wave_format(text: str) -> int | None:
    """Return the declared `wave_format` version, or `None` if the file has
    no marker (legacy pre-Stage-2 output).

    Only the first non-empty line is a candidate. A marker appearing later
    (e.g. after the first finding header) is never recognized -- by the time
    any block splitter runs, that text is already inside a block's body, so
    "detecting" it there would protect against nothing (see the module
    docstring note in the calling code / agents/security.md wave_format
    contract: the marker must be the first non-empty line for exactly this
    reason).
    """
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m = _WAVE_FORMAT_MARKER_RE.match(stripped)
        return int(m.group(1)) if m else None
    return None


# ---------------------------------------------------------------------------
# Block splitting.
# ---------------------------------------------------------------------------


def _split_findings_blocks(markdown: str) -> list[tuple[str, str]]:
    """Return list of (header_line, body) for each finding in the markdown.

    Legacy splitter -- matches ONLY `# Vulnerability N` headers. Used
    unconditionally for wave files without a `wave_format` marker, bug for
    bug: any text after the last `# Vulnerability` header (including a
    `# Needs validation` / `# Hardening` block emitted by a worker that
    doesn't know about the marker yet) lands in that finding's body, and
    `_parse_finding_block`'s last-field-wins field loop then lets a
    `needs_validation` block silently overwrite the preceding finding's
    `sink_kind`/`sink_snippet`. This is preserved intentionally for backward
    compatibility (mixed-engine runs, stale bundles) -- see `parse_wave`.
    """
    matches = list(FINDING_HEADER_RE.finditer(markdown))
    result = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(markdown)
        block = markdown[start:end]
        header, _, body = block.partition("\n")
        result.append((header.rstrip(), body))
    return result


def _split_verdict_blocks(markdown: str) -> list[tuple[str, str, str]]:
    """Return list of (verdict_type, header_line, body) for each block.

    Single pass, closed set of header keywords (`Vulnerability` |
    `Needs validation` | `Hardening`) -- any one of the three closes the
    previous block, so a trailing `Needs validation`/`Hardening` block can
    never bleed into the preceding finding's body (the defect
    `_split_findings_blocks` has by design). A generic `^#\\s` would also
    match a real PHP comment (`# TODO`) at column 0 inside a snippet's YAML
    block scalar -- the closed set avoids that false positive too. Only used
    for wave_format=2 files.
    """
    matches = list(VERDICT_HEADER_RE.finditer(markdown))
    result = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(markdown)
        block = markdown[start:end]
        header, _, body = block.partition("\n")
        verdict_type = _VERDICT_TYPE_MAP[m.group(1).lower()]
        result.append((verdict_type, header.rstrip(), body))
    return result


# ---------------------------------------------------------------------------
# Field extraction.
# ---------------------------------------------------------------------------


def _extract_snippet_block(lines: list[str], start_idx: int, inline_value: str) -> tuple[str, int]:
    """Extract multi-line snippet starting at lines[start_idx].

    `inline_value` is the text after `sink_snippet:` on the same line.
    Returns (snippet_text, new_index).

    Termination no longer special-cases a bare `#`+space line. That check
    used to stop extraction on ANY indented line starting with `#` -- which
    silently truncated snippets containing a `# TODO` PHP comment (a real
    defect: the truncated snippet then hashed differently from its full
    content, desyncing dedupe). It was also fully redundant for its intended
    purpose: a real markdown heading (the only thing worth protecting
    against) can only ever appear at column 0, and a column-0 line already
    terminates the block via the `block_indent == 0` / `ind < block_indent`
    checks below, regardless of its text.
    """
    n = len(lines)
    stripped_inline = inline_value.strip()
    if stripped_inline and stripped_inline not in ("|", "|-", "|+", ">", ">-", ">+"):
        return stripped_inline, start_idx + 1

    i = start_idx + 1
    fenced = False
    while i < n and not lines[i].strip():
        i += 1
    if i < n and lines[i].lstrip(" ").startswith("```"):
        fenced = True
        i += 1

    snippet_lines: list[str] = []
    block_indent: int | None = None
    while i < n:
        blline = lines[i]
        stripped = blline.lstrip(" ")
        ind = len(blline) - len(stripped)

        if fenced:
            if stripped.startswith("```"):
                i += 1
                break
            snippet_lines.append(blline)
            i += 1
            continue

        if not blline.strip():
            snippet_lines.append("")
            i += 1
            continue

        if stripped.startswith("* **"):
            break
        if block_indent is None:
            block_indent = ind
            if block_indent == 0:
                break
        if ind < block_indent:
            break
        snippet_lines.append(blline[block_indent:] if len(blline) >= block_indent else blline)
        i += 1

    return "\n".join(snippet_lines).rstrip(), i


def _normalise_severity(raw: str) -> str:
    s = raw.strip()
    for token in ("Critical", "High", "Medium"):
        if token.lower() in s.lower():
            return token
    return "Medium"


def _parse_confidence(raw: str) -> int:
    m = re.search(r"(\d+)", raw)
    if not m:
        return 8
    return int(m.group(1))


def _extract_loc_from_header(header: str) -> tuple[str, int]:
    """Extract (sink_file, sink_line) from a verdict header line.

    Shared by Finding / NeedsValidation / HardeningNote parsing -- all three
    put the sink location in the header the same way (`\\`file:line\\``, or a
    bare-backtick fallback for missing-line / config-file findings).
    """
    loc_match = TITLE_LOC_RE.search(header)
    if loc_match:
        try:
            return loc_match.group(1).strip(), int(loc_match.group(2))
        except ValueError:
            return loc_match.group(1).strip(), 0

    fb_match = TITLE_LOC_FALLBACK_RE.search(header)
    if fb_match:
        raw = fb_match.group(1).strip()
        path_match = _FILE_PATH_IN_TEXT_RE.search(raw)
        if path_match:
            candidate = path_match.group(1)
            if "/" in candidate or candidate.endswith(
                (".php", ".yaml", ".yml", ".xml", ".twig", ".json", ".env")
            ):
                return candidate, 0
    return "", 0


def _parse_condition_keys(raw: str) -> list[str]:
    """`* **condition_keys**: admin_only, needs_separate_primitive` -> list.

    Comma-separated, stripped, empties dropped. Not validated against the
    closed `CONDITION_KEYS` enum here -- same permissive-parse convention as
    `sink_kind`'s `other:<name>` escape hatch; strict enum membership is a
    prompt-authoring concern (see agents/security.md), not a parse-time gate.
    """
    return [part.strip() for part in raw.split(",") if part.strip()]


def _extract_multiline_list(lines: list[str], start_idx: int, inline_value: str) -> tuple[list[str], int]:
    """Like `_extract_snippet_block`, but returns a list of items instead of
    one joined string. Used for `blockers`, where a comma-separated single
    line would be ambiguous -- a blocker's own text may contain commas.

    Each non-empty line becomes one item; a leading `- ` bullet marker is
    stripped if present. The single-line inline form (`* **blockers**: text`)
    still works and yields a one-item list.
    """
    text, new_idx = _extract_snippet_block(lines, start_idx, inline_value)
    items: list[str] = []
    for raw_line in text.splitlines():
        item = raw_line.strip()
        if item.startswith("- "):
            item = item[2:].strip()
        if item:
            items.append(item)
    return items, new_idx


# ---------------------------------------------------------------------------
# Finding parsing.
# ---------------------------------------------------------------------------


def _parse_finding_block(header: str, body: str, source_file: str = "", slice_id: str = "") -> Finding:
    f = Finding(title_line=header, raw_body=body, source_file=source_file, slice_id=slice_id)
    f.sink_file, f.sink_line = _extract_loc_from_header(header)

    lines = body.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = FIELD_RE.match(line.rstrip())
        if not m:
            i += 1
            continue
        key = m.group(1).strip()
        value = m.group(2).strip()

        if key == "sink_snippet":
            snippet_text, i = _extract_snippet_block(lines, i, value)
            f.sink_snippet = snippet_text
            continue

        if key == "Severity":
            f.severity = _normalise_severity(value)
        elif key == "Confidence":
            f.confidence = _parse_confidence(value)
        elif key == "Category":
            f.category = value
        elif key == "sink_kind":
            f.sink_kind = value.strip()
            classification = validate_sink_kind(f.sink_kind)
            if classification == "unknown_typo" and f.sink_kind:
                warnings.warn(
                    f"unknown sink_kind {f.sink_kind!r} (not in closed enum, "
                    "not `other:*` prefix) — finding will be marked [CUSTOM_SINK]",
                    UserWarning,
                    stacklevel=2,
                )
        elif key == "root_cause_family":
            f.root_cause_family = value.strip()
        elif key == "enclosing_symbol":
            f.enclosing_symbol = value.strip() or "unknown"
        elif key == "condition_keys":
            f.condition_keys = _parse_condition_keys(value)
        elif key == "Description":
            f.description = value
        elif key == "Data path":
            f.data_path = value
        elif key == "Exploitation scenario":
            f.exploit = value
        elif key == "Impact":
            f.impact = value
        elif key == "Recommendation":
            f.recommendation = value
        elif key == "Discovered via":
            f.discovered_via = value

        i += 1
    return f


def _derive_slice_id(path: Path) -> str:
    """Derive slice_id from a wave-output path.

    Resolution order:
    1. v3 layout — `<review_root>/waves/<slice_id>.md` → `path.stem`.
    2. Legacy v2 layout — `SECURITY_REVIEW_RESULTS_<slice_id>.md` → captured group.
    3. Fallback — `path.stem` (handles ad-hoc inputs).
    """
    if path.parent.name == "waves":
        return path.stem
    m = re.search(r"SECURITY_REVIEW_RESULTS_(.+)\.md$", path.name)
    if m:
        return m.group(1)
    return path.stem


# ---------------------------------------------------------------------------
# needs_validation / hardening parsing.
#
# Neither type has Severity/Confidence -- if a worker puts one on anyway
# (prompt violation), it is dropped and flagged, never stored (there is no
# field to store it in).
# ---------------------------------------------------------------------------


def _parse_needs_validation_block(
    header: str, body: str, source_file: str = "", slice_id: str = ""
) -> NeedsValidation:
    sink_file, sink_line = _extract_loc_from_header(header)
    nv = NeedsValidation(
        sink_file=sink_file, sink_line=sink_line,
        raw_body=body, source_file=source_file, slice_id=slice_id,
    )

    lines = body.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = FIELD_RE.match(line.rstrip())
        if not m:
            i += 1
            continue
        key = m.group(1).strip()
        value = m.group(2).strip()

        if key == "sink_snippet":
            nv.sink_snippet, i = _extract_snippet_block(lines, i, value)
            continue
        if key == "blockers":
            nv.blockers, i = _extract_multiline_list(lines, i, value)
            continue

        if key in ("Severity", "Confidence"):
            if FLAG_VERDICT_HAS_SEVERITY not in nv.flags:
                nv.flags.append(FLAG_VERDICT_HAS_SEVERITY)
        elif key == "sink_kind":
            nv.sink_kind = value
            classification = validate_sink_kind(nv.sink_kind)
            if classification == "unknown_typo" and nv.sink_kind:
                warnings.warn(
                    f"unknown sink_kind {nv.sink_kind!r} (not in closed enum, "
                    "not `other:*` prefix) in a needs_validation block",
                    UserWarning,
                    stacklevel=2,
                )
        elif key == "root_cause_family":
            nv.root_cause_family = value
        elif key == "enclosing_symbol":
            nv.enclosing_symbol = value or "unknown"
        elif key == "claimed_root_cause":
            nv.claimed_root_cause = value
        elif key == "trace":
            nv.trace = value
        elif key == "validation_plan_local":
            nv.validation_plan_local = value or None
        elif key == "validation_plan_deployment":
            nv.validation_plan_deployment = value or None
        elif key == "condition_keys":
            nv.condition_keys = _parse_condition_keys(value)

        i += 1

    if not nv.blockers or not (nv.validation_plan_local or nv.validation_plan_deployment):
        if FLAG_NV_INCOMPLETE not in nv.flags:
            nv.flags.append(FLAG_NV_INCOMPLETE)

    return nv


def _parse_hardening_block(
    header: str, body: str, source_file: str = "", slice_id: str = ""
) -> HardeningNote:
    sink_file, sink_line = _extract_loc_from_header(header)
    hn = HardeningNote(
        sink_file=sink_file, sink_line=sink_line,
        raw_body=body, source_file=source_file, slice_id=slice_id,
    )

    lines = body.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = FIELD_RE.match(line.rstrip())
        if not m:
            i += 1
            continue
        key = m.group(1).strip()
        value = m.group(2).strip()

        if key == "sink_snippet":
            hn.sink_snippet, i = _extract_snippet_block(lines, i, value)
            continue

        if key in ("Severity", "Confidence"):
            if FLAG_VERDICT_HAS_SEVERITY not in hn.flags:
                hn.flags.append(FLAG_VERDICT_HAS_SEVERITY)
        elif key == "sink_kind":
            hn.sink_kind = value
            classification = validate_sink_kind(hn.sink_kind)
            if classification == "unknown_typo" and hn.sink_kind:
                warnings.warn(
                    f"unknown sink_kind {hn.sink_kind!r} (not in closed enum, "
                    "not `other:*` prefix) in a hardening block",
                    UserWarning,
                    stacklevel=2,
                )
        elif key == "root_cause_family":
            hn.root_cause_family = value
        elif key == "enclosing_symbol":
            hn.enclosing_symbol = value or "unknown"
        elif key == "text":
            hn.text = value
        elif key == "condition_keys":
            hn.condition_keys = _parse_condition_keys(value)

        i += 1

    return hn


def parse_wave(path: Path) -> ParsedWave:
    """Parse one wave file into its three verdict buckets.

    Dispatches on `_detect_wave_format`:
      - no marker -> legacy path: `_split_findings_blocks` (Vulnerability
        headers only) + `_parse_finding_block`, byte-for-byte what
        `parse_findings_file` did before Stage 2. Any `needs_validation` /
        `hardening` block present without the marker is NOT recognized as
        such -- its header is invisible to `FINDING_HEADER_RE`, so its body
        (including fields like `sink_kind`/`sink_snippet`) is swallowed into
        the preceding `# Vulnerability` block by the legacy splitter's own
        defect, and silently becomes part of that Finding via last-field-wins
        (it has no Severity/Confidence fields of its own, so the surrounding
        Finding keeps its defaults `severity="Medium"`, `confidence=8`).
        This is intentional backward compatibility, not a bug in `parse_wave`.
      - known version (== WAVE_FORMAT_VERSION) -> `_split_verdict_blocks`,
        each block routed to Finding / NeedsValidation / HardeningNote.
      - any other declared version -> `WaveFormatError` (loud refusal).
    """
    text = path.read_text(encoding="utf-8")
    slice_id = _derive_slice_id(path)
    version = _detect_wave_format(text)

    if version is None:
        findings = [
            _parse_finding_block(header, body, source_file=path.name, slice_id=slice_id)
            for header, body in _split_findings_blocks(text)
        ]
        return ParsedWave(findings=findings)

    if version != WAVE_FORMAT_VERSION:
        raise WaveFormatError(
            f"{path}: unsupported wave_format {version} declared "
            f"(this build only knows wave_format {WAVE_FORMAT_VERSION}). "
            "Refusing to guess at the format -- rebuild/reinstall the plugin "
            "bundle that produced this file."
        )

    findings: list[Finding] = []
    needs_validation: list[NeedsValidation] = []
    hardening: list[HardeningNote] = []
    for verdict_type, header, body in _split_verdict_blocks(text):
        if verdict_type == "confirmed":
            findings.append(
                _parse_finding_block(header, body, source_file=path.name, slice_id=slice_id)
            )
        elif verdict_type == "needs_validation":
            needs_validation.append(
                _parse_needs_validation_block(header, body, source_file=path.name, slice_id=slice_id)
            )
        elif verdict_type == "hardening":
            hardening.append(
                _parse_hardening_block(header, body, source_file=path.name, slice_id=slice_id)
            )

    return ParsedWave(findings=findings, needs_validation=needs_validation, hardening=hardening)


def parse_findings_file(path: Path) -> list[Finding]:
    """Return only the `confirmed` findings from a wave file.

    Thin wrapper over `parse_wave` -- signature unchanged (it is in the
    public `__all__` and has callers outside this package:
    `bin/dedupe_findings.py`, `bin/tests/test_refute.py`).
    """
    return parse_wave(path).findings
