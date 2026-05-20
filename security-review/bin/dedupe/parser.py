"""Markdown parser for SECURITY_REVIEW_RESULTS_*.md files.

Extracts Finding objects from the structured markdown format produced by
security review workers.
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path
from typing import Literal

from .models import KNOWN_SINK_KINDS, Finding


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

FINDING_HEADER_RE = re.compile(r"^#\s+Уязвимость\s+\d+[^\n]*$", re.MULTILINE)

FIELD_RE = re.compile(r"^\*\s+\*\*([^\*]+?)\*\*\s*:\s*(.*)$")

TITLE_LOC_RE = re.compile(r"`([^`:]+):(\d+)`")
TITLE_LOC_FALLBACK_RE = re.compile(r"`([^`]+)`")
_FILE_PATH_IN_TEXT_RE = re.compile(r"([\w./-]+\.\w{1,10})\b")


# ---------------------------------------------------------------------------
# Block splitting.
# ---------------------------------------------------------------------------


def _split_findings_blocks(markdown: str) -> list[tuple[str, str]]:
    """Return list of (header_line, body) for each finding in the markdown."""
    matches = list(FINDING_HEADER_RE.finditer(markdown))
    result = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(markdown)
        block = markdown[start:end]
        header, _, body = block.partition("\n")
        result.append((header.rstrip(), body))
    return result


# ---------------------------------------------------------------------------
# Field extraction.
# ---------------------------------------------------------------------------


def _extract_snippet_block(lines: list[str], start_idx: int, inline_value: str) -> tuple[str, int]:
    """Extract multi-line snippet starting at lines[start_idx].

    `inline_value` is the text after `sink_snippet:` on the same line.
    Returns (snippet_text, new_index).
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

        if stripped.startswith("* **") or re.match(r"^#+\s", stripped):
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


# ---------------------------------------------------------------------------
# Finding parsing.
# ---------------------------------------------------------------------------


def _parse_finding_block(header: str, body: str, source_file: str = "", slice_id: str = "") -> Finding:
    f = Finding(title_line=header, raw_body=body, source_file=source_file, slice_id=slice_id)

    loc_match = TITLE_LOC_RE.search(header)
    if loc_match:
        f.sink_file = loc_match.group(1).strip()
        try:
            f.sink_line = int(loc_match.group(2))
        except ValueError:
            f.sink_line = 0
    else:
        fb_match = TITLE_LOC_FALLBACK_RE.search(header)
        if fb_match:
            raw = fb_match.group(1).strip()
            path_match = _FILE_PATH_IN_TEXT_RE.search(raw)
            if path_match:
                candidate = path_match.group(1)
                if "/" in candidate or candidate.endswith(
                    (".php", ".yaml", ".yml", ".xml", ".twig", ".json", ".env")
                ):
                    f.sink_file = candidate
                    f.sink_line = 0

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
        elif key in ("Категория", "Category"):
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
        elif key in ("Описание", "Description"):
            f.description = value
        elif key in ("Путь данных", "Data path"):
            f.data_path = value
        elif key in ("Сценарий эксплуатации", "Exploitation scenario"):
            f.exploit = value
        elif key in ("Потенциальное влияние", "Impact"):
            f.impact = value
        elif key in ("Рекомендация", "Recommendation"):
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


def parse_findings_file(path: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8")
    slice_id = _derive_slice_id(path)
    result = []
    for header, body in _split_findings_blocks(text):
        f = _parse_finding_block(header, body, source_file=path.name, slice_id=slice_id)
        result.append(f)
    return result
