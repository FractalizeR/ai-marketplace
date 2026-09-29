"""Section partition of an authoritative Claude artifact.

The Codex derivation walks an artifact section by section: a section is either
replaced by an authored template or rendered by token substitution
(``derive.py``). This module only splits; ``assert_section_partition`` proves the
sections concatenate back to the exact source.

Boundary rule: a ``^#{1,4} `` line is a section boundary **only** when it is not
inside the leading frontmatter, a fenced code block, or a ``Task`` directive.
Fenced intervals are scanned per CommonMark (an N-backtick fence closes only on a
line of ≥N backticks), so a nested ``` inside a ````markdown block — and a
heading-looking line inside a triple-quoted Task prompt body — never split a
section.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


FRONTMATTER_RE = re.compile(r"\A---\n.*?\n---\n", re.DOTALL)
# Task, paren + triple-quote form. The model value may contain commas
# (``<from plan, field "model">``), so it is matched non-greedily up to ``, prompt=``.
_TASK_PAREN_RE = re.compile(
    r'Task\(subagent_type="[^"]+"'
    r'(?:,\s*model=.*?)?'
    r',\s*prompt=""".*?"""\)',
    re.DOTALL,
)
# Task, bare form: ``Task subagent_type=<id> prompt="<body>"``. A body holding a
# literal ``"`` ends the match early; the heading-skip would then miss headings
# past that quote, which the leak gate would still surface.
_TASK_BARE_RE = re.compile(
    r'Task\s+subagent_type=\S+\s+prompt=".*?"',
    re.DOTALL,
)
_FENCE_OPEN = re.compile(r"`{3,}")
_HEADING = re.compile(r"(#{1,4})\s+(.*?)\s*$")


def frontmatter_end(text: str) -> int:
    """Offset just past the leading ``---`` frontmatter block, or 0 if none."""
    m = FRONTMATTER_RE.match(text)
    return m.end() if m else 0


def task_spans(text: str, start: int = 0) -> list[tuple[int, int]]:
    """Codepoint ranges of ``Task`` directives (both syntaxes) at or after ``start``."""
    spans: list[tuple[int, int]] = []
    for regex in (_TASK_PAREN_RE, _TASK_BARE_RE):
        spans += [m.span() for m in regex.finditer(text, start)]
    return spans


def _fence_intervals(text: str) -> list[tuple[int, int]]:
    """Codepoint ranges of content inside ``` fenced blocks (n-backtick aware).

    Only backtick fences are recognized (the artifacts use no ``~~~`` or indented
    code blocks); ``assert_section_partition`` keeps byte-faithfulness regardless.
    """
    intervals: list[tuple[int, int]] = []
    in_fence = False
    fence_len = 0
    region_start = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        m = _FENCE_OPEN.match(stripped)
        if not in_fence:
            if m:
                in_fence = True
                fence_len = len(m.group(0))
                region_start = offset + len(line)
        else:
            # CommonMark closing fence: only backticks, length >= the opener.
            if m and stripped == m.group(0) and len(m.group(0)) >= fence_len:
                in_fence = False
                intervals.append((region_start, offset))
        offset += len(line)
    if in_fence:  # unterminated fence: treat the rest as opaque
        intervals.append((region_start, offset))
    return intervals


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def _in_any(pos: int, intervals: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in intervals)


def slugify(heading_text: str) -> str:
    """Stable anchor slug; e.g. ``4. Recon phase`` -> ``4-recon-phase``."""
    return re.sub(r"[^a-z0-9]+", "-", heading_text.strip().lower()).strip("-")


@dataclass(frozen=True)
class Section:
    heading_level: int            # 0 = preamble before the first heading
    heading_text: str | None
    section_anchor: str
    span: tuple[int, int]
    original_text: str

    def __post_init__(self) -> None:
        start, end = self.span
        if len(self.original_text) != end - start:
            raise ValueError(
                f"span {self.span} does not match text length "
                f"{len(self.original_text)} for section {self.section_anchor!r}"
            )


def partition_sections(text: str) -> list[Section]:
    """Byte-faithful split at headings, skipping headings inside opaque regions."""
    fm_end = frontmatter_end(text)
    opaque = _merge(
        [(0, fm_end)] + _fence_intervals(text) + task_spans(text, fm_end)
    )

    # Boundary offsets = the line-start of every heading line not inside an opaque span.
    boundaries: list[tuple[int, int, str]] = []  # (offset, level, heading_text)
    offset = 0
    for line in text.splitlines(keepends=True):
        if not _in_any(offset, opaque):
            m = _HEADING.match(line.rstrip("\n"))
            if m:
                boundaries.append((offset, len(m.group(1)), m.group(2)))
        offset += len(line)

    starts = [(0, 0, None)] + boundaries
    sections: list[Section] = []
    for i, (start, level, htext) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        if start == end:
            continue  # a heading at offset 0 leaves no preamble — skip the empty slice
        anchor = slugify(htext) if htext is not None else "_preamble"
        sections.append(
            Section(
                heading_level=level,
                heading_text=htext,
                section_anchor=anchor,
                span=(start, end),
                original_text=text[start:end],
            )
        )
    return sections


def assert_section_partition(sections: list[Section], source: str) -> None:
    """Raise unless ``sections`` is a faithful, gap-free partition of ``source``."""
    cursor = 0
    for sec in sections:
        start, end = sec.span
        if start != cursor:
            raise AssertionError(
                f"non-contiguous sections: expected start {cursor}, got {start} "
                f"for {sec.section_anchor!r}"
            )
        if sec.original_text != source[start:end]:
            raise AssertionError(f"section text mismatch at {sec.span}")
        cursor = end
    if cursor != len(source):
        raise AssertionError(f"sections cover {cursor} chars but source has {len(source)}")
    if "".join(s.original_text for s in sections) != source:
        raise AssertionError("joined sections != source")
