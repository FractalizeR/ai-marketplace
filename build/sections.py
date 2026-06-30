"""Section partition: the coarser, second IR layer for harness derivation.

`extract.extract()` gives a flat *token* partition (Phase 1, byte-faithful). This
module gives an independent *section* partition of the **same** text, split at
markdown headings (`#`..`####`). Both cover the exact source with no gaps. The
Claude build never uses this layer (it stays on the token fold → byte-identical);
the OpenCode build walks sections, replacing harness-coupled ones with authored
templates and token-folding the rest (see ADR-0001 / the Phase-2B plan).

Boundary rule (AD-2B6): a `^#{1,4} ` line is a section boundary **only** when it is
not inside a fenced code block or a `task_block` span. Fenced intervals are scanned
per CommonMark (an N-backtick fence closes only on a line of ≥N backticks), so a
nested ``` inside a ````markdown block — and a heading-looking line inside a
triple-quoted Task prompt body — never split a section.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from segments import Segment, Tier
from extract import CAT_AUQ, CAT_TASK


_FENCE_OPEN = re.compile(r"`{3,}")
_HEADING = re.compile(r"(#{1,4})\s+(.*?)\s*$")


def _fence_intervals(text: str) -> list[tuple[int, int]]:
    """Codepoint ranges of content inside ``` fenced blocks (n-backtick aware).

    Only backtick fences are recognized (the artifacts use no ``~~~`` or indented
    code blocks); ``assert_section_partition`` keeps byte-faithfulness regardless,
    and a spurious split would surface as a coupling-coverage gate failure.
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
    pins: list[str] = field(default_factory=list)        # PROSE_COUPLING ids matched
    inner_segments: list[Segment] = field(default_factory=list)
    is_coupled: bool = False

    def __post_init__(self) -> None:
        start, end = self.span
        if len(self.original_text) != end - start:
            raise ValueError(
                f"span {self.span} does not match text length "
                f"{len(self.original_text)} for section {self.section_anchor!r}"
            )


def partition_sections(text: str, *, task_spans: list[tuple[int, int]]) -> list[Section]:
    """Byte-faithful split at headings, skipping headings inside opaque regions."""
    opaque = _merge(_fence_intervals(text) + list(task_spans))

    # Boundary offsets = the line-start of every heading line not inside an opaque span.
    boundaries: list[tuple[int, int, str]] = []  # (offset, level, heading_text)
    offset = 0
    for line in text.splitlines(keepends=True):
        if not _in_any(offset, opaque):
            m = _HEADING.match(line.rstrip("\n"))
            if m:
                boundaries.append((offset, len(m.group(1)), m.group(2)))
        offset += len(line)

    # Section starts = 0 (preamble) then each boundary offset.
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


def attach_segments(sections: list[Section], segments: list[Segment]) -> list[Section]:
    """Bind each *tagged* token segment to the one section that contains it.

    NEUTRAL segments are the connective prose and routinely span several headings,
    so they are not attached — a neutral section renders from its own text with the
    tagged tokens spliced in (build_sectioned). Tagged tokens are short, and Task
    blocks are opaque to the splitter, so every tagged segment lies within exactly
    one section; a crossing one means the partition logic broke and we fail loudly.
    """
    buckets: dict[int, list[Segment]] = {id(s): [] for s in sections}
    for seg in segments:
        if seg.tier is Tier.NEUTRAL:
            continue
        s_start, s_end = seg.span
        owner = next(
            (s for s in sections if s.span[0] <= s_start and s_end <= s.span[1]),
            None,
        )
        if owner is None:
            raise AssertionError(
                f"tagged segment {seg.category} {seg.span} crosses a section boundary"
            )
        buckets[id(owner)].append(seg)
    return [replace(s, inner_segments=buckets[id(s)]) for s in sections]


def detect_coupling(sections: list[Section], pinned_literals: list[str]) -> list[Section]:
    """Pin-driven coupling: a section is coupled iff it contains ≥1 pinned literal.

    ``pinned_literals`` are the pins for *this* artifact only (filter upstream).
    """
    out: list[Section] = []
    for s in sections:
        matched = [p for p in pinned_literals if p in s.original_text]
        out.append(replace(s, pins=matched, is_coupled=bool(matched)))
    return out


def assert_coupling_guards(sections: list[Section]) -> None:
    """Completeness guards: every prose-coupled token sits in a coupled section.

    `task_block` tokens and `labeled-block` AskUserQuestion tokens have no benign
    prose form — if one lands in a section with no pin, the register is incomplete
    and the OpenCode build would echo a broken instruction. Fail loudly instead.
    Requires `attach_segments` + `detect_coupling` to have run first.
    """
    for s in sections:
        if s.is_coupled:
            continue
        for seg in s.inner_segments:
            if seg.category == CAT_TASK:
                raise AssertionError(
                    f"task_block at {seg.span} is in uncoupled section "
                    f"{s.section_anchor!r} — add a PROSE_COUPLING pin for it"
                )
            if seg.category == CAT_AUQ and seg.attrs.get("occurrence_kind") == "labeled-block":
                raise AssertionError(
                    f"labeled-block AskUserQuestion at {seg.span} is in uncoupled "
                    f"section {s.section_anchor!r} — add a PROSE_COUPLING pin for it"
                )
