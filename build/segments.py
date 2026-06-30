"""Segment model + partition invariants for the byte-preserving IR.

An artifact is partitioned by ``extract()`` into an ordered list of ``Segment``s
that cover the *exact* decoded text with no gaps, no overlaps, and no added or
removed characters. ``build()`` is a pure fold that renders each segment via a
harness adapter and concatenates the result.

All offsets are **codepoint offsets in the decoded ``str``**, never byte
offsets — the only byte-level operation in the pipeline is the final
``bytes-out == bytes-in`` equality in ``build.py`` (see ADR-0001 / the plan's
I/O rule). Mixing the two would corrupt multi-codepoint graphemes such as
``⚠️`` which appear throughout the artifacts.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Tier(enum.Enum):
    """How a segment relates to harness portability.

    ACTIVE_CANONICAL — abstracted now and rendered from a canonical form (must
        reproduce the original for Claude); the only category that exercises a
        non-identity renderer.
    ACTIVE_PARSED — attributes captured now (so later harness renderers are not
        blocked) but rendered by echo for Claude.
    DEFERRED — inventoried as harness-coupled but intentionally not abstracted
        in Phase 1 (e.g. bare tool names); allow-listed in the no-leak scan.
    NEUTRAL — harness-agnostic prose; echoed verbatim.
    """

    ACTIVE_CANONICAL = "active_canonical"
    ACTIVE_PARSED = "active_parsed"
    DEFERRED = "deferred"
    NEUTRAL = "neutral"


class RenderMode(enum.Enum):
    """How an adapter turns a segment back into text."""

    ECHO = "echo"            # emit original_text verbatim
    CANONICAL = "canonical"  # emit the adapter's canonical form for the category
    PASSTHROUGH = "passthrough"  # like ECHO, but semantically "not handled here"


# The single NEUTRAL category key (kept as a constant so the registry and the
# completeness scan agree on the name).
NEUTRAL_CATEGORY = "neutral"


@dataclass(frozen=True)
class Segment:
    """One contiguous slice of an artifact.

    ``original_text`` is the exact source substring ``source[span[0]:span[1]]``.
    ``attrs`` carries category-specific data captured at extract time (empty for
    NEUTRAL). ``render_mode`` is the default rendering for the category; an
    adapter may still override per category via its own dispatch.
    """

    category: str
    tier: Tier
    original_text: str
    span: tuple[int, int]
    render_mode: RenderMode
    attrs: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        start, end = self.span
        if start > end:
            raise ValueError(f"inverted span {self.span} for {self.category!r}")
        if len(self.original_text) != end - start:
            raise ValueError(
                f"span {self.span} (len {end - start}) does not match "
                f"original_text length {len(self.original_text)} for {self.category!r}"
            )


def assert_partition(segments: list[Segment], source: str) -> None:
    """Raise if ``segments`` is not a faithful, gap-free partition of ``source``.

    Checks, in order: contiguity/ordering of spans, that joined text equals the
    source, and that the covered length matches. Any failure means a recognizer
    dropped, reordered, or duplicated bytes — caught before ``build`` runs.
    """
    cursor = 0
    for seg in segments:
        start, end = seg.span
        if start != cursor:
            raise AssertionError(
                f"non-contiguous partition: expected span start {cursor}, "
                f"got {start} for {seg.category!r}"
            )
        if seg.original_text != source[start:end]:
            raise AssertionError(
                f"segment text does not match source at {seg.span} for {seg.category!r}"
            )
        cursor = end
    if cursor != len(source):
        raise AssertionError(
            f"partition covers {cursor} chars but source has {len(source)}"
        )
    if "".join(s.original_text for s in segments) != source:
        raise AssertionError("joined segments != source")
