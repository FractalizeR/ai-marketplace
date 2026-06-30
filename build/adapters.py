"""Harness adapters: render a Segment back into text for a target harness.

Phase 1 ships only ``ClaudeAdapter`` (the round-trip target) plus a tiny
``FakeAdapter`` used by the divergence test to prove the IR has a real seam at
the CORE_ROOT spans. ``CodexAdapter`` / ``OpenCodeAdapter`` are explicit stubs
that raise ``NotImplementedError`` on any tagged segment — they are implemented
in Phases 2/3.
"""

from __future__ import annotations

from segments import NEUTRAL_CATEGORY, RenderMode, Segment, Tier
from extract import (
    CAT_AGENT_FRONTMATTER,
    CAT_ARGS,
    CAT_AUQ,
    CAT_CMD_FRONTMATTER,
    CAT_CORE_ROOT,
    CAT_MCP,
    CAT_TASK,
)

# The one canonical constant a CANONICAL renderer must reproduce for Claude.
CLAUDE_CORE_ROOT = "${CLAUDE_PLUGIN_ROOT}"

_ALL_CATEGORIES = (
    CAT_CORE_ROOT,
    CAT_ARGS,
    CAT_CMD_FRONTMATTER,
    CAT_AGENT_FRONTMATTER,
    CAT_TASK,
    CAT_AUQ,
    CAT_MCP,
)


class ClaudeAdapter:
    """Renders to the authoritative Claude form.

    CORE_ROOT renders from the canonical constant (not by echoing
    ``original_text``), which is what makes the round-trip a real test of the
    canonical renderer rather than a tautology. Every other category echoes.
    """

    name = "claude"

    def render_segment(self, seg: Segment) -> str:
        if seg.category == CAT_CORE_ROOT:
            return CLAUDE_CORE_ROOT
        return seg.original_text

    def capabilities(self) -> dict[str, Tier]:
        return {c: Tier.ACTIVE_CANONICAL if c == CAT_CORE_ROOT else Tier.ACTIVE_PARSED
                for c in _ALL_CATEGORIES}


class FakeAdapter:
    """Identical to Claude except it renders CORE_ROOT to a distinct marker.

    Used only by tests: ``build(FakeAdapter)`` must differ from
    ``build(ClaudeAdapter)`` exactly at the CORE_ROOT spans and nowhere else,
    proving the IR localizes harness variation to its tagged spans.
    """

    name = "fake"
    MARKER = "@@CORE_ROOT@@"

    def render_segment(self, seg: Segment) -> str:
        if seg.category == CAT_CORE_ROOT:
            return self.MARKER
        return seg.original_text

    def capabilities(self) -> dict[str, Tier]:
        return ClaudeAdapter().capabilities()


class _StubAdapter:
    """Phase 2/3 placeholder: refuses to render any tagged segment."""

    name = "stub"

    def render_segment(self, seg: Segment) -> str:
        if seg.category == NEUTRAL_CATEGORY:
            return seg.original_text
        raise NotImplementedError(
            f"{self.name} adapter does not render {seg.category!r} yet "
            f"(Phase 2/3 work)"
        )

    def capabilities(self) -> dict[str, Tier]:
        return {NEUTRAL_CATEGORY: Tier.NEUTRAL}


class CodexAdapter(_StubAdapter):
    name = "codex"


class OpenCodeAdapter(_StubAdapter):
    name = "opencode"


_ADAPTERS = {
    "claude": ClaudeAdapter,
    "fake": FakeAdapter,
    "codex": CodexAdapter,
    "opencode": OpenCodeAdapter,
}


def get_adapter(harness: str):
    try:
        return _ADAPTERS[harness]()
    except KeyError:
        raise ValueError(f"unknown harness {harness!r}; known: {sorted(_ADAPTERS)}")
