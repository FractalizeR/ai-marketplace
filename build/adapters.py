"""Harness adapters: render a Segment back into text for a target harness.

Phase 1 ships only ``ClaudeAdapter`` (the round-trip target) plus a tiny
``FakeAdapter`` used by the divergence test to prove the IR has a real seam at
the CORE_ROOT spans. ``CodexAdapter`` / ``OpenCodeAdapter`` are explicit stubs
that raise ``NotImplementedError`` on any tagged segment — they are implemented
in Phases 2/3.
"""

from __future__ import annotations

import re
from pathlib import Path

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


# --- OpenCode rendering constants -------------------------------------------
OPENCODE_CORE_ROOT = "${CORE_ROOT}"          # bundled-core placeholder (NOT Claude's)
OPENCODE_AUQ_PHRASE = "an interactive prompt"
OPENCODE_MCP_PHRASE = "a semantic IDE tool"
_MAX_DESC = 1024
# Sibling-artifact *file* refs (e.g. "security-project.md", "agents/security-recon.md")
# are broken in a standalone skill — drop the `.md` extension, leaving the logical
# name as a pointer. Word-bounded so a substring like "foo-security.md" is left alone.
_XREF_FILE = re.compile(
    r"\b((?:agents/)?security(?:-project|-changes|-recon|-refute)?)\.md\b"
)


class RenderContext:
    """Per-artifact context handed to ``render_section``."""

    def __init__(self, artifact_basename: str):
        self.artifact_basename = artifact_basename


def _default_template_loader(root: Path):
    def load(artifact_basename: str, section_anchor: str) -> str:
        path = root / artifact_basename / f"{section_anchor}.md"
        if not path.is_file():
            raise FileNotFoundError(
                f"missing OpenCode section template: {artifact_basename}/{section_anchor}.md"
            )
        return path.read_text(encoding="utf-8")
    return load


class OpenCodeAdapter:
    """Derives an OpenCode artifact: token-render portable spans, replace coupled
    sections with authored templates. Prose rewriting (not byte preservation) is
    the contract — there is no Claude-style byte oracle, only the structural gates.

    ``template_loader(artifact_basename, section_anchor) -> str`` is injected so
    tests need no disk. Default loads from ``harness/opencode/sections/``.
    """

    name = "opencode"

    def __init__(self, template_loader=None, *, template_root: Path | None = None):
        if template_loader is None:
            root = template_root or (
                Path(__file__).resolve().parent.parent
                / "harness" / "opencode" / "sections"
            )
            template_loader = _default_template_loader(root)
        self._load = template_loader

    # -- token rendering (renderable categories only) -----------------------
    def render_segment(self, seg: Segment) -> str:
        cat = seg.category
        if cat == NEUTRAL_CATEGORY:
            return seg.original_text
        if cat == CAT_CORE_ROOT:
            return OPENCODE_CORE_ROOT
        if cat == CAT_ARGS:
            return seg.original_text          # OpenCode supports $ARGUMENTS natively (D1)
        if cat == CAT_CMD_FRONTMATTER:
            return _synthesize_frontmatter(seg.attrs)
        if cat == CAT_AGENT_FRONTMATTER:
            # An OpenCode agent needs a `description` frontmatter to register under
            # `--agent <name>`; the model comes from the dispatcher's -m, not the
            # artifact. Synthesize a description-only block (same as commands).
            return _synthesize_frontmatter(seg.attrs)
        if cat == CAT_MCP:
            return OPENCODE_MCP_PHRASE
        if cat == CAT_AUQ:
            if seg.attrs.get("occurrence_kind") == "labeled-block":
                raise AssertionError(
                    "labeled-block AskUserQuestion must be inside a coupled section"
                )
            return OPENCODE_AUQ_PHRASE         # prose-mention -> neutral phrase
        if cat == CAT_TASK:
            raise AssertionError("task_block must be inside a coupled section")
        raise NotImplementedError(f"opencode adapter has no render for {cat!r}")

    # -- section rendering --------------------------------------------------
    def render_section(self, section, ctx: RenderContext) -> str:
        if section.is_coupled:
            out = self._load(ctx.artifact_basename, section.section_anchor)
        else:
            out = self._splice(section)
        return _strip_xrefs(out)

    def _splice(self, section) -> str:
        """Echo the section, substituting its tagged tokens in place."""
        base = section.span[0]
        text = section.original_text
        pieces: list[str] = []
        cursor = 0
        for seg in sorted(section.inner_segments, key=lambda s: s.span[0]):
            rel_start = seg.span[0] - base
            rel_end = seg.span[1] - base
            pieces.append(text[cursor:rel_start])
            pieces.append(self.render_segment(seg))
            cursor = rel_end
        pieces.append(text[cursor:])
        return "".join(pieces)

    def capabilities(self) -> dict[str, Tier]:
        return {c: Tier.ACTIVE_PARSED for c in _ALL_CATEGORIES}


def _synthesize_frontmatter(attrs: dict) -> str:
    raw = attrs.get("description") or ""
    # extract._kv keeps the surrounding quotes; unwrap so truncation/escaping act
    # on the value, never producing an unterminated quoted scalar.
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        value = raw[1:-1]
    else:
        value = raw
    if len(value) > _MAX_DESC:
        value = value[:_MAX_DESC].rsplit(" ", 1)[0]
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'---\ndescription: "{value}"\n---\n'


def _strip_xrefs(text: str) -> str:
    return _XREF_FILE.sub(r"\1", text)


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
