"""The partitioner: turn an artifact's decoded text into a list of Segments.

``extract(text, kind)`` is pure, deterministic, and does no IO. It guarantees
``assert_partition(extract(text, kind), text)`` — the segments cover the exact
text with no gaps/overlaps. Recognized harness-coupled spans are tagged; all
other text becomes NEUTRAL segments.

Tagging rules (Phase 1):
  * The leading YAML frontmatter is one opaque echoed segment, parsed read-only
    into ``attrs`` (never re-serialized). Tokens lexically inside it
    (``${CLAUDE_PLUGIN_ROOT}`` globs, the ``Task`` / ``AskUserQuestion``
    allowed-tools entries) are surfaced only via those attrs, not separately.
  * Body recognizers: CORE_ROOT (``${CLAUDE_PLUGIN_ROOT}``), task_block (both
    syntaxes), auq (``AskUserQuestion``), mcp_ref (``mcp__…__…``), args_injection
    (``$ARGUMENTS``). A point token lexically inside a task_block is subsumed.
  * Everything else is NEUTRAL.
"""

from __future__ import annotations

import enum
import re
from typing import Any

from segments import NEUTRAL_CATEGORY, RenderMode, Segment, Tier


class ArtifactKind(enum.Enum):
    COMMAND = "command"
    AGENT = "agent"


# --- category keys (shared with tokens.py / tests) -------------------------
CAT_CORE_ROOT = "CORE_ROOT"
CAT_ARGS = "args_injection"
CAT_CMD_FRONTMATTER = "cmd_frontmatter"
CAT_AGENT_FRONTMATTER = "agent_frontmatter"
CAT_TASK = "task_block"
CAT_AUQ = "auq"
CAT_MCP = "mcp_ref"

# Default render mode per tagged category for the *neutral* round-trip. Only
# CORE_ROOT is CANONICAL; the rest echo.
_RENDER_MODE = {
    CAT_CORE_ROOT: RenderMode.CANONICAL,
    CAT_ARGS: RenderMode.ECHO,
    CAT_CMD_FRONTMATTER: RenderMode.ECHO,
    CAT_AGENT_FRONTMATTER: RenderMode.ECHO,
    CAT_TASK: RenderMode.ECHO,
    CAT_AUQ: RenderMode.ECHO,
    CAT_MCP: RenderMode.ECHO,
}
_TIER = {
    CAT_CORE_ROOT: Tier.ACTIVE_CANONICAL,
    CAT_ARGS: Tier.ACTIVE_PARSED,
    CAT_CMD_FRONTMATTER: Tier.ACTIVE_PARSED,
    CAT_AGENT_FRONTMATTER: Tier.ACTIVE_PARSED,
    CAT_TASK: Tier.ACTIVE_PARSED,
    CAT_AUQ: Tier.ACTIVE_PARSED,
    CAT_MCP: Tier.ACTIVE_PARSED,
}

# --- regexes ---------------------------------------------------------------
_FRONTMATTER_RE = re.compile(r"\A---\n.*?\n---\n", re.DOTALL)
_CORE_ROOT_RE = re.compile(r"\$\{CLAUDE_PLUGIN_ROOT\}")
_ARGS_RE = re.compile(r"\$ARGUMENTS")
_AUQ_RE = re.compile(r"AskUserQuestion")
_MCP_RE = re.compile(r"mcp__[A-Za-z0-9_]+__[A-Za-z0-9_*]+")
# Task, paren + triple-quote form. model value may contain commas
# (``<from plan, field "model">``) so it is captured non-greedily up to
# ``, prompt=``.
_TASK_PAREN_RE = re.compile(
    r'Task\(subagent_type="(?P<st>[^"]+)"'
    r'(?:,\s*model=(?P<model>.*?))?'
    r',\s*prompt="""(?P<body>.*?)"""\)',
    re.DOTALL,
)
# Task, bare form: ``Task subagent_type=<id> prompt="<body>"``. Best-effort for
# attrs only (the whole block is echoed, so bytes are safe regardless): a body
# containing a literal ``"`` would truncate ``prompt_body``. None do today.
_TASK_BARE_RE = re.compile(
    r'Task\s+subagent_type=(?P<st>\S+)\s+prompt="(?P<body>.*?)"',
    re.DOTALL,
)
_FM_LIST_ITEM_RE = re.compile(r"(?m)^  - (.*)$")


def _kv(frontmatter: str, key: str) -> str | None:
    m = re.search(rf"(?m)^{re.escape(key)}:\s*(.*)$", frontmatter)
    return m.group(1) if m else None


def _frontmatter_attrs(fm: str, kind: ArtifactKind) -> dict[str, Any]:
    if kind is ArtifactKind.COMMAND:
        items = _FM_LIST_ITEM_RE.findall(fm)
        return {
            "description": _kv(fm, "description"),
            "argument_hint": _kv(fm, "argument-hint"),
            "allowed_tools": items,
            "core_root_globs": sum("${CLAUDE_PLUGIN_ROOT}" in it for it in items),
            "has_task_entry": "Task" in items,
            "has_auq_entry": "AskUserQuestion" in items,
        }
    return {
        "name": _kv(fm, "name"),
        "description": _kv(fm, "description"),
        "model": _kv(fm, "model"),
    }


def _fenced_intervals(text: str) -> list[tuple[int, int]]:
    """Codepoint ranges of content inside ```` ``` ```` triple-fenced blocks.

    A line whose stripped form starts with ``` toggles fence state. The range
    spans from just after the opening marker line to the start of the closing
    marker line.
    """
    intervals: list[tuple[int, int]] = []
    in_fence = False
    region_start = 0
    offset = 0
    # splitlines() also breaks on U+2028/U+0085/etc.; acceptable here because
    # fence_context is best-effort attr metadata, not a byte-level operation.
    for line in text.splitlines(keepends=True):
        is_marker = line.strip().startswith("```")
        if is_marker:
            if not in_fence:
                in_fence = True
                region_start = offset + len(line)
            else:
                in_fence = False
                intervals.append((region_start, offset))
        offset += len(line)
    return intervals


def _inline_intervals(text: str) -> list[tuple[int, int]]:
    """Codepoint ranges of single-backtick inline-code spans."""
    return [m.span() for m in re.finditer(r"`[^`\n]+`", text)]


def _in_any(pos: int, intervals: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in intervals)


def extract(text: str, kind: ArtifactKind) -> list[Segment]:
    fenced = _fenced_intervals(text)
    inline = _inline_intervals(text)

    def fence_context(pos: int) -> str:
        if _in_any(pos, fenced):
            return "triple_fence"
        if _in_any(pos, inline):
            return "inline_code"
        return "none"

    # --- frontmatter (opaque, leading) ---
    matches: list[dict[str, Any]] = []
    fm_match = _FRONTMATTER_RE.match(text)
    body_start = 0
    if fm_match:
        body_start = fm_match.end()
        cat = (
            CAT_CMD_FRONTMATTER
            if kind is ArtifactKind.COMMAND
            else CAT_AGENT_FRONTMATTER
        )
        matches.append(
            {
                "start": fm_match.start(),
                "end": fm_match.end(),
                "category": cat,
                "attrs": _frontmatter_attrs(fm_match.group(0), kind),
            }
        )

    # --- body tokens ---
    for m in _CORE_ROOT_RE.finditer(text, body_start):
        before = text[: m.start()]
        # Best-effort role for Phase-2 metadata (does not affect bytes): the
        # flag form is the exact ``--plugin-root="${…}"`` spelling.
        role = "flag_value" if before.endswith('--plugin-root="') else "path_prefix"
        matches.append(
            {
                "start": m.start(),
                "end": m.end(),
                "category": CAT_CORE_ROOT,
                "attrs": {"role": role, "fence_context": fence_context(m.start())},
            }
        )
    for m in _ARGS_RE.finditer(text, body_start):
        matches.append(
            {
                "start": m.start(),
                "end": m.end(),
                "category": CAT_ARGS,
                "attrs": {"fence_context": fence_context(m.start())},
            }
        )
    for m in _AUQ_RE.finditer(text, body_start):
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[line_start : m.start()]
        after = text[m.end() : m.end() + 1]
        kind_attr = (
            "labeled-block"
            if prefix.strip() == "" and after == ":"
            else "prose-mention"
        )
        matches.append(
            {
                "start": m.start(),
                "end": m.end(),
                "category": CAT_AUQ,
                "attrs": {"occurrence_kind": kind_attr},
            }
        )
    for m in _MCP_RE.finditer(text, body_start):
        matches.append(
            {
                "start": m.start(),
                "end": m.end(),
                "category": CAT_MCP,
                "attrs": {"tool": m.group(0), "optional": True},
            }
        )
    for regex, variant in ((_TASK_PAREN_RE, "paren"), (_TASK_BARE_RE, "bare")):
        for m in regex.finditer(text, body_start):
            model = m.groupdict().get("model")
            matches.append(
                {
                    "start": m.start(),
                    "end": m.end(),
                    "category": CAT_TASK,
                    "attrs": {
                        "syntax_variant": variant,
                        "subagent_type": m.group("st"),
                        "model": model,
                        "is_template": bool(model and "<" in model),
                        "prompt_body": m.group("body"),
                        "fence_context": fence_context(m.start()),
                        "is_directive": True,
                    },
                }
            )

    return _assemble(text, matches)


def _assemble(text: str, matches: list[dict[str, Any]]) -> list[Segment]:
    """Resolve overlaps (containers win, contained tokens are subsumed) and
    weave NEUTRAL segments between the accepted tagged spans."""
    # Longest-at-a-start first, so a task_block is accepted before any point
    # token that falls inside it.
    matches.sort(key=lambda d: (d["start"], -(d["end"] - d["start"])))
    accepted: list[dict[str, Any]] = []
    cursor = 0
    for mt in matches:
        if mt["start"] < cursor:
            # Fully contained in the previous accepted span → subsume (e.g. a
            # point token inside a Task prompt body; it travels in prompt_body).
            # NOTE: a subsumed ACTIVE_CANONICAL token (CORE_ROOT) inside a Task
            # body loses its own canonical seam and is echoed as part of the
            # block for ALL harnesses — moot today (no such nesting exists), but
            # Phase 2 must re-scan captured prompt_body for nested tokens.
            if mt["end"] <= cursor:
                continue
            # Partial overlap would silently drop a harness-coupled tag — fail
            # loudly instead (completeness > leniency for a partitioner).
            raise AssertionError(
                f"partial overlap between tagged spans: {mt['category']} "
                f"{(mt['start'], mt['end'])} crosses boundary {cursor}"
            )
        accepted.append(mt)
        cursor = mt["end"]

    segments: list[Segment] = []
    pos = 0
    for mt in accepted:
        if mt["start"] > pos:
            segments.append(
                Segment(
                    category=NEUTRAL_CATEGORY,
                    tier=Tier.NEUTRAL,
                    original_text=text[pos : mt["start"]],
                    span=(pos, mt["start"]),
                    render_mode=RenderMode.ECHO,
                )
            )
        segments.append(
            Segment(
                category=mt["category"],
                tier=_TIER[mt["category"]],
                original_text=text[mt["start"] : mt["end"]],
                span=(mt["start"], mt["end"]),
                render_mode=_RENDER_MODE[mt["category"]],
                attrs=mt["attrs"],
            )
        )
        pos = mt["end"]
    if pos < len(text):
        segments.append(
            Segment(
                category=NEUTRAL_CATEGORY,
                tier=Tier.NEUTRAL,
                original_text=text[pos:],
                span=(pos, len(text)),
                render_mode=RenderMode.ECHO,
            )
        )
    return segments
