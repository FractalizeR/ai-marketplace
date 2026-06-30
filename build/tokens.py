"""Token registry — the single source of truth shared by extract, build, and
the completeness/no-leak test.

Every harness-coupled span the build knows about has one ``CategorySpec`` here.
The completeness test asserts: every category has a tier; every ACTIVE category
that can appear in body prose has a ``leak_pattern`` and a Claude renderer; and
no NEUTRAL segment text matches an ACTIVE ``leak_pattern`` (DEFERRED categories
are allow-listed and may appear in neutral prose).

Categories are keyed identically to ``extract.CAT_*`` so the modules cannot
drift apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from segments import Tier
from extract import (
    CAT_AGENT_FRONTMATTER,
    CAT_ARGS,
    CAT_AUQ,
    CAT_CMD_FRONTMATTER,
    CAT_CORE_ROOT,
    CAT_MCP,
    CAT_TASK,
)


@dataclass(frozen=True)
class CategorySpec:
    tier: Tier
    claude_renderer: str       # short description of how Claude renders it
    leak_pattern: str | None   # regex that must NOT appear in NEUTRAL text (None = positional/none)
    allow_leak: bool = False   # DEFERRED categories may appear in neutral prose


# Deferred (inventoried, not abstracted in Phase 1). Bare harness tool names and
# structured tool-calls double as ordinary English, so tagging them risks false
# positives; they pass through as neutral and are allow-listed in the no-leak scan.
CAT_DEFERRED_TOOLS = "deferred_tools"


REGISTRY: dict[str, CategorySpec] = {
    CAT_CORE_ROOT: CategorySpec(
        tier=Tier.ACTIVE_CANONICAL,
        claude_renderer="canonical constant ${CLAUDE_PLUGIN_ROOT}",
        leak_pattern=r"\$\{CLAUDE_PLUGIN_ROOT\}",
    ),
    CAT_ARGS: CategorySpec(
        tier=Tier.ACTIVE_PARSED,
        claude_renderer="echo $ARGUMENTS",
        leak_pattern=r"\$ARGUMENTS",
    ),
    CAT_CMD_FRONTMATTER: CategorySpec(
        tier=Tier.ACTIVE_PARSED,
        claude_renderer="echo (opaque leading frontmatter block)",
        leak_pattern=None,  # positional: only ever the leading segment
    ),
    CAT_AGENT_FRONTMATTER: CategorySpec(
        tier=Tier.ACTIVE_PARSED,
        claude_renderer="echo (opaque leading frontmatter block)",
        leak_pattern=None,
    ),
    CAT_TASK: CategorySpec(
        tier=Tier.ACTIVE_PARSED,
        claude_renderer="echo (full Task directive block)",
        leak_pattern=r"Task\(subagent_type=|Task\s+subagent_type=",
    ),
    CAT_AUQ: CategorySpec(
        tier=Tier.ACTIVE_PARSED,
        claude_renderer="echo AskUserQuestion",
        leak_pattern=r"AskUserQuestion",
    ),
    CAT_MCP: CategorySpec(
        tier=Tier.ACTIVE_PARSED,
        claude_renderer="echo mcp__…__… reference",
        leak_pattern=r"mcp__[A-Za-z0-9_]+__[A-Za-z0-9_*]+",
    ),
    CAT_DEFERRED_TOOLS: CategorySpec(
        tier=Tier.DEFERRED,
        claude_renderer="n/a (passthrough as neutral)",
        leak_pattern=None,
        allow_leak=True,
    ),
}


def active_leak_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """(category, compiled regex) pairs that must not appear in NEUTRAL text."""
    out = []
    for cat, spec in REGISTRY.items():
        if spec.allow_leak or spec.leak_pattern is None:
            continue
        out.append((cat, re.compile(spec.leak_pattern)))
    return out
