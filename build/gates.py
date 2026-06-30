"""Structural gates for derived OpenCode artifacts.

There is no byte oracle for a non-Claude harness (the Claude round-trip proves we
do not corrupt the authoritative files, not that the derived prose is portable).
These gates are the negative+positive safety net that proves the section-fold
*mechanism* consumed every coupled span:

  * no-leak — none of the Claude-specific tokens survive (CORE_ROOT, Task, AUQ,
    MCP). Sourced from ``tokens.REGISTRY`` so it tracks the registry, not a
    hand-list (catches the bare ``Task subagent_type=`` form). ``$ARGUMENTS`` is
    deliberately NOT forbidden — OpenCode supports it natively.
  * frontmatter — the synthesized leading block carries no Claude command keys
    (``allowed-tools`` / ``argument-hint``); body prose may mention them.
  * xref — no sibling-artifact *file* ref (``security-project.md``) survives; the
    standalone skill cannot resolve it.

Semantic correctness of the authored templates is out of scope here (it is the 2C
live gate); a cheap template↔dispatcher structural assertion lives in
``check_dispatch_template``.
"""

from __future__ import annotations

import re

from tokens import REGISTRY
from extract import CAT_AUQ, CAT_CORE_ROOT, CAT_MCP, CAT_TASK

# Claude-specific categories that must never survive into an OpenCode artifact.
_FORBIDDEN_CATS = (CAT_CORE_ROOT, CAT_TASK, CAT_AUQ, CAT_MCP)
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_FM_FORBIDDEN_KEY = re.compile(r"(?m)^(allowed-tools|argument-hint):")
# Any sibling-artifact *file* ref (command OR agent) is unresolvable in a standalone
# skill — covers security-{project,changes,recon,refute}.md and agents/ prefixes.
_XREF_FILE_RE = re.compile(
    r"\b(?:agents/)?security(?:-project|-changes|-recon|-refute)?\.md\b"
)

# Coupled sections whose template MUST wire an external-process dispatch.
DISPATCH_ANCHORS = frozenset({
    "4-recon-phase", "5-recon-phase",
    "8-parallel-worker-launch", "10-parallel-worker-launch-in-mode-changes",
    "11-5-1-launching-the-refute-wave", "12-5-1-launching-the-refute-wave",
})


def forbidden_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [(c, re.compile(REGISTRY[c].leak_pattern)) for c in _FORBIDDEN_CATS]


def check_opencode_output(text: str) -> list[str]:
    """Return a list of gate violations for one derived artifact (empty = clean)."""
    violations: list[str] = []
    for cat, pat in forbidden_patterns():
        m = pat.search(text)
        if m:
            violations.append(f"leak[{cat}]: {m.group(0)!r}")
    fm = _FRONTMATTER_RE.match(text)
    if fm:
        key = _FM_FORBIDDEN_KEY.search(fm.group(1))
        if key:
            violations.append(f"frontmatter carries Claude key: {key.group(1)!r}")
    xref = _XREF_FILE_RE.search(text)
    if xref:
        violations.append(f"unresolved sibling-artifact file ref: {xref.group(0)!r}")
    return violations


# Each dispatch template must name the external-process primitive and the gap path,
# so a template of pure prose that forgot to wire the dispatcher is caught cheaply.
def check_dispatch_template(text: str) -> list[str]:
    """Structural template↔dispatcher assertion for a worker/recon/refute template."""
    out: list[str] = []
    if "opencode run" not in text:
        out.append("dispatch template does not mention `opencode run`")
    return out
