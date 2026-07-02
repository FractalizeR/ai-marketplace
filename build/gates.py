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
from extract import CAT_ARGS, CAT_AUQ, CAT_CORE_ROOT, CAT_MCP, CAT_TASK

# Claude-specific categories that must never survive into an OpenCode artifact.
_FORBIDDEN_CATS = (CAT_CORE_ROOT, CAT_TASK, CAT_AUQ, CAT_MCP)
# Codex adds $ARGUMENTS (no Codex substitution → must render to a neutral phrase).
CODEX_FORBIDDEN_CATS = (CAT_CORE_ROOT, CAT_TASK, CAT_AUQ, CAT_MCP, CAT_ARGS)
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_FM_FORBIDDEN_KEY = re.compile(r"(?m)^(allowed-tools|argument-hint):")
# Any sibling-artifact *file* ref (command OR agent) is unresolvable in a standalone
# skill — covers security-{project,changes,recon,refute}.md and agents/ prefixes.
_XREF_FILE_RE = re.compile(
    r"\b(?:agents/)?security(?:-project|-changes|-recon|-refute)?\.md\b"
)
# Codex worker prose is a bundled read-follow file, so agent-role refs
# (agents/*.md, security-recon.md, security-refute.md) MUST survive; only the two
# ORCHESTRATOR refs are unresolvable in a skill body (C1/E-C9).
_CODEX_ORCH_XREF_RE = re.compile(r"(?<![\w-])security-(?:project|changes)\.md\b")
# [^\S\n] = inline whitespace only, so an empty `name:\n` value does not let \s*
# swallow the newline and capture the NEXT line's content as the value.
_SKILL_NAME_RE = re.compile(r"(?m)^name:[^\S\n]*(.*)$")
_SKILL_DESC_RE = re.compile(r"(?m)^description:[^\S\n]*(.*)$")

# Coupled sections whose template MUST wire an external-process dispatch.
DISPATCH_ANCHORS = frozenset({
    "4-recon-phase", "5-recon-phase",
    "8-parallel-worker-launch", "10-parallel-worker-launch-in-mode-changes",
    "11-5-1-launching-the-refute-wave", "12-5-1-launching-the-refute-wave",
})


def forbidden_patterns(cats=_FORBIDDEN_CATS) -> list[tuple[str, re.Pattern[str]]]:
    return [(c, re.compile(REGISTRY[c].leak_pattern)) for c in cats]


def _leak_violations(text: str, cats) -> list[str]:
    """No-leak scan sourced from ``tokens.REGISTRY`` (tracks the registry, not a
    hand-list) — harness-neutral so OpenCode and Codex share it (AC6)."""
    out: list[str] = []
    for cat, pat in forbidden_patterns(cats):
        m = pat.search(text)
        if m:
            out.append(f"leak[{cat}]: {m.group(0)!r}")
    return out


def check_opencode_output(text: str) -> list[str]:
    """Return a list of gate violations for one derived artifact (empty = clean)."""
    violations = _leak_violations(text, _FORBIDDEN_CATS)
    fm = _FRONTMATTER_RE.match(text)
    if fm:
        key = _FM_FORBIDDEN_KEY.search(fm.group(1))
        if key:
            violations.append(f"frontmatter carries Claude key: {key.group(1)!r}")
    xref = _XREF_FILE_RE.search(text)
    if xref:
        violations.append(f"unresolved sibling-artifact file ref: {xref.group(0)!r}")
    return violations


def _nonempty_value(match) -> bool:
    """A frontmatter scalar is non-empty after unwrapping optional quotes."""
    if match is None:
        return False
    val = match.group(1).strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
        val = val[1:-1]
    return bool(val.strip())


def check_codex_output(text: str, *, is_skill: bool) -> list[str]:
    """Structural gate for one derived Codex artifact (empty = clean).

    Codex has no byte oracle, so the frontmatter rule is the ONLY thing that would
    catch a synthesized-but-empty ``description`` (which 3A would pass yet 3B's
    ``validate_plugin.py`` would reject). ``is_skill`` distinguishes an orchestrator
    skill (must carry name+description frontmatter) from a worker agent (frontmatter
    stripped → must NOT begin with a Claude ``---`` block, E-C3)."""
    violations = _leak_violations(text, CODEX_FORBIDDEN_CATS)
    fm = _FRONTMATTER_RE.match(text)
    if is_skill:
        if not fm:
            violations.append("skill artifact missing leading frontmatter block")
        else:
            body = fm.group(1)
            if not _nonempty_value(_SKILL_NAME_RE.search(body)):
                violations.append("skill frontmatter missing non-empty `name`")
            if not _nonempty_value(_SKILL_DESC_RE.search(body)):
                violations.append("skill frontmatter missing non-empty `description`")
            key = _FM_FORBIDDEN_KEY.search(body)
            if key:
                violations.append(f"frontmatter carries Claude key: {key.group(1)!r}")
    elif fm:
        violations.append("worker agent must not begin with a frontmatter block "
                          "(Codex agent prose is stripped of Claude frontmatter)")
    xref = _CODEX_ORCH_XREF_RE.search(text)
    if xref:
        violations.append(f"unresolved orchestrator file ref: {xref.group(0)!r}")
    return violations


# Each dispatch template must wire the full external-process invocation, so a
# template of pure prose (or one that forgot the agent/model) is caught cheaply.
# These are the structural invariants every worker/recon/refute dispatch shares;
# the forwarded per-role fields (slice_id vs batch_index vs project_root) differ,
# so they are NOT asserted here (that would overfit per anchor).
def check_dispatch_template(text: str) -> list[str]:
    """Structural template↔dispatcher assertion for a worker/recon/refute template."""
    out: list[str] = []
    if "opencode run" not in text:
        out.append("dispatch template does not mention `opencode run`")
    if "--agent " not in text:
        out.append("dispatch template does not target a worker via `--agent <name>`")
    if "-m " not in text:
        out.append("dispatch template does not wire model tiering (`-m`)")
    return out


# Codex has no named agents: a worker gets its role prose by reading a bundled
# `agents/<role>.md` file and following it. The dispatch template must wire the
# full `codex exec` invocation with tiering, the composite-repo write dir, and a
# read-follow reference to that file.
_CODEX_AGENT_READFOLLOW_RE = re.compile(r"agents/security(?:-recon|-refute)?\.md")


def check_codex_dispatch_template(text: str) -> list[str]:
    """Structural template↔dispatcher assertion for a Codex worker/recon/refute
    template (no ``--agent``; workers read+follow a bundled agent file)."""
    out: list[str] = []
    if "codex exec" not in text:
        out.append("dispatch template does not invoke `codex exec`")
    if "-m " not in text:
        out.append("dispatch template does not wire model tiering (`-m`)")
    # --add-dir is the composite-repo write invariant: review_root lies outside
    # project_root, and a workspace-write worker would otherwise fail to write its
    # wave file silently (M1-DS/E-C5 — same forgot-a-flag class as the OpenCode `--`).
    if "--add-dir" not in text:
        out.append("dispatch template does not grant the review_root write dir (`--add-dir`)")
    # -o <file> captures the worker's last message — the partial safety net every
    # role/worker template relies on for stdout-based recovery (E13).
    if "-o " not in text:
        out.append("dispatch template does not capture output for the safety net (`-o <file>`)")
    if not _CODEX_AGENT_READFOLLOW_RE.search(text):
        out.append("dispatch template has no read-follow ref to a bundled `agents/<role>.md`")
    # E-C10: a fan-out template is str.format-substituted by dispatch.py, so the
    # read-follow path must use the {core_root} placeholder — ${CORE_ROOT}/agents/…
    # would raise `str.format` KeyError('CORE_ROOT') before any process launches.
    if re.search(r"\$\{CORE_ROOT\}/agents/", text):
        out.append("read-follow path uses ${CORE_ROOT}/agents (str.format KeyError) — "
                   "use the {core_root} dispatch placeholder")
    return out
