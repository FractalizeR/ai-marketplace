"""Structural gates for derived Codex artifacts.

The derived prose has no byte oracle, so these gates are the safety net:

  * no-leak — none of the Claude-specific tokens survive (``${CLAUDE_PLUGIN_ROOT}``,
    a ``Task`` / ``Agent`` directive in either syntax, ``AskUserQuestion``, ``mcp__…``,
    ``$ARGUMENTS``). The derivation deliberately leaves a ``Task`` directive and a
    labeled ``AskUserQuestion:`` block untouched outside a templated section, so
    this scan is what fails a build whose templates do not cover them.
  * frontmatter — a skill carries non-empty ``name`` + ``description`` and no Claude
    command keys (``allowed-tools`` / ``argument-hint``); a worker agent carries none.
  * xref — no orchestrator *file* ref (``security-project.md``) survives; the
    standalone skill cannot resolve it.

Semantic correctness of the authored templates is out of scope here (it is the live
gate); a cheap template↔dispatcher structural assertion lives in
``check_codex_dispatch_template``.
"""

from __future__ import annotations

import re

# (label, pattern) of Claude-specific tokens that must never survive into a Codex
# artifact. Kept independent of the substitution in derive.py on purpose.
_LEAK_PATTERNS = (
    ("CORE_ROOT", re.compile(r"\$\{CLAUDE_PLUGIN_ROOT\}")),
    ("task_block", re.compile(r"\b(?:Task|Agent)\s*\(\s*subagent_type\s*=|\bTask\s+subagent_type=")),
    ("auq", re.compile(r"AskUserQuestion")),
    ("mcp_ref", re.compile(r"mcp__[A-Za-z0-9_]+__[A-Za-z0-9_*]+")),
    ("args_injection", re.compile(r"\$ARGUMENTS")),
)
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_FM_FORBIDDEN_KEY = re.compile(r"(?m)^(allowed-tools|argument-hint):")
# Codex worker prose is a bundled read-follow file, so agent-role refs
# (agents/*.md, security-recon.md) MUST survive; only the
# ORCHESTRATOR ref is unresolvable in a skill body (C1/E-C9).
_CODEX_ORCH_XREF_RE = re.compile(r"(?<![\w-])security-project\.md\b")
# [^\S\n] = inline whitespace only, so an empty `name:\n` value does not let \s*
# swallow the newline and capture the NEXT line's content as the value.
_SKILL_NAME_RE = re.compile(r"(?m)^name:[^\S\n]*(.*)$")
_SKILL_DESC_RE = re.compile(r"(?m)^description:[^\S\n]*(.*)$")

# Templated sections whose template MUST wire an external-process dispatch.
DISPATCH_ANCHORS = frozenset({
    "4-recon-phase",
    "8-parallel-worker-launch",
})


def _leak_violations(text: str) -> list[str]:
    out: list[str] = []
    for label, pat in _LEAK_PATTERNS:
        m = pat.search(text)
        if m:
            out.append(f"leak[{label}]: {m.group(0)!r}")
    return out


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
    violations = _leak_violations(text)
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


# Codex has no named agents: a worker gets its role prose by reading a bundled
# `agents/<role>.md` file and following it. The dispatch template must wire the
# full `codex exec` invocation with tiering, the composite-repo write dir, and a
# read-follow reference to that file.
_CODEX_AGENT_READFOLLOW_RE = re.compile(r"agents/security(?:-recon)?\.md")


def check_codex_dispatch_template(text: str) -> list[str]:
    """Structural template↔dispatcher assertion for a Codex worker/recon
    template (no ``--agent``; workers read+follow a bundled agent file)."""
    out: list[str] = []
    if "codex exec" not in text:
        out.append("dispatch template does not invoke `codex exec`")
    if "-m " not in text:
        out.append("dispatch template does not wire model tiering (`-m`)")
    # --add-dir is the composite-repo write invariant: review_root lies outside
    # project_root, and a workspace-write worker would otherwise fail to write its
    # wave file silently (M1-DS/E-C5 — a forgot-a-flag class).
    if "--add-dir" not in text:
        out.append("dispatch template does not grant the review_root write dir (`--add-dir`)")
    # -o <file> captures the worker's last message — the partial safety net every
    # role/worker template relies on for stdout-based recovery (E13).
    if "-o " not in text:
        out.append("dispatch template does not capture output for the safety net (`-o <file>`)")
    if not _CODEX_AGENT_READFOLLOW_RE.search(text):
        out.append("dispatch template has no read-follow ref to a bundled `agents/<role>.md`")
    # E-C10: a fan-out template is str.format-substituted by dispatch.py, so the
    # read-follow path must use the {core_root} placeholder — ${FR_SECURITY_CORE_ROOT}/agents/…
    # would raise `str.format` KeyError('FR_SECURITY_CORE_ROOT') before any process launches.
    if re.search(r"\$\{FR_SECURITY_CORE_ROOT\}/agents/", text):
        out.append("read-follow path uses ${FR_SECURITY_CORE_ROOT}/agents (str.format KeyError) — "
                   "use the {core_root} dispatch placeholder")
    return out
