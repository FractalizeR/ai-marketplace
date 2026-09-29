"""Derive a Codex artifact from an authoritative Claude artifact, section by section.

A section is **templated** iff ``harness/codex/sections/<artifact>/<anchor>.md``
exists: its text is replaced wholesale by that authored template. Every other
section is rendered by:

  * frontmatter (the preamble's leading ``---`` block): a command becomes a Codex
    skill block (``name`` = artifact stem + the cleaned ``description``); an
    agent's is stripped (a Codex worker is a plain read-follow file);
  * token substitution: ``${CLAUDE_PLUGIN_ROOT}`` → ``${FR_SECURITY_CORE_ROOT}``,
    ``$ARGUMENTS`` / prose-mention ``AskUserQuestion`` / ``mcp__…__…`` → neutral
    phrases.

A labeled ``AskUserQuestion:`` block and a ``Task`` directive have no benign
rendering, so they are left untouched on purpose: outside a templated section
they reach the output and fail the no-leak gate (``gates.check_codex_output``).
Finally the orchestrator file ref is stripped from every section.

Each template starts with a ``<!-- source-sha256: <hex> -->`` line: the sha256 of
the Claude section it was authored against (never emitted). A mismatch means the
Claude prose changed under the template. After reviewing the template against the
new Claude section, record the new hashes with
``python3 build/build.py --mode=refresh-hashes``.

Template consistency is reported as problems (not raised): a template whose
anchor names no section (a renamed heading would otherwise silently fall back to
token rendering), an anchor naming several sections, a missing or stale source
hash, and a dispatch template that does not wire ``codex exec`` read-follow.
``template_set_problems`` adds a missing ``REQUIRED_TEMPLATES`` entry and a
template directory that names no artifact.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from gates import DISPATCH_ANCHORS, check_codex_dispatch_template
from sections import (
    FRONTMATTER_RE,
    Section,
    assert_section_partition,
    partition_sections,
)

CODEX_CORE_ROOT = "${FR_SECURITY_CORE_ROOT}"    # bundled-core placeholder; the operator exports it
CODEX_ARGS_PHRASE = "the invocation arguments"  # Codex has no $ARGUMENTS substitution
MCP_PHRASE = "a semantic IDE tool"
AUQ_PHRASE = "an interactive prompt"
_MAX_DESC = 1024

_TOKEN_RE = re.compile(
    r"(?P<core>\$\{CLAUDE_PLUGIN_ROOT\})"
    r"|(?P<args>\$ARGUMENTS)"
    r"|(?P<auq>AskUserQuestion)"
    r"|(?P<mcp>mcp__[A-Za-z0-9_]+__[A-Za-z0-9_*]+)"
)
_REPLACEMENT = {"core": CODEX_CORE_ROOT, "args": CODEX_ARGS_PHRASE,
                "auq": AUQ_PHRASE, "mcp": MCP_PHRASE}

# Only the ORCHESTRATOR file ref is stripped: a standalone skill body cannot
# resolve a sibling orchestrator. Agent-role refs (agents/*.md, security-recon.md)
# are real bundled read-follow files a Codex worker opens under
# ${FR_SECURITY_CORE_ROOT}/agents/ and must survive. The left guard `(?<![\w-])`
# only blocks a match inside a longer token; a fixed-length `agents/` lookbehind
# would spuriously spare `subagents/security-project.md`.
_CODEX_ORCH_XREF = re.compile(r"(?<![\w-])(security-project)\.md\b")


class ArtifactKind(enum.Enum):
    COMMAND = "command"
    AGENT = "agent"


def kind_for(path: Path) -> ArtifactKind:
    parent = path.parent.name
    if parent == "commands":
        return ArtifactKind.COMMAND
    if parent == "agents":
        return ArtifactKind.AGENT
    raise ValueError(f"artifact {path} is not under commands/ or agents/")


def strip_codex_xrefs(text: str) -> str:
    return _CODEX_ORCH_XREF.sub(r"\1", text)


def _is_labeled_auq(text: str, m: re.Match) -> bool:
    """``AskUserQuestion:`` alone at the start of its line (after indentation)."""
    line_start = text.rfind("\n", 0, m.start()) + 1
    return text[line_start:m.start()].strip() == "" and text[m.end():m.end() + 1] == ":"


def substitute_tokens(text: str) -> str:
    def repl(m: re.Match) -> str:
        if m.lastgroup == "auq" and _is_labeled_auq(text, m):
            return m.group(0)
        return _REPLACEMENT[m.lastgroup]
    return _TOKEN_RE.sub(repl, text)


def _frontmatter_value(frontmatter: str, key: str) -> str | None:
    m = re.search(rf"(?m)^{re.escape(key)}:\s*(.*)$", frontmatter)
    return m.group(1) if m else None


def _clean_description(raw: str | None) -> str:
    """Unwrap → length-bound → escape, so truncation never leaves an
    unterminated quoted scalar."""
    raw = raw or ""
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        value = raw[1:-1]
    else:
        value = raw
    if len(value) > _MAX_DESC:
        value = value[:_MAX_DESC].rsplit(" ", 1)[0]
    return value.replace("\\", "\\\\").replace('"', '\\"')


def skill_frontmatter(claude_frontmatter: str, *, name: str) -> str:
    desc = _clean_description(_frontmatter_value(claude_frontmatter, "description"))
    return f'---\nname: {name}\ndescription: "{desc}"\n---\n'


def render_untemplated(section: Section, *, kind: ArtifactKind, name: str) -> str:
    text = section.original_text
    head = ""
    fm = FRONTMATTER_RE.match(text) if section.span[0] == 0 else None
    if fm:
        if kind is ArtifactKind.COMMAND:
            head = skill_frontmatter(fm.group(0), name=name)
        text = text[fm.end():]
    return strip_codex_xrefs(head + substitute_tokens(text))


_HASH_HEADER_RE = re.compile(r"\A<!-- source-sha256: ([0-9a-f]{64}) -->\n")
REFRESH_HINT = ("review the template against the Claude section, then run "
                "`python3 build/build.py --mode=refresh-hashes`")


@dataclass(frozen=True)
class Template:
    path: Path
    source_sha256: str | None   # None = header missing
    body: str                   # what is emitted (header removed)


def section_sha256(section: Section) -> str:
    return hashlib.sha256(section.original_text.encode("utf-8")).hexdigest()


def hash_header(sha: str) -> str:
    return f"<!-- source-sha256: {sha} -->\n"


def parse_template(path: Path) -> Template:
    raw = path.read_text(encoding="utf-8")
    m = _HASH_HEADER_RE.match(raw)
    if m:
        return Template(path, m.group(1), raw[m.end():])
    return Template(path, None, raw)


# Sections the Codex skill must never inherit as Claude prose. Most of them hold
# no `Task` directive or labeled `AskUserQuestion:` block, so without this list a
# deleted template would pass the no-leak gate and ship the Claude text.
REQUIRED_TEMPLATES: dict[str, frozenset[str]] = {
    "security-project": frozenset({
        "3b-resolve-console-runner-environment-aware",
        "4-recon-phase",
        "6-optional-interactive-checkpoint",
        "8-parallel-worker-launch",
        "9-safety-net-progress-per-worker",
    }),
}


def template_set_problems(artifact_names: set[str], root: Path) -> list[str]:
    """Required templates that are missing, and template directories that name
    no artifact (a renamed or removed command/agent)."""
    problems: list[str] = []
    for name, anchors in sorted(REQUIRED_TEMPLATES.items()):
        if name not in artifact_names:
            problems.append(f"required templates are listed for {name}, "
                            f"which is not an artifact")
            continue
        present = {p.stem for p in (root / name).glob("*.md")}
        problems += [f"required template {name}/{a}.md is missing"
                     for a in sorted(anchors - present)]
    if root.is_dir():
        problems += [f"template directory {d.name}/ matches no artifact"
                     for d in sorted(root.iterdir())
                     if d.is_dir() and d.name not in artifact_names]
    return problems


def load_templates(artifact_name: str, root: Path) -> dict[str, Template]:
    """``{anchor: Template}`` for one artifact (empty if it has no templates)."""
    tdir = root / artifact_name
    if not tdir.is_dir():
        return {}
    return {p.stem: parse_template(p) for p in sorted(tdir.glob("*.md"))}


def _placement_problems(name: str, templates: dict[str, Template],
                        sections: list[Section]) -> list[str]:
    anchors = [s.section_anchor for s in sections]
    problems: list[str] = []
    for anchor in templates:
        count = anchors.count(anchor)
        if count == 0:
            problems.append(f"template {name}/{anchor}.md matches no section "
                            f"(heading renamed or removed?)")
        elif count > 1:
            problems.append(f"template {name}/{anchor}.md matches {count} sections")
    return problems


def derive_artifact(source: str, *, kind: ArtifactKind, name: str,
                    templates: dict[str, Template]) -> tuple[str, list[str]]:
    """Render one artifact; returns ``(text, template problems)``."""
    sections = partition_sections(source)
    assert_section_partition(sections, source)
    problems = _placement_problems(name, templates, sections)
    out: list[str] = []
    for sec in sections:
        tpl = templates.get(sec.section_anchor)
        if tpl is None:
            out.append(render_untemplated(sec, kind=kind, name=name))
            continue
        where = f"{name}/{sec.section_anchor}.md"
        if tpl.source_sha256 is None:
            problems.append(f"template {where} has no source-sha256 header; {REFRESH_HINT}")
        elif tpl.source_sha256 != section_sha256(sec):
            problems.append(f"template {where} is stale: its Claude section changed; "
                            f"{REFRESH_HINT}")
        rendered = strip_codex_xrefs(tpl.body)
        if sec.section_anchor in DISPATCH_ANCHORS:
            problems += [f"[{sec.section_anchor}]: {p}"
                         for p in check_codex_dispatch_template(rendered)]
        out.append(rendered)
    return "".join(out), problems


def refreshed_templates(source: str, *, name: str, templates: dict[str, Template]
                        ) -> tuple[dict[Path, str], list[str]]:
    """``({path: new file text}, problems)`` for templates whose header differs from
    the current source hash. Misplaced templates are reported, never rewritten."""
    sections = partition_sections(source)
    problems = _placement_problems(name, templates, sections)
    by_anchor = {s.section_anchor: s for s in sections}
    updates: dict[Path, str] = {}
    for anchor, tpl in templates.items():
        sec = by_anchor.get(anchor)
        if sec is None or problems:
            continue
        sha = section_sha256(sec)
        if tpl.source_sha256 != sha:
            updates[tpl.path] = hash_header(sha) + tpl.body
    return updates, problems
