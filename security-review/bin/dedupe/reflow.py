"""Markdown reflow — wraps long prose lines while preserving structure.

Workers emit each paragraph as one physical line. This module re-wraps
to a target width while preserving fenced code, indented blocks, tables,
and headings.
"""

from __future__ import annotations

import re
import textwrap

DEFAULT_WRAP_WIDTH = 100

_FIELD_LINE_WRAP_RE = re.compile(r"^(\*\s+\*\*[^*]+\*\*\s*:\s+)(.*)$")
_BULLET_LINE_RE = re.compile(r"^([-*+]\s+)(.*)$")
_NUMBERED_LINE_RE = re.compile(r"^(\d+\.\s+)(.*)$")


def reflow_markdown(text: str, width: int = DEFAULT_WRAP_WIDTH) -> str:
    """Re-wrap long prose paragraphs to `width` chars while preserving
    markdown structure (fenced code, indented code / block scalars, tables,
    headers)."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        stripped = line.lstrip()
        indent_len = len(line) - len(stripped)

        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue

        if indent_len >= 4:
            out.append(line)
            continue

        if stripped.startswith("|") or stripped.startswith("#") or stripped == "" or stripped == "---":
            out.append(line)
            continue

        if len(line) <= width:
            out.append(line)
            continue

        base_indent = " " * indent_len
        m_field = _FIELD_LINE_WRAP_RE.match(stripped)
        m_bullet = _BULLET_LINE_RE.match(stripped)
        m_numbered = _NUMBERED_LINE_RE.match(stripped)

        if m_field:
            prefix = m_field.group(1)
            content = m_field.group(2)
            init_indent = base_indent + prefix
            sub_indent = base_indent + " " * len(prefix)
        elif m_bullet:
            prefix = m_bullet.group(1)
            content = m_bullet.group(2)
            init_indent = base_indent + prefix
            sub_indent = base_indent + " " * len(prefix)
        elif m_numbered:
            prefix = m_numbered.group(1)
            content = m_numbered.group(2)
            init_indent = base_indent + prefix
            sub_indent = base_indent + " " * len(prefix)
        else:
            content = stripped
            init_indent = base_indent
            sub_indent = base_indent

        wrapped = textwrap.fill(
            content,
            width=width,
            initial_indent=init_indent,
            subsequent_indent=sub_indent,
            break_long_words=False,
            break_on_hyphens=False,
        )
        out.append(wrapped)
    result = "\n".join(out)
    if text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result
