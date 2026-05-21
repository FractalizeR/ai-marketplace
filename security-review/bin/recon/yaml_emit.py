"""Strict-subset YAML dumper compatible with validate_context.parse_yaml_subset.

Emits:
- 2-space indent, block-style only (no flow except `[]` for empty list).
- `key: value` for scalars; `key:\\n  nested` for dict/list values.
- Block scalar `|` for multi-line strings.
- Double-quoted strings when they contain reserved tokens / specials / leading
  whitespace / look like booleans/null/numbers.

Round-trip guarantee: emit(d) → parse_yaml_subset → equals d, for any d that
uses only str / int / float / bool / None / dict / list (no empty dict, see
`_emit_dict` notes).
"""

from __future__ import annotations

import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def dump_yaml_subset(value: Any) -> str:
    """Dump value as YAML subset string. Result ends with `\\n`."""
    lines = _emit(value, 0)
    return "\n".join(lines) + ("\n" if lines else "")


def dump_frontmatter(value: Any) -> str:
    """Dump as `---\\n<yaml>\\n---\\n`."""
    return "---\n" + dump_yaml_subset(value) + "---\n"


# ---------------------------------------------------------------------------
# Emit core.
# ---------------------------------------------------------------------------


def _indent(level: int) -> str:
    return " " * level


def _emit(value: Any, indent: int) -> list[str]:
    if isinstance(value, dict):
        return _emit_dict(value, indent)
    if isinstance(value, list):
        return _emit_list(value, indent)
    return [_indent(indent) + _scalar_repr(value)]


def _emit_dict(d: dict, indent: int) -> list[str]:
    """Empty dict is forbidden (parser would round-trip it to None).

    Use status: unknown / data: null upstream instead.
    """
    if not d:
        raise ValueError("Empty dict is not representable in YAML subset; use null or omit the key")
    pad = _indent(indent)
    lines: list[str] = []
    for k, v in d.items():
        _validate_key(k)
        if isinstance(v, dict):
            if not v:
                # Round-trips as None; document this convention. We forbid here for clarity.
                raise ValueError(f"Empty dict value at key {k!r}: use null instead")
            lines.append(f"{pad}{k}:")
            lines.extend(_emit_dict(v, indent + 2))
        elif isinstance(v, list):
            if not v:
                lines.append(f"{pad}{k}: []")
            else:
                lines.append(f"{pad}{k}:")
                lines.extend(_emit_list(v, indent + 2))
        elif isinstance(v, str) and "\n" in v:
            lines.append(f"{pad}{k}: |")
            lines.extend(_emit_block_scalar(v, indent + 2))
        else:
            lines.append(f"{pad}{k}: {_scalar_repr(v)}")
    return lines


def _emit_list(items: list, indent: int) -> list[str]:
    pad = _indent(indent)
    out: list[str] = []
    for item in items:
        if isinstance(item, dict):
            if not item:
                raise ValueError("Cannot emit empty dict as list item")
            inner = _emit_dict(item, indent + 2)
            first = inner[0]
            # First inner line is "<indent+2>key: value" or "<indent+2>key:".
            # Splice it onto a "- " line.
            assert first.startswith(_indent(indent + 2)), f"unexpected indent on {first!r}"
            out.append(pad + "- " + first[indent + 2:])
            out.extend(inner[1:])
        elif isinstance(item, list):
            raise ValueError("Nested list as list item is not supported by YAML subset")
        elif isinstance(item, str) and "\n" in item:
            raise ValueError("Multiline string as scalar list item is not supported")
        else:
            out.append(f"{pad}- {_scalar_repr(item)}")
    return out


def _emit_block_scalar(s: str, indent: int) -> list[str]:
    """Emit lines for a `|` block scalar at the given indent."""
    pad = _indent(indent)
    out: list[str] = []
    for ln in s.split("\n"):
        out.append(f"{pad}{ln}" if ln else "")
    # parse_yaml_subset rstrips trailing newlines from block scalars; do not
    # emit a trailing empty line as the explicit value.
    while out and out[-1] == "":
        out.pop()
    return out


# ---------------------------------------------------------------------------
# Scalar repr.
# ---------------------------------------------------------------------------


# Keys may contain ASCII alphanumerics, underscore, and `-` (after the first
# char). Hyphen is required for kebab-case addon identifiers like
# `api-platform` used in `recon_bags.addon.<name>`. The matching regex in
# `validate_context.parse_yaml_subset._parse_dict` must accept the same shape;
# round-trip is tested in `test_yaml_emit.py::KebabCaseKeys`.
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

_RESERVED = frozenset({"true", "false", "yes", "no", "on", "off", "null", "~"})

_SPECIAL_CHARS = frozenset(":#[]{},&*!|>%@`")


def _validate_key(k: Any) -> None:
    if not isinstance(k, str) or not _KEY_RE.match(k):
        raise ValueError(f"Invalid YAML subset key: {k!r} (must match /^[A-Za-z_][A-Za-z0-9_-]*$/)")


def _scalar_repr(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, bool):
        # bool is a subclass of int; checked above.
        raise AssertionError("unreachable")
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # repr() preserves round-trip for finite floats; reject inf/nan
        # because parse_yaml_subset doesn't recognize them.
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError(f"Cannot emit non-finite float: {v}")
        return repr(v)
    if isinstance(v, str):
        return _string_repr(v)
    raise ValueError(f"Unsupported scalar type: {type(v).__name__}")


def _string_repr(s: str) -> str:
    if _needs_quoting(s):
        return _double_quoted(s)
    return s


def _needs_quoting(s: str) -> bool:
    if s == "":
        return True
    if s.strip() != s:
        return True
    if s.lower() in _RESERVED:
        return True
    # Numeric look-alike → would round-trip to int/float without quotes.
    try:
        int(s)
        return True
    except ValueError:
        pass
    try:
        float(s)
        return True
    except ValueError:
        pass
    if any(c in _SPECIAL_CHARS for c in s):
        return True
    if s[0] in "-?'\"":
        return True
    return False


def _double_quoted(s: str) -> str:
    if "\n" in s:
        raise ValueError("Newlines in scalar require block scalar; caller bug")
    # JSON-compatible escaping (YAML double-quoted is a superset of JSON strings).
    # ensure_ascii=False keeps Unicode literal — readable in CONTEXT.md.
    # Round-trip is guaranteed because parse_yaml_subset uses json.loads on "..." scalars.
    return json.dumps(s, ensure_ascii=False)
