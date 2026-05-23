#!/usr/bin/env python3
"""Validate <review_root>/CONTEXT.md against schema v2.

Validations:
  1. Frontmatter — required keys, types, schema_version=2.
  2. Sections — every required core section present with anchor; valid status
     and shape (list or scalar). recon_bags bag validated against
     `RECON_BAGS_SCHEMA` of the recipe in `recipe_used`.
  3. Sanity probes — recipe-driven (probes from recipe.sanity_probes()):
     - Hallucination: declared files that don't exist on disk.
     - Coverage diff ladder (rev 3.5):
         diff ≤ 5 %    → ok
         5–20 %        → warning
         > 20 %        → error
  4. Ceiling policy: if frontmatter.recon_confidence.ceiling == "medium",
     level cannot be "high".

Exit codes:
  0 — valid (warnings allowed)
  1 — invalid (errors)
  2 — usage error

stdlib only. Backward-compat exports preserved for plan_waves until S5:
  SECTIONS, SECTION_TYPE_LIST, SECTION_TYPE_SCALAR — legacy v1 mapping.
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# YAML subset parser (shared with yaml_emit, plan_waves).
# ---------------------------------------------------------------------------

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
ANCHOR_RE = re.compile(r"<!--\s*section_id:\s*([a-z_]+)\s*-->")
FENCED_YAML_RE = re.compile(r"```yaml\s*\n(.*?)\n```", re.DOTALL)


class YamlSubsetError(ValueError):
    pass


def parse_yaml_subset(text: str) -> dict:
    lines = text.splitlines()
    pos = 0
    root, end_pos = _parse_block(lines, pos, 0)
    for i in range(end_pos, len(lines)):
        if lines[i].strip() and not lines[i].lstrip().startswith("#"):
            raise YamlSubsetError(f"Unexpected content after document end at line {i + 1}: {lines[i]!r}")
    return root


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_blank_or_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _parse_block(lines, pos, indent):
    while pos < len(lines) and _is_blank_or_comment(lines[pos]):
        pos += 1
    if pos >= len(lines):
        return {}, pos
    first = lines[pos]
    first_indent = _line_indent(first)
    if first_indent < indent:
        return {}, pos
    stripped = first.lstrip(" ")
    if stripped.startswith("- "):
        return _parse_list(lines, pos, first_indent)
    return _parse_dict(lines, pos, first_indent)


def _parse_dict(lines, pos, indent):
    result: dict = {}
    while pos < len(lines):
        line = lines[pos]
        if _is_blank_or_comment(line):
            pos += 1
            continue
        cur_indent = _line_indent(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlSubsetError(f"Unexpected indent at line {pos + 1}: {line!r}")
        content = line[indent:]
        # Keys: ASCII alnum + `_`, with `-` allowed after the first character
        # to support kebab-case addon identifiers (e.g. `api-platform`) used in
        # `recon_bags.addon.<name>`. Mirrors `recon.yaml_emit._KEY_RE`.
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$", content)
        if not m:
            raise YamlSubsetError(f"Expected key at line {pos + 1}: {line!r}")
        key, rest = m.group(1), m.group(2)
        if rest.strip() in ("|", "|-", "|+", ">", ">-", ">+"):
            pos += 1
            block_lines = []
            block_indent = None
            while pos < len(lines):
                blline = lines[pos]
                if not blline.strip():
                    block_lines.append("")
                    pos += 1
                    continue
                li = _line_indent(blline)
                if li <= indent:
                    break
                if block_indent is None:
                    block_indent = li
                block_lines.append(blline[block_indent:])
                pos += 1
            result[key] = "\n".join(block_lines).rstrip()
            continue
        if rest == "":
            pos += 1
            peek = pos
            while peek < len(lines) and _is_blank_or_comment(lines[peek]):
                peek += 1
            if peek >= len(lines):
                result[key] = None
                continue
            next_indent = _line_indent(lines[peek])
            if next_indent <= indent:
                result[key] = None
                continue
            nested, pos = _parse_block(lines, pos, next_indent)
            result[key] = nested
            continue
        result[key] = _parse_scalar(rest)
        pos += 1
    return result, pos


def _parse_list(lines, pos, indent):
    result: list = []
    while pos < len(lines):
        line = lines[pos]
        if _is_blank_or_comment(line):
            pos += 1
            continue
        cur_indent = _line_indent(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlSubsetError(f"Unexpected indent inside list at line {pos + 1}: {line!r}")
        stripped = line[indent:]
        if not stripped.startswith("- "):
            break
        item_text = stripped[2:]
        if ":" in item_text and re.match(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:", item_text):
            mini_indent = indent + 2
            synthetic_line = " " * mini_indent + item_text
            patched = lines[:pos] + [synthetic_line] + lines[pos + 1:]
            nested, new_pos = _parse_dict(patched, pos, mini_indent)
            result.append(nested)
            pos = new_pos
            continue
        result.append(_parse_scalar(item_text))
        pos += 1
    return result, pos


SCALAR_TRUE = {"true", "yes", "on"}
SCALAR_FALSE = {"false", "no", "off"}
SCALAR_NULL = {"null", "~", ""}


def _parse_scalar(raw):
    s = raw.strip()
    if s and not s.startswith(('"', "'", "[")):
        m = re.search(r"\s+#", s)
        if m:
            s = s[:m.start()].strip()
    if not s:
        return None
    if s.startswith('"') and s.endswith('"'):
        # Double-quoted is JSON-compatible (yaml_emit guarantees this).
        # `unicode_escape` would mangle Unicode (e.g. Cyrillic), so decode via JSON.
        try:
            return json.loads(s)
        except json.JSONDecodeError as exc:
            raise YamlSubsetError(f"Invalid double-quoted string: {s!r} ({exc})") from exc
    if s.startswith("'") and s.endswith("'"):
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        parts = [p.strip() for p in inner.split(",")]
        return [_parse_scalar(p) for p in parts]
    low = s.lower()
    if low in SCALAR_NULL:
        return None
    if low in SCALAR_TRUE:
        return True
    if low in SCALAR_FALSE:
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


# ---------------------------------------------------------------------------
# Section extraction.
# ---------------------------------------------------------------------------


@dataclass
class ParsedSection:
    section_id: str
    body: str


def extract_sections(text: str) -> dict[str, ParsedSection]:
    """Walk markdown body, find anchor comments, map section_id → body.
    Tolerant: anchor may appear after `## heading` OR up to 3 lines before.
    """
    m = FRONTMATTER_RE.match(text)
    body = text[m.end():] if m else text
    result: dict[str, ParsedSection] = {}
    pattern = re.compile(r"^##\s+.*?$", re.MULTILINE)
    matches = list(pattern.finditer(body))
    for i, hm in enumerate(matches):
        heading_start = hm.start()
        section_content_start = hm.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        section_body = body[section_content_start:end]
        anchor = ANCHOR_RE.search(section_body)
        if not anchor:
            prev_end = matches[i - 1].end() if i > 0 else 0
            pre_heading = body[prev_end:heading_start]
            pre_lines = [ln for ln in pre_heading.splitlines() if ln.strip()]
            tail = "\n".join(pre_lines[-3:]) if pre_lines else ""
            anchor = ANCHOR_RE.search(tail)
        if not anchor:
            continue
        section_id = anchor.group(1)
        result[section_id] = ParsedSection(section_id=section_id, body=section_body)
    return result


# ---------------------------------------------------------------------------
# v2 schema.
# ---------------------------------------------------------------------------

SECTION_TYPE_LIST = "list"
SECTION_TYPE_SCALAR = "scalar"

# Core sections in schema v2 — section_id → (shape, required).
CORE_SECTIONS_V2: dict[str, tuple[str, bool]] = {
    "attack_surface":   (SECTION_TYPE_LIST, True),
    "data_access":      (SECTION_TYPE_LIST, True),
    "auth_layer":       (SECTION_TYPE_SCALAR, True),
    "authz_usage":      (SECTION_TYPE_LIST, True),
    "output_renderers": (SECTION_TYPE_LIST, True),
    "serialization":    (SECTION_TYPE_LIST, True),
    "file_operations":  (SECTION_TYPE_LIST, True),
    "http_clients":     (SECTION_TYPE_LIST, True),
    "secrets":          (SECTION_TYPE_SCALAR, True),
    "fintech_markers":  (SECTION_TYPE_LIST, True),
    "frontend_assets":  (SECTION_TYPE_LIST, True),
}

# Frontmatter keys required for schema v2.
V2_FRONTMATTER_REQUIRED = {
    "schema_version", "generated_at", "git_rev",
    "project_fingerprint", "code_fingerprint", "scope",
    "stack", "recipe_used", "tool_versions",
    "sources_used", "missing_sections", "recon_confidence",
}

V2_VALID_STATUSES = {"ok", "unknown", "none", "pending_enrichment"}
V2_CONFIDENCE_LEVELS = {"high", "medium", "low"}
V2_CEILING_LEVELS = {"high", "medium", "low"}

# Allowed `environment.console_mode` values (frontmatter.environment, optional;
# 4.x). Mirrors recon.sandbox.ConsoleRunner.mode. The block is optional so
# pre-4.x CONTEXT.md files (and --skip-recon against them) still validate.
V2_CONSOLE_MODES = {"host", "container", "custom", "disabled"}

# Allowed capability_flag values (frontmatter.capabilities). Free-form keys,
# enum values. See plan §1.7.
V2_CAPABILITY_VALUES = {
    "emitted",
    "not_supported_by_recipe",
    "recipe_failed",
    "not_applicable",
}

# Allowed values for `schema_revision` minor (frontmatter, optional). Bound
# upper limit defensively — should be small ints (1, 2, ...).
V2_SCHEMA_REVISION_MIN = 1
V2_SCHEMA_REVISION_MAX = 99

# 3.4.0 transitional allowlist — emptied in Wave 2.5 once symfony + laravel
# recipes declared `routes_authz_matrix`, `sensitive_columns`, `runtime` in
# their RECON_BAGS_SCHEMA. Kept as an empty set so callers may add
# future transitional keys without re-introducing the constant.
FUTURE_FRAMEWORK_KEYS_3_4: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# LEGACY v1 schema — retained for plan_waves.py until S5 rewrite.
# Do NOT use for new code; uses CORE_SECTIONS_V2 directly.
# ---------------------------------------------------------------------------

LEGACY_SECTIONS_V1: dict[str, tuple[str, bool]] = {
    "stack": (SECTION_TYPE_SCALAR, True),
    "http_entry_points": (SECTION_TYPE_LIST, True),
    "console_commands": (SECTION_TYPE_LIST, True),
    "messenger_handlers": (SECTION_TYPE_LIST, True),
    "event_listeners": (SECTION_TYPE_LIST, True),
    "doctrine_kernel_listeners": (SECTION_TYPE_LIST, True),
    "auth_layer": (SECTION_TYPE_SCALAR, True),
    "voters": (SECTION_TYPE_LIST, True),
    "authz_usage": (SECTION_TYPE_LIST, True),
    "repositories": (SECTION_TYPE_LIST, True),
    "forms": (SECTION_TYPE_LIST, True),
    "serializer": (SECTION_TYPE_LIST, True),
    "file_operations": (SECTION_TYPE_LIST, True),
    "http_client": (SECTION_TYPE_LIST, True),
    "twig_overrides": (SECTION_TYPE_SCALAR, True),
    "twig_templates": (SECTION_TYPE_LIST, True),
    "frontend_assets": (SECTION_TYPE_LIST, True),
    "security_parameters": (SECTION_TYPE_SCALAR, True),
    "fintech_markers": (SECTION_TYPE_LIST, True),
    "user_overrides": (SECTION_TYPE_SCALAR, False),
}
SECTIONS = LEGACY_SECTIONS_V1  # back-compat alias


# ---------------------------------------------------------------------------
# Validation result.
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------------------
# Frontmatter validation (v2).
# ---------------------------------------------------------------------------


def _validate_environment_block(env: object, res: ValidationResult) -> None:
    """Validate the optional `environment` frontmatter block (4.x).

    Shape: {containerized: bool, host_php_present: bool,
            host_php_version: str|null, console_mode: <enum>,
            console_gap: bool, console_gap_reason: str|null,
            container_signals?: list[str]}.
    """
    if not isinstance(env, dict):
        res.errors.append(f"frontmatter.environment must be a mapping, got: {type(env).__name__}")
        return
    for key in ("containerized", "console_gap"):
        v = env.get(key)
        if not isinstance(v, bool):
            res.errors.append(f"frontmatter.environment.{key} must be a bool, got: {v!r}")
    # host_php_present may be absent in hand-written/old blocks; check if present.
    if "host_php_present" in env and not isinstance(env.get("host_php_present"), bool):
        res.errors.append(
            f"frontmatter.environment.host_php_present must be a bool, got: {env.get('host_php_present')!r}"
        )
    mode = env.get("console_mode")
    if mode not in V2_CONSOLE_MODES:
        res.errors.append(
            f"frontmatter.environment.console_mode must be one of {sorted(V2_CONSOLE_MODES)}, got: {mode!r}"
        )
    for key in ("host_php_version", "console_gap_reason"):
        v = env.get(key)
        if v is not None and not isinstance(v, str):
            res.errors.append(f"frontmatter.environment.{key} must be a string or null, got: {v!r}")
    sig = env.get("container_signals")
    if sig is not None:
        if not isinstance(sig, list) or not all(isinstance(s, str) for s in sig):
            res.errors.append("frontmatter.environment.container_signals must be a list of strings")


def _validate_frontmatter_v2(text: str, res: ValidationResult) -> Optional[dict]:
    m = FRONTMATTER_RE.match(text)
    if not m:
        res.errors.append("Missing frontmatter (expected leading `---\\n...\\n---\\n`)")
        return None
    try:
        fm = parse_yaml_subset(m.group(1))
    except YamlSubsetError as exc:
        res.errors.append(f"Frontmatter parse error: {exc}")
        return None
    if not isinstance(fm, dict):
        res.errors.append("Frontmatter root is not a mapping")
        return None

    sv = fm.get("schema_version")
    if sv != 2:
        res.errors.append(
            f"schema_version must be 2 (got {sv!r}). "
            "v3 does not support v1 contexts; rerun recon to regenerate."
        )
        # L1: don't early-return — keep validating against v2 expectations so
        # the user sees all issues in one pass. Old v1 sections will fail their
        # own shape checks below, which is fine signal for a dedicated rerun.

    # schema_revision: optional minor version. Absent → assume revision 1
    # (3.3.0 contract). Present must be int in [V2_SCHEMA_REVISION_MIN,
    # V2_SCHEMA_REVISION_MAX].
    if "schema_revision" in fm:
        sr = fm.get("schema_revision")
        # bool is a subclass of int — reject explicitly to avoid `True == 1`
        # silently passing.
        if isinstance(sr, bool) or not isinstance(sr, int):
            res.errors.append(
                f"schema_revision must be int "
                f"({V2_SCHEMA_REVISION_MIN}..{V2_SCHEMA_REVISION_MAX}), got: {sr!r}"
            )
        elif not (V2_SCHEMA_REVISION_MIN <= sr <= V2_SCHEMA_REVISION_MAX):
            res.errors.append(
                f"schema_revision out of range "
                f"[{V2_SCHEMA_REVISION_MIN}..{V2_SCHEMA_REVISION_MAX}], got: {sr}"
            )

    # capabilities: optional dict, free-form keys, enum values from
    # V2_CAPABILITY_VALUES. Used to declare which optional sections the recipe
    # emitted vs. skipped — feeds operator triage.
    if "capabilities" in fm:
        caps = fm.get("capabilities")
        if not isinstance(caps, dict):
            res.errors.append(
                f"capabilities must be a mapping, got: {type(caps).__name__}"
            )
        else:
            for k, v in caps.items():
                if not isinstance(v, str) or v not in V2_CAPABILITY_VALUES:
                    res.errors.append(
                        f"capabilities.{k} must be one of "
                        f"{sorted(V2_CAPABILITY_VALUES)}, got: {v!r}"
                    )

    for k in sorted(V2_FRONTMATTER_REQUIRED - set(fm.keys())):
        res.errors.append(f"Frontmatter missing required key: {k}")

    # stack block.
    stack = fm.get("stack")
    if isinstance(stack, dict):
        for k in ("language", "framework"):
            if k not in stack:
                res.errors.append(f"frontmatter.stack missing key: {k}")
        # Optional addons / integrations: must be lists of strings if present.
        # Missing keys are treated as empty list (no error).
        for opt_key in ("addons", "integrations"):
            v = stack.get(opt_key)
            if v is None:
                continue
            if not isinstance(v, list):
                res.errors.append(
                    f"frontmatter.stack.{opt_key} must be a list of strings, got {type(v).__name__}"
                )
                continue
            for i, item in enumerate(v):
                if not isinstance(item, str):
                    res.errors.append(
                        f"frontmatter.stack.{opt_key}[{i}] must be a string, got {type(item).__name__}"
                    )
    elif "stack" in fm:
        res.errors.append(f"frontmatter.stack must be a mapping, got {type(stack).__name__}")

    # tool_versions.
    tv = fm.get("tool_versions")
    if tv is not None and not isinstance(tv, dict):
        res.errors.append(f"tool_versions must be a mapping, got: {type(tv).__name__}")

    # environment block (optional, 4.x). Records console-runner resolution and
    # any coverage gap. Validate shape only when present — pre-4.x contexts omit
    # it and must keep validating.
    if "environment" in fm:
        _validate_environment_block(fm.get("environment"), res)

    # sources_used / missing_sections.
    for key in ("sources_used", "missing_sections"):
        v = fm.get(key)
        if v is not None and not isinstance(v, list):
            res.errors.append(f"{key} must be a list, got: {type(v).__name__}")

    # recon_confidence (string OR dict {level, ceiling}).
    rc = fm.get("recon_confidence")
    if isinstance(rc, str):
        if rc not in V2_CONFIDENCE_LEVELS:
            res.errors.append(f"recon_confidence (string) must be one of {sorted(V2_CONFIDENCE_LEVELS)}, got: {rc!r}")
    elif isinstance(rc, dict):
        level = rc.get("level")
        ceiling = rc.get("ceiling")
        if level not in V2_CONFIDENCE_LEVELS:
            res.errors.append(f"recon_confidence.level invalid: {level!r}")
        if ceiling is not None and ceiling not in V2_CEILING_LEVELS:
            res.errors.append(f"recon_confidence.ceiling invalid: {ceiling!r}")
        if ceiling == "medium" and level == "high":
            res.errors.append("recon_confidence.level=high but ceiling=medium — invalid (ceiling clamps level)")
        if ceiling == "low" and level in ("high", "medium"):
            res.errors.append("recon_confidence.level above ceiling=low — invalid")
    elif "recon_confidence" in fm:
        res.errors.append(f"recon_confidence must be string or mapping, got: {type(rc).__name__}")

    return fm


# ---------------------------------------------------------------------------
# Section validation (v2).
# ---------------------------------------------------------------------------


def _section_payload(section_body: str) -> Optional[dict]:
    fence = FENCED_YAML_RE.search(section_body)
    if not fence:
        return None
    try:
        payload = parse_yaml_subset(fence.group(1))
    except YamlSubsetError:
        return None
    return payload if isinstance(payload, dict) else None


def _validate_payload_shape(
    section_id: str, expected_type: str, payload: dict, res: ValidationResult
) -> None:
    status = payload.get("status")
    if status is None:
        res.errors.append(f"Section '{section_id}': missing 'status' key")
        return
    if status not in V2_VALID_STATUSES:
        res.errors.append(
            f"Section '{section_id}': invalid status {status!r} "
            f"(expected one of {sorted(V2_VALID_STATUSES)})"
        )
        return
    if status == "unknown":
        if "reason" not in payload:
            res.errors.append(f"Section '{section_id}': status=unknown requires 'reason'")
        return
    if status == "pending_enrichment":
        if "enrichment_hint" not in payload:
            res.errors.append(f"Section '{section_id}': status=pending_enrichment requires 'enrichment_hint'")
        return
    if status == "none":
        return  # valid empty marker
    # status == "ok"
    if expected_type == SECTION_TYPE_LIST:
        items = payload.get("items")
        if items is None:
            res.errors.append(f"Section '{section_id}': list-type status=ok requires 'items'")
        elif not isinstance(items, list):
            res.errors.append(f"Section '{section_id}': 'items' must be a list")
    elif expected_type == SECTION_TYPE_SCALAR:
        data = payload.get("data")
        if data is None:
            res.errors.append(f"Section '{section_id}': scalar-type status=ok requires 'data'")
        elif not isinstance(data, dict):
            res.errors.append(f"Section '{section_id}': 'data' must be a mapping")
        # M7: scalar sections must declare `source_files` (rev 3.4 mode=changes
        # channel 2). Allows plan_waves to detect config-only diffs.
        sf = payload.get("source_files")
        if sf is None:
            res.errors.append(
                f"Section '{section_id}': scalar-type status=ok requires 'source_files' "
                "(list of config files used to derive `data`)"
            )
        elif not isinstance(sf, list):
            res.errors.append(f"Section '{section_id}': 'source_files' must be a list")


def _validate_core_sections(text: str, res: ValidationResult) -> None:
    sections = extract_sections(text)
    for section_id, (expected_type, required) in CORE_SECTIONS_V2.items():
        if section_id not in sections:
            if required:
                res.errors.append(f"Missing required section anchor: {section_id}")
            continue
        payload = _section_payload(sections[section_id].body)
        if payload is None:
            res.errors.append(f"Section '{section_id}': cannot parse fenced yaml block")
            continue
        _validate_payload_shape(section_id, expected_type, payload, res)


def _validate_recon_bags(
    text: str, fm: dict, res: ValidationResult,
    recipe_loader=None,
) -> None:
    """Validate the recon_bags section against the recipe's 3-level schema.

    Expected shape on disk:
        recon_bags:
          stack:
            <stack_name>:                 # e.g. symfony, laravel
              <bag_key>: SectionPayload
          addon:
            <addon_name>:                 # e.g. easyadmin, sonata
              <bag_key>: SectionPayload
          integration:
            <integration_name>:           # placeholder for Stage 4+
              <bag_key>: SectionPayload

    The recipe's RECON_BAGS_SCHEMA must mirror this shape exactly:
        {kind: {name: {bag_key: SectionSpec}}}

    Unknown kinds / names / keys → error (closed schema). Missing
    required keys → error.
    """
    sections = extract_sections(text)
    fs = sections.get("recon_bags")
    if fs is None:
        # Allowed when recipe has no RECON_BAGS_SCHEMA (e.g. generic_php).
        return
    payload = _section_payload(fs.body)
    if payload is None:
        res.errors.append("Section 'recon_bags': cannot parse fenced yaml block")
        return
    recipe_used = fm.get("recipe_used")
    if not isinstance(recipe_used, str) or recipe_used in (None, "", "none"):
        res.warnings.append("recon_bags present but no recipe_used in frontmatter; skipping bag validation")
        return
    schema, schema_err = _load_recipe_schema(recipe_used, recipe_loader)
    if schema is None:
        detail = f": {schema_err}" if schema_err else ""
        res.warnings.append(f"could not load RECON_BAGS_SCHEMA for recipe '{recipe_used}'{detail}")
        return
    if not isinstance(schema, dict):
        res.warnings.append(
            f"RECON_BAGS_SCHEMA for recipe '{recipe_used}' is not a mapping; skipping bag validation"
        )
        return

    # Allowed kinds and which kinds the schema declares.
    allowed_kinds = {"stack", "addon", "integration"}
    schema_kinds = set(schema.keys())
    unknown_schema_kinds = schema_kinds - allowed_kinds
    if unknown_schema_kinds:
        res.warnings.append(
            f"recipe '{recipe_used}' RECON_BAGS_SCHEMA declares unknown kinds "
            f"{sorted(unknown_schema_kinds)} (allowed: {sorted(allowed_kinds)})"
        )

    # 1. Required keys present (walk schema).
    for kind, names in schema.items():
        if not isinstance(names, dict):
            continue
        for name, bag_keys in names.items():
            if not isinstance(bag_keys, dict):
                continue
            payload_bag = (
                payload.get(kind, {}).get(name, {})
                if isinstance(payload.get(kind), dict) else {}
            )
            if not isinstance(payload_bag, dict):
                payload_bag = {}
            for key, spec in bag_keys.items():
                if spec.required and key not in payload_bag:
                    res.errors.append(
                        f"recon_bags.{kind}.{name}.{key} required by recipe schema but missing"
                    )

    # 2. Walk emitted payload, validate each leaf against the schema.
    for kind, names in payload.items():
        if kind not in allowed_kinds:
            res.errors.append(
                f"recon_bags.{kind} is not an allowed kind "
                f"(allowed: {sorted(allowed_kinds)})"
            )
            continue
        if not isinstance(names, dict):
            res.errors.append(f"recon_bags.{kind} must be a mapping")
            continue
        schema_for_kind = schema.get(kind, {}) if isinstance(schema.get(kind), dict) else {}
        for name, bag in names.items():
            if name not in schema_for_kind:
                res.errors.append(
                    f"recon_bags.{kind}.{name} is not declared in recipe schema "
                    f"(allowed: {sorted(schema_for_kind.keys())})"
                )
                continue
            if not isinstance(bag, dict):
                res.errors.append(f"recon_bags.{kind}.{name} must be a mapping")
                continue
            bag_schema = schema_for_kind[name]
            if not isinstance(bag_schema, dict):
                continue
            for key, sub_payload in bag.items():
                if key not in bag_schema:
                    if key in FUTURE_FRAMEWORK_KEYS_3_4:
                        res.warnings.append(
                            f"recon_bags.{kind}.{name}.{key} is not declared in "
                            f"recipe schema yet (transitional 3.4.0 allowlist)"
                        )
                        continue
                    res.errors.append(
                        f"recon_bags.{kind}.{name}.{key} is not declared in recipe schema "
                        f"(allowed keys: {sorted(bag_schema.keys())})"
                    )
                    continue
                spec = bag_schema[key]
                if not isinstance(sub_payload, dict):
                    res.errors.append(f"recon_bags.{kind}.{name}.{key} must be a mapping")
                    continue
                expected_shape = SECTION_TYPE_LIST if spec.shape == "list" else SECTION_TYPE_SCALAR
                section_label = f"recon_bags.{kind}.{name}.{key}"
                _validate_payload_shape(section_label, expected_shape, sub_payload, res)
                # Per-item / per-data key validation when status=ok.
                if sub_payload.get("status") == "ok":
                    if spec.shape == "list" and spec.item_keys is not None:
                        items = sub_payload.get("items", [])
                        if isinstance(items, list):
                            for idx, item in enumerate(items):
                                if not isinstance(item, dict):
                                    continue
                                unknown = set(item.keys()) - spec.item_keys
                                if unknown:
                                    res.warnings.append(
                                        f"{section_label}.items[{idx}]: unknown keys {sorted(unknown)} "
                                        f"(allowed: {sorted(spec.item_keys)})"
                                    )
                    elif spec.shape == "scalar" and spec.data_keys is not None:
                        data = sub_payload.get("data", {})
                        if isinstance(data, dict):
                            unknown = set(data.keys()) - spec.data_keys
                            if unknown:
                                res.warnings.append(
                                    f"{section_label}.data: unknown keys {sorted(unknown)} "
                                    f"(allowed: {sorted(spec.data_keys)})"
                                )


def _load_recipe_schema(recipe_used: str, recipe_loader=None):
    """Return (RECON_BAGS_SCHEMA dict | None, error_message | None)."""
    try:
        if recipe_loader is not None:
            mod = recipe_loader(recipe_used)
        else:
            mod = importlib.import_module(f"recon.recipes.{recipe_used}")
    except (ModuleNotFoundError, ImportError) as e:
        return None, f"import error: {e}"
    schema = getattr(mod, "RECON_BAGS_SCHEMA", None)
    return schema, None


# ---------------------------------------------------------------------------
# Sanity probes (recipe-driven).
# ---------------------------------------------------------------------------


# Coverage diff ladder (rev 3.5).
COVERAGE_OK_THRESHOLD = 0.05      # diff ≤ 5 %
COVERAGE_WARN_THRESHOLD = 0.20    # 5 % < diff ≤ 20 % → warn; > 20 % → error


def _payload_at_path(text: str, section_path: str) -> Optional[dict]:
    """Resolve dot-notation path to a payload dict.

    "attack_surface"                      → top-level core section payload.
    "recon_bags.stack.symfony.voters"  → nested key under recon_bags.
    """
    parts = section_path.split(".")
    sections = extract_sections(text)
    if len(parts) == 1:
        sec = sections.get(parts[0])
        if sec is None:
            return None
        return _section_payload(sec.body)
    fs = sections.get(parts[0])
    if fs is None:
        return None
    payload = _section_payload(fs.body)
    cur = payload
    for p in parts[1:]:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur if isinstance(cur, dict) else None


def _declared_files(payload: dict, kind_filter: Optional[str] = None) -> set[str]:
    items = payload.get("items")
    if not isinstance(items, list):
        return set()
    out = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        if kind_filter is not None and it.get("kind") != kind_filter:
            continue
        f = it.get("file")
        if isinstance(f, str) and f.strip():
            out.add(f.strip())
    return out


def _path_excluded(rel: str, exclude: tuple[str, ...]) -> bool:
    """Match `rel` against recipe.EXCLUDE_PATHS entries.

    Entries ending in `/` are prefix-matched; entries with `*` use fnmatch on
    the filename; otherwise prefix or contains-segment match.
    """
    import fnmatch
    rel_with_slash = "/" + rel
    for ex in exclude:
        if "*" in ex:
            # Glob-style — match on the basename and any path segment.
            if fnmatch.fnmatch(rel.rsplit("/", 1)[-1], ex):
                return True
            continue
        if ex.endswith("/"):
            if rel.startswith(ex) or ("/" + ex) in rel_with_slash:
                return True
        else:
            if rel == ex or rel.startswith(ex + "/") or ("/" + ex + "/") in rel_with_slash:
                return True
    return False


def _glob_files(project_root: Path, patterns: list[str], exclude: tuple[str, ...] = ()) -> set[str]:
    found = set()
    for pat in patterns:
        for p in project_root.glob(pat):
            if not p.is_file():
                continue
            rel = p.relative_to(project_root).as_posix()
            if _path_excluded(rel, exclude):
                continue
            found.add(rel)
    return found


def _filter_by_content(project_root: Path, files: set[str], pattern: str) -> set[str]:
    """Keep only files whose text content matches `pattern` (regex).

    Read errors / unreadable files are silently dropped. Used by sanity probes
    to narrow name-based globs to files that actually match by signature
    (e.g. `*Command.php` → only those importing Symfony Console Command FQN).
    """
    try:
        rx = re.compile(pattern)
    except re.error:
        return files
    out = set()
    for rel in files:
        try:
            text = (project_root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if rx.search(text):
            out.add(rel)
    return out


def _enforce_ceiling(fm: dict, res: ValidationResult) -> None:
    rc = fm.get("recon_confidence")
    if not isinstance(rc, dict):
        return
    ceiling = rc.get("ceiling")
    level = rc.get("level")
    if ceiling == "medium" and level == "high":
        res.errors.append("ceiling=medium clamps level — frontmatter has level=high which is invalid")


def sanity_check(
    review_root: Path,
    project_root: Optional[Path] = None,
    recipe_loader=None,
) -> ValidationResult:
    """Recipe-driven sanity: hallucination + coverage diff ladder."""
    res = ValidationResult()
    context_path = review_root / "CONTEXT.md"
    if not context_path.is_file():
        res.errors.append(f"CONTEXT.md not found in {review_root}")
        return res
    text = context_path.read_text(encoding="utf-8")
    fm = _validate_frontmatter_v2(text, res)
    if fm is None:
        return res
    recipe_used = fm.get("recipe_used")
    if not isinstance(recipe_used, str):
        res.warnings.append("recipe_used missing — skipping sanity probes")
        return res
    try:
        if recipe_loader is not None:
            recipe = recipe_loader(recipe_used)
        else:
            recipe = importlib.import_module(f"recon.recipes.{recipe_used}")
    except (ModuleNotFoundError, ImportError) as e:
        res.warnings.append(f"could not import recipe '{recipe_used}': {e}")
        return res
    if project_root is None:
        # Best guess: parent of review_root if it looks like a project; else give up.
        candidate = review_root.parent
        if (candidate / "composer.json").is_file() or (candidate / "package.json").is_file():
            project_root = candidate
        else:
            res.warnings.append(
                "project_root not specified and could not be inferred — sanity coverage skipped"
            )
            return res
    project_root = project_root.resolve()
    if not project_root.is_dir():
        res.errors.append(f"project_root not a directory: {project_root}")
        return res

    probes = recipe.sanity_probes() if callable(getattr(recipe, "sanity_probes", None)) else []
    # H4: pull recipe.EXCLUDE_PATHS so coverage globs ignore the same paths the
    # recipe ignored when building inventory (vendor/, var/, tests/, etc).
    exclude_paths = tuple(getattr(recipe, "EXCLUDE_PATHS", ()))
    for probe in probes:
        payload = _payload_at_path(text, probe.section_path)
        if payload is None:
            res.warnings.append(f"sanity[{probe.label}]: section {probe.section_path} not found")
            continue
        status = payload.get("status")
        if status == "pending_enrichment":
            # Skip coverage on pending sections; report as info-warning.
            res.warnings.append(
                f"sanity[{probe.label}]: section {probe.section_path} status=pending_enrichment, coverage check skipped"
            )
            continue
        if status != "ok":
            # unknown / none — no hallucinations possible, skip coverage.
            continue
        declared = _declared_files(payload, kind_filter=probe.kind_filter)
        # Hallucination check.
        hallucinated = sorted(f for f in declared if not (project_root / f).is_file())
        if hallucinated:
            preview = ", ".join(hallucinated[:5])
            extra = f" (+{len(hallucinated)-5} more)" if len(hallucinated) > 5 else ""
            res.warnings.append(
                f"sanity[{probe.label}]: {len(hallucinated)} declared file(s) not on disk: {preview}{extra}"
            )
        # Coverage diff ladder.
        found = _glob_files(project_root, probe.glob_patterns, exclude=exclude_paths)
        if probe.content_filter:
            found = _filter_by_content(project_root, found, probe.content_filter)
        if not found:
            continue  # nothing to glob; legit empty case
        missing = found - declared
        diff = len(missing) / len(found)
        if diff <= COVERAGE_OK_THRESHOLD:
            continue
        miss_preview = ", ".join(sorted(missing)[:5])
        miss_extra = f" (+{len(missing)-5} more)" if len(missing) > 5 else ""
        msg = (
            f"sanity[{probe.label}]: declared {len(declared)} of {len(found)} filesystem matches "
            f"({diff:.0%} missing). Missing: {miss_preview}{miss_extra}"
        )
        if diff <= COVERAGE_WARN_THRESHOLD:
            res.warnings.append(msg)
            # L6: if diff puts us in the warn band, frontmatter level=high is
            # inconsistent (rev 3.5 ladder).
            rc = fm.get("recon_confidence")
            level = rc.get("level") if isinstance(rc, dict) else (rc if isinstance(rc, str) else None)
            if level == "high":
                res.errors.append(
                    f"sanity[{probe.label}]: coverage diff {diff:.0%} puts confidence in "
                    f"medium band, but frontmatter recon_confidence.level=high"
                )
        else:
            res.errors.append(msg)
    return res


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def validate_context_file(path: Path, recipe_loader=None) -> ValidationResult:
    """Validate CONTEXT.md (schema v2) at given absolute path. v1 → error."""
    res = ValidationResult()
    if not path.is_file():
        res.errors.append(f"File not found: {path}")
        return res
    text = path.read_text(encoding="utf-8")
    fm = _validate_frontmatter_v2(text, res)
    if fm is None:
        return res
    _enforce_ceiling(fm, res)
    _validate_core_sections(text, res)
    _validate_recon_bags(text, fm, res, recipe_loader=recipe_loader)
    return res


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate <review-root>/CONTEXT.md (schema v2)")
    parser.add_argument("--review-root", type=Path, required=True,
                        help="Review root directory containing CONTEXT.md")
    parser.add_argument("--sanity", action="store_true",
                        help="Run recipe-driven sanity probes (filesystem coverage)")
    parser.add_argument("--project-root", type=Path, default=None,
                        help="Project root for --sanity (default: parent of --review-root)")
    args = parser.parse_args(argv)

    review_root = args.review_root.resolve()
    context_path = review_root / "CONTEXT.md"
    if not context_path.is_file():
        print(f"error: CONTEXT.md not found in {review_root}", file=sys.stderr)
        return 2

    res = validate_context_file(context_path)
    if args.sanity and res.ok():
        s = sanity_check(review_root, project_root=args.project_root)
        res.errors.extend(s.errors)
        res.warnings.extend(s.warnings)

    for w in res.warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    for e in res.errors:
        print(f"ERROR: {e}", file=sys.stderr)
    if res.ok():
        print("OK")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
