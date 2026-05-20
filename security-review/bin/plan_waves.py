#!/usr/bin/env python3
"""Deterministic wave planner for security review (schema v2).

Reads <review_root>/CONTEXT.md, applies the WAVES table, autosplits by file
count, outputs JSON for the orchestrator.

stdlib only. No external dependencies.

Usage:
    plan_waves.py <context.md>
                  [--plugin-root=<path>]
                  [--all-opus]
                  [--scope-glob=<glob>]
                  [--diff-files=<path-to-file-with-list>]
                  [--exploratory]
                  [--include-vendor] [--include-tests]

Default model assignment is the balanced profile: opus for W1/W2/W6,
sonnet for W3/W4/W5/W∞. Pass --all-opus to force any wave whose
default_model is opus onto opus (legacy behaviour); W3 is sonnet-only by
definition (default_model=sonnet) so --all-opus does not promote it.

Plan output (stdout, JSON):
    [
      {
        "slice_id": "W1_PART1",
        "wave_id": "W1",
        "themes": ["auth", "disclosure"],
        "checklists": ["/abs/.../checklists/core/auth.md", ...],
        "relevant_section_paths": [...],
        "entry_points_in_scope": [...],
        "target_files": [...],
        "model": "opus",
        "mode": "project" | "changes"
      },
      ...
    ]
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional


# ---------------------------------------------------------------------------
# Closed concept enum.
#
# Concepts decouple WaveSpec from per-stack section paths. A wave declares
# concepts it cares about; CONCEPT_RESOLVERS maps (stack, concept) → list of
# `framework_specific.<stack>.*` paths. Adding a new recipe (Laravel, Django)
# means extending CONCEPT_RESOLVERS, not editing WaveSpec.
#
# To extend: add a new entry to Concept, then declare paths under each stack
# in CONCEPT_RESOLVERS. Stacks without a particular concept simply omit it
# (resolver returns []).
# ---------------------------------------------------------------------------


Concept = Literal[
    "auth_guards",            # firewalls, voters, policies, guards
    "request_inputs",         # forms, FormRequests, validators
    "output_renderers",       # twig overrides, blade components, view layers
    "messaging",              # messenger transports, queue jobs, listeners
    "serialization",          # serializers, normalizers, denormalizers
    "console_entries",        # CLI commands, kernels
    "graphql_layer",          # GraphQL schema/resolvers (lighthouse, rebing, api-platform, webonyx)
    "admin_surface",          # admin-bundle CRUD enumeration (EasyAdmin/Sonata/Nova) + voter coverage
    # 3.4.0 additions — see plan §1.7 + glossary.
    "route_authz_matrix",     # per-route effective_middleware + authz_evidence array
    "sensitive_data_model",   # entity-fields with PII/secrets + encryption_status
    "long_running_runtime",   # Octane / RoadRunner / Swoole — only meaningful on Laravel
]

ALL_CONCEPTS: tuple[Concept, ...] = (
    "auth_guards",
    "request_inputs",
    "output_renderers",
    "messaging",
    "serialization",
    "console_entries",
    "graphql_layer",
    "admin_surface",
    "route_authz_matrix",
    "sensitive_data_model",
    "long_running_runtime",
)


# Mapping (stack, concept) → list of dot-notation paths.
# Entries omitted for (stack, concept) that the recipe doesn't surface (e.g.
# `generic_php` exposes no framework_specific bag, so all its mappings are
# empty by virtue of absence).
CONCEPT_RESOLVERS: dict[tuple[str, str], tuple[str, ...]] = {
    # --- Symfony ---
    ("symfony", "auth_guards"): (
        "framework_specific.symfony.voters",
        "framework_specific.symfony.firewalls",
    ),
    ("symfony", "request_inputs"): (
        "framework_specific.symfony.forms",
    ),
    ("symfony", "output_renderers"): (
        "framework_specific.symfony.twig_overrides",
    ),
    ("symfony", "messaging"): (
        "framework_specific.symfony.messenger_transports",
    ),
    ("symfony", "graphql_layer"): (
        "framework_specific.symfony.graphql_layer",
    ),
    ("symfony", "admin_surface"): (
        "framework_specific.symfony.easyadmin_crud_controllers",
        "framework_specific.symfony.sonata_admin_classes",
        "framework_specific.symfony.admin_authz_coverage",
    ),
    ("symfony", "route_authz_matrix"): (
        "framework_specific.symfony.routes_authz_matrix",
    ),
    ("symfony", "sensitive_data_model"): (
        "framework_specific.symfony.sensitive_columns",
    ),
    # serialization & console_entries: Symfony recipe doesn't surface dedicated
    # framework_specific bags for these — concepts resolve to () and the wave
    # uses only its core paths.
    # long_running_runtime: Symfony does not declare runtime; Octane gate is a
    # Laravel-only concept (see plan §C-агент Octane gate).

    # --- Laravel ---
    ("laravel", "auth_guards"): (
        "framework_specific.laravel.policies",
        "framework_specific.laravel.middleware_groups",
    ),
    ("laravel", "request_inputs"): (
        "framework_specific.laravel.form_requests",
    ),
    ("laravel", "graphql_layer"): (
        "framework_specific.laravel.graphql_layer",
    ),
    ("laravel", "route_authz_matrix"): (
        "framework_specific.laravel.routes_authz_matrix",
    ),
    ("laravel", "sensitive_data_model"): (
        "framework_specific.laravel.sensitive_columns",
    ),
    ("laravel", "long_running_runtime"): (
        "framework_specific.laravel.runtime",
    ),
    # output_renderers: Blade templates live in core `output_renderers`; no
    # dedicated framework_specific bag needed.
    # messaging: queue jobs surface in core `attack_surface` (kind: message_handler);
    # no dedicated bag.
    # serialization & console_entries: same as Symfony — core sections suffice.
}


def resolve_concept_paths(stack: str, concept: str) -> list[str]:
    """Return framework_specific paths for (stack, concept), or [] when absent."""
    return list(CONCEPT_RESOLVERS.get((stack, concept), ()))

# Reuse the YAML subset parser & section extraction from validate_context.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_context as vc  # noqa: E402


# ---------------------------------------------------------------------------
# Wave definitions (schema v2 — раздел F плана rev 3.7).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WaveSpec:
    wave_id: str
    themes: tuple[str, ...]
    # Core (stack-agnostic) section paths the wave cares about.
    # Per-stack `framework_specific.*` paths are derived from
    # `relevant_concepts` via CONCEPT_RESOLVERS at plan time.
    relevant_section_paths: tuple[str, ...]
    # Concepts (closed enum) that resolve to per-stack framework_specific
    # paths. Empty tuple = wave is purely core-section-driven.
    relevant_concepts: tuple[str, ...]
    # Filter for attack_surface items by `kind`. None = no filter.
    # Applies only to "attack_surface" path; items in other sections pass.
    relevant_kinds: Optional[tuple[str, ...]]
    entry_point_section_paths: tuple[str, ...]
    entry_point_kinds: Optional[tuple[str, ...]]
    default_model: str
    balanced_model: str
    trigger: str


WAVES: tuple[WaveSpec, ...] = (
    WaveSpec(
        wave_id="W1",
        themes=("auth", "disclosure"),
        relevant_section_paths=(
            "attack_surface",
            "authz_usage",
            "data_access",
            "auth_layer",
        ),
        relevant_concepts=(
            "auth_guards",
            "graphql_layer",
            "admin_surface",
            # 3.4.0: route-level authz matrix + sensitive entity-fields +
            # long-running runtime (Octane). Recipes for 3.3.0 don't yet
            # emit these — resolver returns paths, worker treats absent
            # sections as no-op (`status: missing`).
            "route_authz_matrix",
            "sensitive_data_model",
            "long_running_runtime",
        ),
        relevant_kinds=("http_route", "http_route_admin", "cli_command", "message_handler"),
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=("http_route", "http_route_admin", "cli_command", "message_handler"),
        default_model="opus",
        balanced_model="opus",
        trigger="always",
    ),
    WaveSpec(
        wave_id="W2",
        themes=("injection", "data-access"),
        relevant_section_paths=(
            "attack_surface",
            "data_access",
            "authz_usage",
        ),
        relevant_concepts=(
            "request_inputs",
            "graphql_layer",
            "admin_surface",
            # 3.4.0: per-route authz matrix is also relevant for
            # injection/data-access (mass-assignment recall + admin-route
            # surface).
            "route_authz_matrix",
        ),
        relevant_kinds=("http_route", "http_route_admin", "cli_command", "message_handler"),
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=("http_route", "http_route_admin", "cli_command", "message_handler"),
        default_model="opus",
        balanced_model="opus",
        trigger="always",
    ),
    WaveSpec(
        wave_id="W3",
        themes=("output-render", "frontend-js"),
        relevant_section_paths=(
            "attack_surface",
            "output_renderers",
            "frontend_assets",
        ),
        relevant_concepts=("output_renderers",),
        relevant_kinds=("http_route", "http_route_admin", "template_render"),
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=("http_route", "http_route_admin", "template_render"),
        default_model="sonnet",
        balanced_model="sonnet",
        trigger="has_output_or_frontend",
    ),
    WaveSpec(
        wave_id="W4",
        themes=("serialization", "crypto"),
        relevant_section_paths=(
            "attack_surface",
            "serialization",
            "secrets",
        ),
        relevant_concepts=(
            "messaging",
            "serialization",
            # 3.4.0: sensitive entity-fields (PII / secrets) feed crypto
            # checklist — encryption_status diff vs. expected.
            "sensitive_data_model",
        ),
        relevant_kinds=("message_handler", "http_route", "event_listener"),
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=("message_handler", "http_route", "event_listener"),
        default_model="opus",
        balanced_model="sonnet",
        trigger="always",
    ),
    WaveSpec(
        wave_id="W5",
        themes=("ssrf-fileops",),
        relevant_section_paths=(
            "attack_surface",
            "file_operations",
            "http_clients",
        ),
        relevant_concepts=(),
        relevant_kinds=("http_route", "cli_command", "event_listener"),
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=("http_route", "cli_command", "event_listener"),
        default_model="opus",
        balanced_model="sonnet",
        trigger="has_fileops_or_httpclient",
    ),
    WaveSpec(
        wave_id="W6",
        themes=("fintech",),
        relevant_section_paths=(
            "attack_surface",
            "fintech_markers",
            "data_access",
        ),
        relevant_concepts=(),
        relevant_kinds=("http_route", "message_handler", "event_listener"),
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=("http_route", "message_handler", "event_listener"),
        default_model="opus",
        balanced_model="opus",
        trigger="has_fintech",
    ),
)


def _winf_spec() -> WaveSpec:
    """Build exploratory WINF spec.

    section_paths, concepts and themes — union of all focused waves (so WINF
    gets every section in scope and pulls every core / framework checklist).
    relevant_kinds & entry_point_kinds = None (no filter): exploratory must
    surface every entry-kind, including ones not yet listed in any focused
    wave (forward-compat: a future recipe emitting e.g. `webhook_handler`
    would still be scanned without a plan_waves bump).
    """
    paths: list[str] = []
    seen_paths: set[str] = set()
    concepts: list[str] = []
    seen_concepts: set[str] = set()
    themes: list[str] = []
    seen_themes: set[str] = set()
    for w in WAVES:
        for p in w.relevant_section_paths:
            if p not in seen_paths:
                seen_paths.add(p)
                paths.append(p)
        for c in w.relevant_concepts:
            if c not in seen_concepts:
                seen_concepts.add(c)
                concepts.append(c)
        for t in w.themes:
            if t not in seen_themes:
                seen_themes.add(t)
                themes.append(t)
    return WaveSpec(
        wave_id="WINF",
        themes=tuple(themes),
        relevant_section_paths=tuple(paths),
        relevant_concepts=tuple(concepts),
        relevant_kinds=None,
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=None,
        default_model="opus",
        balanced_model="sonnet",
        trigger="flag",
    )


def resolved_section_paths(wave: WaveSpec, stack: str) -> list[str]:
    """Return final list of section paths for `wave` under `stack`.

    Combines the wave's stack-agnostic `relevant_section_paths` with
    framework_specific paths derived from `relevant_concepts` via
    CONCEPT_RESOLVERS. Order is preserved; duplicates are dropped.
    """
    out: list[str] = []
    seen: set[str] = set()
    for p in wave.relevant_section_paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    for c in wave.relevant_concepts:
        for p in resolve_concept_paths(stack, c):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


EXPLORATORY_WAVE = _winf_spec()


# ---------------------------------------------------------------------------
# Consumer kind → waves inverse index.
#
# Used by /security-changes orchestrator after reverse-grep: for a consumer
# file whose `kind` is known (from CONTEXT.md attack_surface lookup), the
# index returns the list of waves whose `relevant_kinds` cover that kind.
# This replaces the previous LLM-heuristic "guess which wave matches".
# ---------------------------------------------------------------------------


def consumer_kinds_to_waves() -> dict[str, list[str]]:
    """Build inverse index `kind → [wave_ids]` from WAVES.

    Excludes EXPLORATORY_WAVE (relevant_kinds=None means "all kinds" — would
    swamp the index and add noise to the orchestrator's decision).
    """
    index: dict[str, list[str]] = {}
    for wave in WAVES:
        if wave.relevant_kinds is None:
            continue
        for kind in wave.relevant_kinds:
            index.setdefault(kind, []).append(wave.wave_id)
    return index


def lookup_kind_for_file(file_path: str, ctx: ParsedContext) -> Optional[str]:
    """Find `kind` of an attack-surface item by file path.

    Resolution: scan ctx.sections["attack_surface"]["items"] (canonical), then
    framework_specific.<stack>.* sections that carry items with `kind`.
    Returns the first match's `kind` or None.

    `file_path` is normalized through `_normalize_path` before comparison
    (recipe emits POSIX `relative_to(project_root)` form).
    """
    target = _normalize_path(file_path)
    stack = ctx.stack
    payload = ctx.sections.get("attack_surface")
    if isinstance(payload, dict):
        for item in payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            f = _item_file(item, stack=stack)
            if f and _normalize_path(f) == target:
                k = item.get("kind")
                if isinstance(k, str) and k:
                    return k
    # framework_specific.<stack>.<section> may also carry items with `kind`.
    fw_root = ctx.sections.get("framework_specific")
    if isinstance(fw_root, dict):
        for stack_payload in fw_root.values():
            if not isinstance(stack_payload, dict):
                continue
            for sec_payload in stack_payload.values():
                if not isinstance(sec_payload, dict):
                    continue
                for item in sec_payload.get("items") or []:
                    if not isinstance(item, dict):
                        continue
                    f = _item_file(item, stack=stack)
                    if f and _normalize_path(f) == target:
                        k = item.get("kind")
                        if isinstance(k, str) and k:
                            return k
    return None


# Autosplit limits by model.
OPUS_SPLIT = 50
SONNET_SPLIT = 30
WINF_SPLIT = 65  # exploratory benefits from wider context per chunk


# Default vendor / tests exclude (path-prefix match).
_VENDOR_PREFIXES: tuple[str, ...] = (
    "vendor/", "node_modules/", "var/",
    "public/bundles/", "public/build/",
    "build/", "dist/", "assets/vendor/",
)
_TESTS_PREFIXES: tuple[str, ...] = ("tests/", "test/")


def _is_vendor_path(path: str) -> bool:
    # removeprefix (not lstrip) — `lstrip("./")` strips any combination of `.`
    # and `/` chars, so `'../vendor/foo'.lstrip('./')` → `'vendor/foo'` (false
    # positive). We only want to peel ONE leading `./`.
    p = path.removeprefix("./")
    return any(p.startswith(pref) for pref in _VENDOR_PREFIXES)


def _is_tests_path(path: str) -> bool:
    p = path.removeprefix("./")
    return any(p.startswith(pref) for pref in _TESTS_PREFIXES)


# ---------------------------------------------------------------------------
# Context reading.
# ---------------------------------------------------------------------------


@dataclass
class ParsedContext:
    frontmatter: dict[str, Any]
    # For top-level sections (anchor → fenced yaml dict). framework_specific is
    # stored under its anchor; nested dot-notation paths are resolved on demand.
    sections: dict[str, dict[str, Any]]

    @property
    def stack(self) -> str:
        """Stack name from frontmatter (e.g. 'symfony', 'none', 'unknown').

        Source of truth: `frontmatter.stack.framework`. Falls back to "unknown"
        when missing, so resolve_checklists treats it as "no framework layer".
        """
        st = self.frontmatter.get("stack")
        if isinstance(st, dict):
            fw = st.get("framework")
            if isinstance(fw, str) and fw:
                return fw
        return "unknown"

    def payload_at(self, path: str) -> Optional[dict[str, Any]]:
        """Resolve dot-notation path → payload dict.

        "attack_surface"                     → top-level core section payload.
        "framework_specific.symfony.voters"  → nested key under framework_specific.
        Returns None when the path doesn't resolve to a dict.
        """
        parts = path.split(".")
        cur: Any = self.sections.get(parts[0])
        for p in parts[1:]:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
        return cur if isinstance(cur, dict) else None

    def section_status(self, path: str) -> str:
        payload = self.payload_at(path)
        if payload is None:
            return "missing"
        status = payload.get("status")
        return status if isinstance(status, str) else "missing"

    def section_items(self, path: str) -> list[dict[str, Any]]:
        payload = self.payload_at(path)
        if not payload or payload.get("status") != "ok":
            return []
        items = payload.get("items")
        if not isinstance(items, list):
            return []
        return [x for x in items if isinstance(x, dict)]

    def section_has_items(self, path: str) -> bool:
        return len(self.section_items(path)) > 0

    def scalar_source_files(self, path: str) -> list[str]:
        """Return source_files of a scalar-shape section (status=ok), else []."""
        payload = self.payload_at(path)
        if not payload or payload.get("status") != "ok":
            return []
        # Distinguish list-shape (has `items`) from scalar (has `data` /
        # `source_files`). Scalar sections in schema v2 carry source_files.
        if "items" in payload:
            return []
        sf = payload.get("source_files")
        if not isinstance(sf, list):
            return []
        return [s for s in sf if isinstance(s, str) and s]


def parse_context(path: Path) -> ParsedContext:
    text = path.read_text(encoding="utf-8")

    m = vc.FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("Missing frontmatter in CONTEXT.md")
    try:
        fm = vc.parse_yaml_subset(m.group(1))
    except vc.YamlSubsetError as exc:
        raise ValueError(f"Frontmatter parse error: {exc}") from exc
    if not isinstance(fm, dict):
        raise ValueError("Frontmatter is not a mapping")
    sv = fm.get("schema_version")
    if sv != 2:
        raise ValueError(
            f"Unsupported schema_version: {sv!r} (expected 2). v3 plan_waves "
            "does not read v1 SECURITY_CONTEXT.md — rerun recon_inventory to "
            "regenerate <review_root>/CONTEXT.md."
        )

    sections_raw = vc.extract_sections(text)
    sections: dict[str, dict[str, Any]] = {}
    for sid, parsed in sections_raw.items():
        fence = vc.FENCED_YAML_RE.search(parsed.body)
        if not fence:
            continue
        try:
            payload = vc.parse_yaml_subset(fence.group(1))
        except vc.YamlSubsetError:
            continue
        if isinstance(payload, dict):
            sections[sid] = payload

    return ParsedContext(frontmatter=fm, sections=sections)


# ---------------------------------------------------------------------------
# Wave triggering.
# ---------------------------------------------------------------------------


def should_trigger(wave: WaveSpec, ctx: ParsedContext) -> bool:
    trigger = wave.trigger
    if trigger == "always":
        return True
    if trigger == "flag":
        return False  # only via --exploratory
    if trigger == "has_output_or_frontend":
        return (
            ctx.section_has_items("output_renderers")
            or ctx.section_has_items("frontend_assets")
        )
    if trigger == "has_fileops_or_httpclient":
        return (
            ctx.section_has_items("file_operations")
            or ctx.section_has_items("http_clients")
        )
    if trigger == "has_fintech":
        return ctx.section_has_items("fintech_markers")
    raise ValueError(f"Unknown trigger: {trigger}")


# ---------------------------------------------------------------------------
# File collection.
# ---------------------------------------------------------------------------


# Per-stack PSR-4 root for the conventional `App\` namespace. Used as a
# last-resort fallback when an item omits `file` and only carries an FQN.
# Recipes are expected to always set `file` directly (canonical contract);
# this map exists only for legacy / edge items.
_APP_NAMESPACE_ROOTS: dict[str, str] = {
    "symfony": "src",
    "laravel": "app",
}


def _item_file(item: dict[str, Any], stack: str = "unknown") -> Optional[str]:
    r"""Extract project-relative file path from a section item.

    Schema v2 items SHOULD carry a `file` key (recipe contract). Falls back to
    `path` / `template`, then FQN→PSR-4 derivation as a last resort. The
    fallback uses `_APP_NAMESPACE_ROOTS[stack]` to map `App\` to the right
    directory (`src/` for Symfony, `app/` for Laravel). Stacks without an
    `App\` convention skip the App-prefix branch.
    """
    for key in ("file", "path", "template"):
        v = item.get(key)
        if isinstance(v, str) and v:
            return v
    app_root = _APP_NAMESPACE_ROOTS.get(stack)
    for key in ("controller", "class", "handler", "subscriber"):
        v = item.get(key)
        if not isinstance(v, str) or not v:
            continue
        # PHP FQN may carry a leading backslash (`\App\Controller\X`); strip
        # it so split doesn't yield an empty first segment.
        fqn = v.split("::", 1)[0].lstrip("\\")
        parts = fqn.split("\\")
        if not parts or not parts[0]:
            continue
        if parts[0] == "App":
            if app_root is None:
                # Unknown stack — App\ has no canonical root. Skip fallback.
                return None
            return app_root + "/" + "/".join(parts[1:]) + ".php"
        return "/".join(parts) + ".php"
    return None


def _matches_scope_glob(file_path: str, glob_pattern: str) -> bool:
    return fnmatch.fnmatch(file_path, glob_pattern)


def _kind_filter_passes(
    section_path: str,
    item: dict[str, Any],
    relevant_kinds: Optional[tuple[str, ...]],
) -> bool:
    """Apply kind filter only on `attack_surface` items.

    Plan rev F: relevant_kinds is the entry-kind filter for attack_surface.
    Other sections (data_access, output_renderers, frontend_assets, voters
    etc.) carry uniform / section-specific kinds — filtering them by an
    entry-kind whitelist would drop legitimate items.
    """
    if section_path != "attack_surface" or relevant_kinds is None:
        return True
    return item.get("kind") in set(relevant_kinds)


def collect_files(
    section_paths: tuple[str, ...],
    relevant_kinds: Optional[tuple[str, ...]],
    ctx: ParsedContext,
    *,
    scope_glob: Optional[str] = None,
    require_touched: bool = False,
    include_vendor: bool = False,
    include_tests: bool = False,
) -> list[str]:
    """Channel 1 — collect unique file paths from list-shape section items.

    require_touched=True: keep item only when `touched_by_diff is True`. The
    recipe is authoritative — it received `diff_files` during build_inventory
    and is responsible for setting the flag. Do not re-derive from diff_files
    here: it would mask recipe bugs (and split source-of-truth between two
    places). Use `is True` (not bool()) so a stray string `"false"` from a
    hand-edited yaml does not leak through.
    """
    collected: set[str] = set()
    stack = ctx.stack
    for path in section_paths:
        for item in ctx.section_items(path):
            if not _kind_filter_passes(path, item, relevant_kinds):
                continue
            file_path = _item_file(item, stack=stack)
            if not file_path:
                continue
            if not include_vendor and _is_vendor_path(file_path):
                continue
            if not include_tests and _is_tests_path(file_path):
                continue
            if require_touched and item.get("touched_by_diff") is not True:
                continue
            if scope_glob and not _matches_scope_glob(file_path, scope_glob):
                continue
            collected.add(file_path)
    return sorted(collected)


def collect_scalar_changes(
    section_paths: tuple[str, ...],
    ctx: ParsedContext,
    diff_files: set[str],
    *,
    scope_glob: Optional[str] = None,
    include_vendor: bool = False,
    include_tests: bool = False,
) -> list[str]:
    """Channel 2 — for mode=changes only.

    For each scalar section in `section_paths`, if its `source_files` set
    intersects `diff_files`, surface ALL its source_files into target_files
    (worker re-reads the whole config block, not just the touched line).

    Skips list-shape sections (they go through channel 1 / collect_files).
    """
    out: set[str] = set()
    for path in section_paths:
        sf = ctx.scalar_source_files(path)
        if not sf:
            continue
        sf_set = set(sf)
        if not (sf_set & diff_files):
            continue
        for f in sf:
            if not include_vendor and _is_vendor_path(f):
                continue
            if not include_tests and _is_tests_path(f):
                continue
            if scope_glob and not _matches_scope_glob(f, scope_glob):
                continue
            out.add(f)
    return sorted(out)


def collect_entry_points(
    section_paths: tuple[str, ...],
    entry_kinds: Optional[tuple[str, ...]],
    ctx: ParsedContext,
) -> list[str]:
    """Identifiers (route name / FQN / handler) for items in entry-point sections."""
    out: set[str] = set()
    kind_set = set(entry_kinds) if entry_kinds else None
    stack = ctx.stack
    for path in section_paths:
        for item in ctx.section_items(path):
            if path == "attack_surface" and kind_set is not None:
                if item.get("kind") not in kind_set:
                    continue
            label = (
                item.get("identifier")
                or item.get("route_name")
                or item.get("name")
                or item.get("handler")
                or item.get("controller")
                or item.get("class")
                or _item_file(item, stack=stack)
            )
            if isinstance(label, str) and label:
                out.add(label)
    return sorted(out)


# ---------------------------------------------------------------------------
# Checklist resolution (rev 3.7 layout: core/ + frameworks/{stack}/).
# ---------------------------------------------------------------------------


def resolve_checklists(
    themes: tuple[str, ...],
    stack: str,
    plugin_root: Optional[Path],
) -> list[str]:
    """Return absolute checklist paths for the given themes & stack.

    Layout:
      checklists/core/{theme}.md            — always loaded if present.
      checklists/frameworks/{stack}/{theme}.md — loaded if stack ∉ {none, unknown}
                                                 and the file exists.

    Order: all core first (theme order preserved), then all framework files
    (theme order preserved). Worker is told that framework files override
    core when both are present (anchor in frameworks/{stack}/{theme}.md).

    Graceful skip: missing files are silently dropped — core is best-effort,
    framework is opt-in. plugin_root=None disables resolution entirely
    (returns []) — callers must pass an existing plugin root.
    """
    if plugin_root is None:
        return []
    root = plugin_root.resolve()
    out: list[str] = []
    for t in themes:
        core = root / "checklists" / "core" / f"{t}.md"
        if core.is_file():
            out.append(str(core))
    if stack and stack not in ("none", "unknown"):
        for t in themes:
            fw = root / "checklists" / "frameworks" / stack / f"{t}.md"
            if fw.is_file():
                out.append(str(fw))
    return out


# ---------------------------------------------------------------------------
# Autosplit.
# ---------------------------------------------------------------------------


def split_files(
    files: list[str],
    model: str,
    *,
    limit_override: Optional[int] = None,
) -> list[list[str]]:
    if not files:
        return [[]]
    limit = limit_override if limit_override is not None else (
        OPUS_SPLIT if model == "opus" else SONNET_SPLIT
    )
    if len(files) <= limit:
        return [files]
    n_parts = math.ceil(len(files) / limit)
    chunk_size = math.ceil(len(files) / n_parts)
    return [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]


# ---------------------------------------------------------------------------
# Plan building.
# ---------------------------------------------------------------------------


def _wave_target_files(
    wave: WaveSpec,
    ctx: ParsedContext,
    *,
    scope_glob: Optional[str],
    diff_files: Optional[set[str]],
    include_vendor: bool,
    include_tests: bool,
) -> list[str]:
    """Channel 1 + channel 2 union for one wave."""
    section_paths = tuple(resolved_section_paths(wave, ctx.stack))
    list_files = collect_files(
        section_paths,
        wave.relevant_kinds,
        ctx,
        scope_glob=scope_glob,
        require_touched=diff_files is not None,
        include_vendor=include_vendor,
        include_tests=include_tests,
    )
    if diff_files is None:
        return list_files
    scalar_files = collect_scalar_changes(
        section_paths,
        ctx,
        diff_files,
        scope_glob=scope_glob,
        include_vendor=include_vendor,
        include_tests=include_tests,
    )
    if not scalar_files:
        return list_files
    return sorted(set(list_files) | set(scalar_files))


def build_plan(
    ctx: ParsedContext,
    *,
    plugin_root: Optional[Path] = None,
    all_opus: bool = False,
    exploratory: bool = False,
    scope_glob: Optional[str] = None,
    diff_files: Optional[set[str]] = None,
    include_vendor: bool = False,
    include_tests: bool = False,
    extra_target_files: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    mode = "changes" if diff_files is not None else "project"
    # Normalize external diff_files to recipe's POSIX, no-leading-./ form so
    # set intersections (channel 2) line up. Idempotent: already-normalized
    # paths pass through unchanged.
    if diff_files is not None:
        diff_files = {_normalize_path(p) for p in diff_files}
    # Normalize extra_target_files identically: orchestrator passes them
    # straight from `removed_defenses.json` / consumer grep output, so leading
    # `./` and whitespace are common.
    extra_norm: list[str] = (
        sorted({_normalize_path(p) for p in extra_target_files if p and p.strip()})
        if extra_target_files else []
    )
    plan: list[dict[str, Any]] = []
    stack = ctx.stack

    waves_to_run = [w for w in WAVES if should_trigger(w, ctx)]

    for wave in waves_to_run:
        model = wave.default_model if all_opus else wave.balanced_model
        files = _wave_target_files(
            wave, ctx,
            scope_glob=scope_glob,
            diff_files=diff_files,
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        # Inject extra_target_files (from /security-changes removed-defense
        # detection: consumers of removed Voter/Policy/Middleware + controllers
        # that lost their authz attribute). Done BEFORE the empty-intersection
        # skip so a wave with no diff intersection but with extra files still
        # gets scheduled — that's the whole point of the flag.
        if extra_norm:
            files = sorted(set(files) | set(extra_norm))
        if diff_files is not None and not files:
            continue  # no intersection with diff
        if scope_glob and not files:
            continue
        entry_points = collect_entry_points(
            wave.entry_point_section_paths, wave.entry_point_kinds, ctx,
        )
        chunks = split_files(files, model)
        checklists = resolve_checklists(wave.themes, stack, plugin_root)
        for idx, chunk in enumerate(chunks, start=1):
            slice_id = f"{wave.wave_id}_PART{idx}"
            if mode == "changes":
                slice_id += "_CHANGES"
            plan.append({
                "slice_id": slice_id,
                "wave_id": wave.wave_id,
                "themes": list(wave.themes),
                "checklists": checklists,
                "relevant_section_paths": resolved_section_paths(wave, stack),
                "entry_points_in_scope": entry_points,
                "target_files": chunk,
                "model": model,
                "mode": mode,
            })

    if exploratory:
        wave = EXPLORATORY_WAVE
        model = wave.default_model if all_opus else wave.balanced_model
        files = _wave_target_files(
            wave, ctx,
            scope_glob=scope_glob,
            diff_files=diff_files,
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        if extra_norm:
            files = sorted(set(files) | set(extra_norm))
        # mode=changes: skip WINF entirely if nothing intersects the diff —
        # exploratory has no value when there's no changed code to explore.
        # project mode: still emit one slice (exploratory ranges over context
        # via `relevant_section_paths`, target_files=[] is a valid signal).
        if not (mode == "changes" and not files):
            # Anchor entry points: own + union of all focused waves'.
            own = set(collect_entry_points(
                wave.entry_point_section_paths, wave.entry_point_kinds, ctx,
            ))
            focused: set[str] = set()
            for s in plan:
                focused.update(s.get("entry_points_in_scope", []))
            all_eps = sorted(own | focused)
            # Exploratory loads union of all themes' checklists (раздел F:
            # «На W∞ exploratory загружаются все темы union'ом»).
            checklists = resolve_checklists(wave.themes, stack, plugin_root)

            chunks = split_files(files, model, limit_override=WINF_SPLIT) or [[]]
            for idx, chunk in enumerate(chunks, start=1):
                slice_id = f"WINF_PART{idx}"
                if mode == "changes":
                    slice_id += "_CHANGES"
                plan.append({
                    "slice_id": slice_id,
                    "wave_id": wave.wave_id,
                    "themes": list(wave.themes),
                    "checklists": checklists,
                    "relevant_section_paths": resolved_section_paths(wave, stack),
                    "entry_points_in_scope": all_eps,
                    "target_files": chunk,
                    "model": model,
                    "mode": mode,
                })

    return plan


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _normalize_path(s: str) -> str:
    """Normalize project-relative path: strip leading './' so diff_files and
    item.file are compared in the same form. Recipe emits POSIX
    `Path.relative_to(project_root).as_posix()` (no leading dot); but external
    callers (CI scripts, hand-curated diffs) may pass `./src/Foo.php`.
    """
    return s.strip().removeprefix("./")


def read_diff_files(path: Path) -> set[str]:
    return {
        _normalize_path(ln) for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    }


def _default_plugin_root() -> Path:
    return Path(__file__).resolve().parent.parent


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Plan security review waves (schema v2)")
    parser.add_argument("context", type=Path, help="Path to <review_root>/CONTEXT.md")
    parser.add_argument(
        "--plugin-root", type=Path, default=None,
        help="Plugin root (containing checklists/). Default: parent of bin/.",
    )
    parser.add_argument(
        "--all-opus", action="store_true",
        help="Use default_model (opus) for waves whose default differs from "
             "balanced. W3 stays sonnet by definition.",
    )
    parser.add_argument("--exploratory", action="store_true", help="Append W∞ exploratory wave")
    parser.add_argument("--scope-glob", type=str, default=None,
                        help="Glob to restrict target files")
    parser.add_argument("--diff-files", type=Path, default=None,
                        help="File listing changed files (one per line) → mode=changes")
    parser.add_argument("--include-vendor", action="store_true",
                        help="Keep vendor/**, node_modules/**, var/**, build/**, dist/**")
    parser.add_argument("--include-tests", action="store_true",
                        help="Keep tests/** and test/** directories")
    parser.add_argument(
        "--save-plan", type=Path, default=None,
        help="Persist generated plan as JSON at this path (atomic write via "
        "temp+rename). Stdout still prints the plan. Renderer reads the saved "
        "file via --waves-plan to emit `## Checklist coverage` block.",
    )
    parser.add_argument(
        "--extra-target-files", type=str, default=None,
        help="CSV-list of additional files to include in target_files of every "
             "wave (and WINF). Used by /security-changes for consumers of "
             "removed defenses (Voter/Policy/Middleware) and controllers that "
             "lost authz attributes — those files must be reviewed even when "
             "they themselves are unchanged in the diff.",
    )
    args = parser.parse_args(argv)

    plugin_root = args.plugin_root or _default_plugin_root()

    try:
        ctx = parse_context(args.context)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        diff_files = read_diff_files(args.diff_files) if args.diff_files else None
    except (FileNotFoundError, OSError) as exc:
        print(f"Error reading --diff-files: {exc}", file=sys.stderr)
        return 2

    extra_files: list[str] = (
        [f.strip() for f in args.extra_target_files.split(",") if f.strip()]
        if args.extra_target_files else []
    )

    plan = build_plan(
        ctx,
        plugin_root=plugin_root,
        all_opus=args.all_opus,
        exploratory=args.exploratory,
        scope_glob=args.scope_glob,
        diff_files=diff_files,
        include_vendor=args.include_vendor,
        include_tests=args.include_tests,
        extra_target_files=extra_files,
    )

    if args.save_plan is not None:
        # Atomic write: temp file in the same directory, then rename. Avoids
        # partial-state files visible to renderer if process is killed
        # mid-write.
        target = args.save_plan
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(target.suffix + ".tmp")
            tmp.write_text(json.dumps(plan, indent=2), encoding="utf-8")
            tmp.replace(target)
        except OSError as exc:
            print(f"Error writing --save-plan {target}: {exc}", file=sys.stderr)
            return 2

    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
