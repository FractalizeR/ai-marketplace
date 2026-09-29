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
                  [--exploratory]
                  [--recon-gaps=<recon_gaps.json>]
                  [--include-vendor] [--include-tests]

Default model assignment is the balanced profile: opus for W1/W2/W6,
sonnet for W3/W4/W5/W∞; the WGAP follow-up wave (recon gaps) is always
opus. Pass --all-opus to force any wave whose default_model is opus onto opus (legacy behaviour); W3 is sonnet-only by
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
        "mode": "project"
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
# `recon_bags.stack.<stack>.*` paths. Adding a new recipe (Laravel, Django)
# means extending CONCEPT_RESOLVERS, not editing WaveSpec.
#
# To extend: add a new entry to Concept, then declare paths under each stack
# in CONCEPT_RESOLVERS. Stacks without a particular concept simply omit it
# (resolver returns []).
# ---------------------------------------------------------------------------


Concept = Literal[
    "auth_guards",            # firewalls, voters, policies, guards
    "request_trust",          # trusted_proxies/hosts/headers — effective client IP/host
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
    "request_trust",
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
# `generic_php` exposes no recon_bags bag, so all its mappings are
# empty by virtue of absence).
CONCEPT_RESOLVERS: dict[tuple[str, str], tuple[str, ...]] = {
    # --- Symfony ---
    ("symfony", "auth_guards"): (
        "recon_bags.stack.symfony.voters",
        "recon_bags.stack.symfony.firewalls",
    ),
    ("symfony", "request_trust"): (
        "recon_bags.stack.symfony.trusted_config",
    ),
    ("symfony", "request_inputs"): (
        "recon_bags.stack.symfony.forms",
    ),
    ("symfony", "output_renderers"): (
        "recon_bags.stack.symfony.twig_overrides",
    ),
    ("symfony", "messaging"): (
        "recon_bags.stack.symfony.messenger_transports",
    ),
    ("symfony", "graphql_layer"): (
        "recon_bags.stack.symfony.graphql_layer",
    ),
    ("symfony", "admin_surface"): (
        "recon_bags.addon.easyadmin.crud_controllers",
        "recon_bags.addon.sonata.admin_classes",
        "recon_bags.stack.symfony.admin_authz_coverage",
    ),
    ("symfony", "route_authz_matrix"): (
        "recon_bags.stack.symfony.routes_authz_matrix",
    ),
    ("symfony", "sensitive_data_model"): (
        "recon_bags.stack.symfony.sensitive_columns",
    ),
    # serialization & console_entries: Symfony recipe doesn't surface dedicated
    # recon_bags bags for these — concepts resolve to () and the wave
    # uses only its core paths.
    # long_running_runtime: Symfony does not declare runtime; Octane gate is a
    # Laravel-only concept (see plan §C-agent Octane gate).

    # --- Laravel ---
    ("laravel", "auth_guards"): (
        "recon_bags.stack.laravel.policies",
        "recon_bags.stack.laravel.middleware_groups",
    ),
    ("laravel", "request_inputs"): (
        "recon_bags.stack.laravel.form_requests",
    ),
    ("laravel", "graphql_layer"): (
        "recon_bags.stack.laravel.graphql_layer",
    ),
    ("laravel", "route_authz_matrix"): (
        "recon_bags.stack.laravel.routes_authz_matrix",
    ),
    ("laravel", "sensitive_data_model"): (
        "recon_bags.stack.laravel.sensitive_columns",
    ),
    ("laravel", "long_running_runtime"): (
        "recon_bags.stack.laravel.runtime",
    ),
    # output_renderers: Blade templates live in core `output_renderers`; no
    # dedicated recon_bags bag needed.
    # messaging: queue jobs surface in core `attack_surface` (kind: message_handler);
    # no dedicated bag.
    # serialization & console_entries: same as Symfony — core sections suffice.
}


def resolve_concept_paths(stack: str, concept: str) -> list[str]:
    """Return recon_bags paths for (stack, concept), or [] when absent."""
    return list(CONCEPT_RESOLVERS.get((stack, concept), ()))

# Reuse the YAML subset parser & section extraction from validate_context.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_context as vc  # noqa: E402


# ---------------------------------------------------------------------------
# Wave definitions (schema v2 — section F of plan rev 3.7).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WaveSpec:
    wave_id: str
    themes: tuple[str, ...]
    # Core (stack-agnostic) section paths the wave cares about.
    # Per-stack `recon_bags.*` paths are derived from
    # `relevant_concepts` via CONCEPT_RESOLVERS at plan time.
    relevant_section_paths: tuple[str, ...]
    # Concepts (closed enum) that resolve to per-stack recon_bags
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
            "request_trust",
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
        # "business-logic" rides W2 (trigger="always") rather than W6
        # (trigger="has_fintech", which never plans on a non-fintech
        # project) — see checklists/core/business-logic.md and
        # test_business_logic_checklist_present_in_w2_without_fintech in
        # tests/test_plan_waves.py.
        themes=("injection", "data-access", "business-logic"),
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
        themes=("output-render", "frontend-js", "security-headers"),
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


def _union_spec(wave_id: str, *, balanced_model: str, trigger: str) -> WaveSpec:
    """Build a spec spanning every focused wave (WINF, WGAP).

    section_paths, concepts and themes — union of all focused waves (so the
    wave gets every section in scope and pulls every core / framework
    checklist). relevant_kinds & entry_point_kinds = None (no filter): the
    wave must surface every entry-kind, including ones not yet listed in any
    focused wave (forward-compat: a future recipe emitting e.g. `webhook_handler`
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
        wave_id=wave_id,
        themes=tuple(themes),
        relevant_section_paths=tuple(paths),
        relevant_concepts=tuple(concepts),
        relevant_kinds=None,
        entry_point_section_paths=("attack_surface",),
        entry_point_kinds=None,
        default_model="opus",
        balanced_model=balanced_model,
        trigger=trigger,
    )


def resolved_section_paths(wave: WaveSpec, stack: str) -> list[str]:
    """Return final list of section paths for `wave` under `stack`.

    Combines the wave's stack-agnostic `relevant_section_paths` with
    recon_bags paths derived from `relevant_concepts` via
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


def _winf_spec() -> WaveSpec:
    return _union_spec("WINF", balanced_model="sonnet", trigger="flag")


def _wgap_spec() -> WaveSpec:
    return _union_spec("WGAP", balanced_model="opus", trigger="gap")


EXPLORATORY_WAVE = _winf_spec()

# Recon left these files uninterpreted; the worker has to discover entry
# points and trust boundaries itself, hence opus regardless of --all-opus.
GAP_WAVE = _wgap_spec()
GAP_MAX_FILES = 150
RECON_GAPS_SCHEMA_VERSION = 1


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
    # For top-level sections (anchor → fenced yaml dict). recon_bags is
    # stored under its anchor; nested dot-notation paths are resolved on demand.
    sections: dict[str, dict[str, Any]]

    @property
    def stack(self) -> str:
        """Stack name from frontmatter (e.g. 'symfony', 'none', 'unknown').

        Source of truth: `frontmatter.stack.framework`. Falls back to "unknown"
        when missing, so resolve_checklists treats it as "no stack layer".
        """
        st = self.frontmatter.get("stack")
        if isinstance(st, dict):
            fw = st.get("framework")
            if isinstance(fw, str) and fw:
                return fw
        return "unknown"

    @property
    def resolution_context(self) -> "ResolutionContext":
        """Build a ResolutionContext from frontmatter.stack for resolve_checklists.

        - stack: from stack.framework (default "unknown").
        - addons: from stack.addons (default empty).
        - integrations: from stack.integrations (default empty).

        Defends against malformed YAML (non-list addons/integrations, non-string
        items) before passing to ResolutionContext, which normalizes the result
        (dedupe + sort) in __post_init__.
        """
        st = self.frontmatter.get("stack")
        stack_name = "unknown"
        addons_raw: tuple[str, ...] = ()
        integrations_raw: tuple[str, ...] = ()
        if isinstance(st, dict):
            fw = st.get("framework")
            if isinstance(fw, str) and fw:
                stack_name = fw
            a = st.get("addons")
            if isinstance(a, list):
                addons_raw = tuple(x for x in a if isinstance(x, str) and x)
            i = st.get("integrations")
            if isinstance(i, list):
                integrations_raw = tuple(x for x in i if isinstance(x, str) and x)
        return ResolutionContext(
            stack=stack_name,
            addons=addons_raw,
            integrations=integrations_raw,
        )

    def payload_at(self, path: str) -> Optional[dict[str, Any]]:
        """Resolve dot-notation path → payload dict.

        "attack_surface"                     → top-level core section payload.
        "recon_bags.stack.symfony.voters"  → nested key under recon_bags.
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
        # `partial` is a routable status just like `ok`: the section carries real
        # items, coverage is merely incomplete (e.g. EasyAdmin CRUD delegating
        # configureFields() to a parent). Dropping it would silently under-route
        # the admin_surface / route_authz waves — the opposite of what `partial`
        # ("look harder here") should mean.
        if not payload or payload.get("status") not in ("ok", "partial"):
            return []
        items = payload.get("items")
        if not isinstance(items, list):
            return []
        return [x for x in items if isinstance(x, dict)]

    def section_has_items(self, path: str) -> bool:
        return len(self.section_items(path)) > 0

    def scalar_source_files(self, path: str) -> list[str]:
        """Return source_files of a scalar-shape section (status ok|partial|
        pending_enrichment), else []."""
        payload = self.payload_at(path)
        # `partial` routes like `ok` (see section_items) — e.g. a partial
        # admin_authz_coverage still lists the admin controllers to audit.
        # `pending_enrichment` routes too: the recon utility already knows the
        # files (the security config, `.env`), so a section the recon agent
        # never enriched must not drop them from the workers' scope.
        if not payload or payload.get("status") not in ("ok", "partial", "pending_enrichment"):
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
            f"Unsupported schema_version: {sv!r} (expected 2). Rerun "
            "recon_inventory to regenerate <review_root>/CONTEXT.md."
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
    if trigger in ("flag", "gap"):
        return False  # only via --exploratory / recon gaps
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
    include_vendor: bool = False,
    include_tests: bool = False,
) -> list[str]:
    """Collect unique file paths from list-shape section items."""
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
            if scope_glob and not _matches_scope_glob(file_path, scope_glob):
                continue
            collected.add(file_path)
    return sorted(collected)


def _filter_scalar_files(
    files: list[str],
    *,
    scope_glob: Optional[str],
    include_vendor: bool,
    include_tests: bool,
) -> set[str]:
    """Shared vendor/tests/scope filter for scalar source_files.

    Shared by the scalar-section path and the WGAP gap files so their
    filtering can't drift.
    """
    out: set[str] = set()
    for f in files:
        if not include_vendor and _is_vendor_path(f):
            continue
        if not include_tests and _is_tests_path(f):
            continue
        if scope_glob and not _matches_scope_glob(f, scope_glob):
            continue
        out.add(f)
    return out


def collect_scalar_project(
    section_paths: tuple[str, ...],
    ctx: ParsedContext,
    *,
    scope_glob: Optional[str] = None,
    include_vendor: bool = False,
    include_tests: bool = False,
) -> list[str]:
    """Collect scalar `source_files` of the wave's sections.

    Recon-known trust-boundary config files (e.g. auth_layer→security.yaml,
    secrets→.env) must be routed unconditionally — otherwise they are
    enumerated by recon but never reach any worker's target_files, and
    catching their vulns silently depends on the model ranging beyond scope.

    Skips list-shape sections (they go through collect_files).
    """
    out: set[str] = set()
    for path in section_paths:
        out |= _filter_scalar_files(
            ctx.scalar_source_files(path),
            scope_glob=scope_glob,
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
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
# Checklist resolution (4-layer: core → stack → addons → integrations).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolutionContext:
    """Inputs for the 4-layer checklist resolver.

    - stack: e.g. "symfony"/"laravel"/"none"/"unknown"; "none"/"unknown" disable
      the stack and addons layers.
    - addons: alphabetically sorted, deduped (normalized in __post_init__).
    - integrations: alphabetically sorted, deduped (normalized in __post_init__).
    """
    stack: str
    addons: tuple[str, ...]
    integrations: tuple[str, ...]

    def __post_init__(self) -> None:
        # Normalize addons / integrations: drop non-strings, dedupe, sort.
        for field in ("addons", "integrations"):
            raw = getattr(self, field)
            normalized = tuple(sorted({x for x in raw if isinstance(x, str) and x}))
            object.__setattr__(self, field, normalized)


def resolve_checklists(
    themes: tuple[str, ...],
    ctx: ResolutionContext,
    plugin_root: Optional[Path],
) -> list[str]:
    """Return absolute checklist paths for the given themes & resolution ctx.

    Layout (4-layer; precedence increases with depth):
      1. checklists/core/{theme}.md
      2. checklists/stacks/{stack}/{theme}.md             — skip if stack ∈ {none, unknown}
      3. checklists/stacks/{stack}/addons/{addon}/{theme}.md
         — for each addon, alphabetical; skip if stack ∈ {none, unknown}
      4. checklists/integrations/{integration}/{theme}.md
         — for each integration, alphabetical; independent of stack

    Order per theme: core → stack → addons → integrations
    (i.e., less specific first; more specific layer overrides on conflict).
    Across themes: theme order is preserved (for each theme we append its full
    chain before moving to the next).

    Graceful skip: missing files are silently dropped — every layer is opt-in.
    plugin_root=None disables resolution entirely (returns []) — callers must
    pass an existing plugin root.
    """
    if plugin_root is None:
        return []
    root = plugin_root.resolve()
    cl = root / "checklists"
    out: list[str] = []
    stack_active = bool(ctx.stack) and ctx.stack not in ("none", "unknown")
    for t in themes:
        # 1. core.
        core = cl / "core" / f"{t}.md"
        if core.is_file():
            out.append(str(core))
        # 2. stack.
        if stack_active:
            stk = cl / "stacks" / ctx.stack / f"{t}.md"
            if stk.is_file():
                out.append(str(stk))
            # 3. addons (only if stack is active — addons live under stacks/{stack}/addons/).
            for addon in ctx.addons:
                ad = cl / "stacks" / ctx.stack / "addons" / addon / f"{t}.md"
                if ad.is_file():
                    out.append(str(ad))
        # 4. integrations (independent of stack).
        for integration in ctx.integrations:
            ig = cl / "integrations" / integration / f"{t}.md"
            if ig.is_file():
                out.append(str(ig))
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
    include_vendor: bool,
    include_tests: bool,
) -> list[str]:
    """List-shape items unioned with the wave's scalar source_files."""
    section_paths = tuple(resolved_section_paths(wave, ctx.stack))
    list_files = collect_files(
        section_paths,
        wave.relevant_kinds,
        ctx,
        scope_glob=scope_glob,
        include_vendor=include_vendor,
        include_tests=include_tests,
    )
    scalar_files = collect_scalar_project(
        section_paths,
        ctx,
        scope_glob=scope_glob,
        include_vendor=include_vendor,
        include_tests=include_tests,
    )
    if not scalar_files:
        return list_files
    return sorted(set(list_files) | set(scalar_files))


def _gap_target_files(
    recon_gaps: list[dict[str, Any]],
    taken: set[str],
    *,
    scope_glob: Optional[str],
    include_vendor: bool,
    include_tests: bool,
) -> list[str]:
    """Files for the WGAP wave: gap items in order, then path; capped.

    Files already routed to another slice are dropped — those workers see them
    anyway, and a second pass would only double the cost.
    """
    out: list[str] = []
    seen: set[str] = set(taken)
    for item in recon_gaps:
        raw = item.get("files")
        if not isinstance(raw, list):
            continue
        keep = _filter_scalar_files(
            [f for f in raw if isinstance(f, str) and f],
            scope_glob=scope_glob,
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        for f in sorted(keep):
            if f not in seen:
                seen.add(f)
                out.append(f)
    return out[:GAP_MAX_FILES]


def build_plan(
    ctx: ParsedContext,
    *,
    plugin_root: Optional[Path] = None,
    all_opus: bool = False,
    exploratory: bool = False,
    scope_glob: Optional[str] = None,
    include_vendor: bool = False,
    include_tests: bool = False,
    recon_gaps: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    plan: list[dict[str, Any]] = []
    stack = ctx.stack

    waves_to_run = [w for w in WAVES if should_trigger(w, ctx)]

    for wave in waves_to_run:
        model = wave.default_model if all_opus else wave.balanced_model
        files = _wave_target_files(
            wave, ctx,
            scope_glob=scope_glob,
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        if scope_glob and not files:
            continue
        entry_points = collect_entry_points(
            wave.entry_point_section_paths, wave.entry_point_kinds, ctx,
        )
        chunks = split_files(files, model)
        checklists = resolve_checklists(wave.themes, ctx.resolution_context, plugin_root)
        for idx, chunk in enumerate(chunks, start=1):
            plan.append({
                "slice_id": f"{wave.wave_id}_PART{idx}",
                "wave_id": wave.wave_id,
                "themes": list(wave.themes),
                "checklists": checklists,
                "relevant_section_paths": resolved_section_paths(wave, stack),
                "entry_points_in_scope": entry_points,
                "target_files": chunk,
                "model": model,
                "mode": "project",
            })

    if exploratory:
        wave = EXPLORATORY_WAVE
        model = wave.default_model if all_opus else wave.balanced_model
        files = _wave_target_files(
            wave, ctx,
            scope_glob=scope_glob,
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        # Anchor entry points: own + union of all focused waves'.
        own = set(collect_entry_points(
            wave.entry_point_section_paths, wave.entry_point_kinds, ctx,
        ))
        focused: set[str] = set()
        for s in plan:
            focused.update(s.get("entry_points_in_scope", []))
        all_eps = sorted(own | focused)
        # Exploratory loads the union of all themes' checklists.
        checklists = resolve_checklists(wave.themes, ctx.resolution_context, plugin_root)

        # target_files=[] is a valid signal: exploratory ranges over context
        # via `relevant_section_paths`.
        chunks = split_files(files, model, limit_override=WINF_SPLIT) or [[]]
        for idx, chunk in enumerate(chunks, start=1):
            plan.append({
                "slice_id": f"WINF_PART{idx}",
                "wave_id": wave.wave_id,
                "themes": list(wave.themes),
                "checklists": checklists,
                "relevant_section_paths": resolved_section_paths(wave, stack),
                "entry_points_in_scope": all_eps,
                "target_files": chunk,
                "model": model,
                "mode": "project",
            })

    if recon_gaps:
        wave = GAP_WAVE
        taken = {f for s in plan for f in s["target_files"]}
        files = _gap_target_files(
            recon_gaps, taken,
            scope_glob=scope_glob,
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        if files:
            checklists = resolve_checklists(wave.themes, ctx.resolution_context, plugin_root)
            for idx, chunk in enumerate(split_files(files, wave.balanced_model), start=1):
                plan.append({
                    "slice_id": f"{wave.wave_id}_PART{idx}",
                    "wave_id": wave.wave_id,
                    "themes": list(wave.themes),
                    "checklists": checklists,
                    "relevant_section_paths": resolved_section_paths(wave, stack),
                    "entry_points_in_scope": list(chunk),
                    "target_files": chunk,
                    "model": wave.balanced_model,
                    "mode": "project",
                })

    return plan


def read_recon_gaps(path: Path) -> list[dict[str, Any]]:
    """Items of a recon_gaps.json; [] for a missing, unreadable or foreign file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        print(f"Warning: ignoring unreadable {path}: {exc}", file=sys.stderr)
        return []
    if not isinstance(data, dict) or data.get("schema_version") != RECON_GAPS_SCHEMA_VERSION:
        print(
            f"Warning: ignoring {path}: unsupported schema_version "
            f"{data.get('schema_version') if isinstance(data, dict) else None!r}",
            file=sys.stderr,
        )
        return []
    items = data.get("items")
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict)]


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


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
    parser.add_argument(
        "--recon-gaps", type=Path, default=None,
        help="recon_gaps.json written by validate_context.py --gaps-out. "
             "Default: recon_gaps.json next to the CONTEXT.md argument. Absent "
             "or empty → no WGAP wave.",
    )
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
    args = parser.parse_args(argv)

    plugin_root = args.plugin_root or _default_plugin_root()

    try:
        ctx = parse_context(args.context)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    gaps_path = args.recon_gaps or args.context.parent / "recon_gaps.json"
    recon_gaps = read_recon_gaps(gaps_path)

    plan = build_plan(
        ctx,
        plugin_root=plugin_root,
        all_opus=args.all_opus,
        exploratory=args.exploratory,
        scope_glob=args.scope_glob,
        include_vendor=args.include_vendor,
        include_tests=args.include_tests,
        recon_gaps=recon_gaps,
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
