"""generic_php recipe — fallback when no stack-specific recipe scores ≥ 0.7.

Used for projects with composer.json / *.php files but no recognizable
framework markers (Slim, Phalcon, raw PSR-15, custom MVC).

S1 stub: detect logic + minimal sanity probes + skeleton build_inventory.
Real fleshing-out is deferred (out of S1 scope).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from recon.types import (
    InventoryResult,
    SectionPayload,
    SectionSpec,
    SanityProbe,
    StackMatch,
)

RECIPE_NAME = "generic_php"
LANGUAGE = "php"

# No stack-specific bag for generic recipe.
FRAMEWORK_SPECIFIC_SCHEMA: dict[str, SectionSpec] = {}

# Note: NO `var/` excluded here — generic projects may use var/ for sources.
EXCLUDE_PATHS: tuple[str, ...] = (
    "vendor/", "node_modules/", "tests/", "test/", "Tests/", "Test/", "*.min.js",
)


# ---------------------------------------------------------------------------
# Detect: floor for "looks like a PHP project at all".
# ---------------------------------------------------------------------------


def detect(project_root: Path) -> Optional[StackMatch]:
    """Return a baseline confidence based on PHP signals.

    - composer.json present → 0.5
    - any *.php file (top 2 levels) → +0.3 (capped at 0.8)
    - both → 0.8
    Returns None if neither signal triggers.

    Caller (recipes registry) treats this as a fallback: stack-specific
    recipes win above 0.7; generic_php is consulted only when no stack
    scores ≥ 0.7.
    """
    score = 0.0
    evidence = []

    if (project_root / "composer.json").is_file():
        score += 0.5
        evidence.append("composer.json")

    if _has_php_file(project_root):
        score += 0.3
        evidence.append("*.php files")

    if score == 0.0:
        return None
    return StackMatch(name="generic_php", confidence=score, evidence=evidence)


def _has_php_file(project_root: Path, max_depth: int = 3) -> bool:
    """Cheap check: are there *.php files within max_depth levels?"""
    if not project_root.is_dir():
        return False
    try:
        # Top-level scan first (cheap).
        for entry in project_root.iterdir():
            if entry.is_file() and entry.suffix == ".php":
                return True
        # Then bounded recursion.
        for entry in project_root.rglob("*.php"):
            if "vendor" in entry.parts or "node_modules" in entry.parts:
                continue
            return True
    except (OSError, PermissionError):
        return False
    return False


def sanity_probes() -> list[SanityProbe]:
    return [
        SanityProbe(
            section_path="data_access",
            glob_patterns=["src/**/*Repository.php", "app/**/*Repository.php"],
            label="Repository classes",
        ),
    ]


CORE_SECTION_IDS = (
    "attack_surface", "data_access", "auth_layer", "authz_usage",
    "output_renderers", "serialization", "file_operations", "http_clients",
    "secrets", "fintech_markers", "frontend_assets",
)


def build_inventory(
    project_root: Path,
    diff_files: Optional[set[str]] = None,
    *,
    plugin_root: Optional[Path] = None,
    no_console: bool = False,
    exclude: Optional[tuple[str, ...]] = None,
) -> InventoryResult:
    """STUB — emits skeleton with all sections in pending_enrichment.

    Real population for generic_php is out of S2 scope; the kwargs
    `plugin_root` / `no_console` / `exclude` are accepted to keep the
    contract uniform across recipes.
    """
    del plugin_root, no_console, exclude  # unused in stub
    scalar_core = {"auth_layer", "secrets"}
    core: dict[str, SectionPayload] = {}
    for sid in CORE_SECTION_IDS:
        is_scalar = sid in scalar_core
        core[sid] = SectionPayload(
            status="pending_enrichment",
            enrichment_hint=f"S1 stub: {sid} not yet collected for generic_php.",
            items=None if is_scalar else [],
            data=None,
            source_files=[] if is_scalar else None,
        )
    return InventoryResult(
        status="partial",
        core=core,
        framework_specific={},
        sources_used=["recipe_stub:generic_php"],
        warnings=["s1_stub_recipe: generic_php build_inventory returns skeleton only"],
    )
