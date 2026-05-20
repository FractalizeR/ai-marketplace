"""Typed dataclasses for recipe contract (schema v2).

These types form the API surface between recipes and recon_inventory utility.
Validator imports them too for shape checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

# ---------------------------------------------------------------------------
# Status enums.
# ---------------------------------------------------------------------------

InventoryStatus = Literal["ok", "partial", "failed"]
SectionStatus = Literal["ok", "unknown", "none", "pending_enrichment"]


# ---------------------------------------------------------------------------
# Inventory dataclasses.
# ---------------------------------------------------------------------------


@dataclass
class SectionPayload:
    """One section of CONTEXT.md.

    Either `items` (list-shape) or `data` (scalar-shape) is populated, not both.
    `source_files` is required for scalar sections (rev 3.4 mode=changes channel 2).
    """

    status: SectionStatus
    items: Optional[list[dict]] = None
    data: Optional[dict] = None
    reason: Optional[str] = None
    enrichment_hint: Optional[str] = None
    source_files: Optional[list[str]] = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class InventoryResult:
    """Output of recipe.build_inventory()."""

    status: InventoryStatus
    core: dict[str, SectionPayload] = field(default_factory=dict)
    framework_specific: dict[str, SectionPayload] = field(default_factory=dict)
    sources_used: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    missing_sections: list[str] = field(default_factory=list)


@dataclass
class SanityProbe:
    """One sanity check: glob filesystem and compare to declared section.

    section_path supports dot-notation:
      "attack_surface" or "framework_specific.symfony.voters".
    kind_filter (optional) filters items by `kind` for attack_surface.
    content_filter (optional) is a regex; when set, only files whose
    text matches are counted as filesystem matches. Used to disambiguate
    name-based collisions (e.g. *Command.php matches both Symfony Console
    commands and DDD/CQRS Command DTOs — the regex narrows to real CLI).
    """

    section_path: str
    glob_patterns: list[str]
    label: str
    kind_filter: Optional[str] = None
    content_filter: Optional[str] = None


@dataclass
class StackMatch:
    """Output of recipe.detect()."""

    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Section shape spec — used by recipe FRAMEWORK_SPECIFIC_SCHEMA.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SectionSpec:
    """Closed shape of one bag-section.

    shape: "list" or "scalar".
    item_keys (for list-shape): set of allowed keys per item.
    data_keys (for scalar-shape): set of allowed keys in data dict.
    required: must be present in build_inventory output (status=ok / unknown / none / pending_enrichment).
    """

    shape: Literal["list", "scalar"]
    item_keys: Optional[frozenset[str]] = None
    data_keys: Optional[frozenset[str]] = None
    required: bool = True


# ---------------------------------------------------------------------------
# Path safety — utility used by extractor wrappers.
# ---------------------------------------------------------------------------


class PathOutsideProjectRoot(ValueError):
    """Raised when a recipe/utility tries to access a path outside project_root."""


def assert_inside_project(path: Path, project_root: Path) -> Path:
    """Resolve both paths, ensure path is under project_root, return resolved path.

    Symlinks inside project_root are followed. macOS /var → /private/var case
    is handled because Path.resolve() resolves symlinks on both sides.
    """
    resolved = path.resolve()
    root_resolved = project_root.resolve()
    if not resolved.is_relative_to(root_resolved):
        raise PathOutsideProjectRoot(
            f"Path {path} resolves to {resolved}, which is outside project_root {root_resolved}"
        )
    return resolved
