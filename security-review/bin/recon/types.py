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
SectionStatus = Literal["ok", "partial", "unknown", "none", "pending_enrichment"]


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
    """Output of recipe.build_inventory().

    `recon_bags` shape: `{kind: {name: {bag_key: SectionPayload}}}`.
    `kind` is one of {"stack", "addon", "integration"}. `name` is the
    stack/addon/integration identifier (e.g. "symfony", "easyadmin").
    Empty kind / name dicts are allowed and dropped at emit time.

    `detected_addons` (Stage 1+): sorted list of addon names that the recipe
    confirmed are present in the project (e.g. ["easyadmin", "sonata"]).
    The utility (`recon_inventory`) propagates this into
    `frontmatter.stack.addons`, which drives addon-layer checklist
    resolution in plan_waves. Recipes that have no addon concept return
    an empty list.

    `detected_integrations` (Stage 4+): sorted list of integration names that
    the recipe confirmed are present (e.g. ["jwt-generic", "oauth-oidc"]).
    Mirrors `detected_addons` but for vendor-neutral cross-stack integrations.
    Propagated by `recon_inventory` into `frontmatter.stack.integrations`,
    which drives integration-layer checklist resolution in plan_waves.
    Integrations are independent of the stack — they activate even on a
    generic / unknown stack. Recipes that detect no integrations return an
    empty list.
    """

    status: InventoryStatus
    core: dict[str, SectionPayload] = field(default_factory=dict)
    recon_bags: dict[str, dict[str, dict[str, SectionPayload]]] = field(default_factory=dict)
    sources_used: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    missing_sections: list[str] = field(default_factory=list)
    detected_addons: list[str] = field(default_factory=list)
    detected_integrations: list[str] = field(default_factory=list)


@dataclass
class SanityProbe:
    """One sanity check: glob filesystem and compare to declared section.

    section_path supports dot-notation:
      "attack_surface" or "recon_bags.stack.symfony.voters".
    kind_filter (optional) filters declared items by `kind` for attack_surface.
    It accepts either a single kind string or a tuple of kinds — a tuple matches
    items whose `kind` is any member (e.g. HTTP controllers span both
    `http_route` and `http_route_admin`, so declaring both keeps EasyAdmin
    controllers from reading as coverage gaps).
    content_filter (optional) is a regex; when set, only files whose
    text matches are counted as filesystem matches. Used to disambiguate
    name-based collisions (e.g. *Command.php matches both Symfony Console
    commands and DDD/CQRS Command DTOs — the regex narrows to real CLI).
    coverage: when False, only the hallucination check runs (declared files
    must exist on disk) and the filesystem-coverage ratio is skipped. Use for
    sections whose membership is a semantic subset the glob cannot reproduce —
    e.g. sensitive_columns lists only entities with a sensitively-NAMED column,
    so a filename glob over all entities is not a meaningful coverage universe.
    """

    section_path: str
    glob_patterns: list[str]
    label: str
    kind_filter: Optional[str | tuple[str, ...]] = None
    content_filter: Optional[str] = None
    coverage: bool = True


@dataclass
class StackMatch:
    """Output of recipe.detect()."""

    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Section shape spec — used by recipe RECON_BAGS_SCHEMA.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SectionSpec:
    """Closed shape of one bag-section.

    shape: "list" or "scalar".
    item_keys (for list-shape): set of allowed keys per item.
    data_keys (for scalar-shape): set of allowed keys in data dict.
    required: must be present in build_inventory output (status=ok / partial / unknown / none / pending_enrichment).
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
