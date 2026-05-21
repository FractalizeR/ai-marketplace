"""API Platform addon detector (Stage 2).

Exports:
- detect_api_platform(project_root): True/False from composer dependency probe
  OR presence of `config/packages/api_platform.yaml|php`. Used by
  `symfony.build_inventory` to decide whether to add `"api-platform"` to
  `frontmatter.stack.addons` (drives addon-layer checklist loading).
- collect_api_platform_resources(...): the bag collector. Currently returns
  `status="unknown"` because the `api-platform-resources` extractor is not
  implemented yet. The bag shape is wired so the extractor can land later
  without changing the inventory contract.

The PHP-side enumeration will eventually run through `recon.sandbox.run_extractor`
with the `api-platform-resources` extractor; see `_detect.md` in the addon
checklist tree for the gap description.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

API Platform v4 transition: package was renamed `api-platform/core` →
`api-platform/symfony` for the Symfony-specific bundle. We detect both so
projects on either v3.x or v4.x activate the addon. Note: the GraphQL
detection layer (`recon.graphql_detect`) only knows about `api-platform/core`
for now; that's a separate concern (graphql_layer scalar) and not gated by
this detector.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from recon.recipes._shared import EXCLUDE_PATHS, is_excluded, to_relative
from recon.types import SectionPayload


# Composer package names that gate API Platform detection.
# Both v3.x (`api-platform/core`) and v4.x (`api-platform/symfony`) variants.
API_PLATFORM_PACKAGES: tuple[str, ...] = (
    "api-platform/core",
    "api-platform/symfony",
)


def detect_api_platform(project_root: Path) -> bool:
    """Return True iff any API Platform signal is present.

    Signals (any one is enough):
    1. composer.json `require`/`require-dev` contains `api-platform/core` or
       `api-platform/symfony` (v4 split package).
    2. `config/packages/api_platform.yaml` exists.
    3. `config/packages/api_platform.php` exists (less common but supported
       in modern Symfony Flex setups).

    Cheap composer probe — doesn't parse PHP, doesn't list ApiResources.
    Stack recipe calls this to decide whether to declare `api-platform` as a
    stack addon (drives addon-layer checklist resolution in plan_waves).
    Heavier enumeration (ApiResource classes, operations) lives in
    `collect_api_platform_resources` once the extractor lands.
    """
    composer = project_root / "composer.json"
    if composer.is_file():
        try:
            data = json.loads(composer.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None
        if isinstance(data, dict):
            for section in ("require", "require-dev"):
                deps = data.get(section)
                if not isinstance(deps, dict):
                    continue
                for pkg in API_PLATFORM_PACKAGES:
                    if pkg in deps:
                        return True

    # Config-file fallback: a Symfony Flex install may pin a meta-package
    # while still wiring api_platform.yaml. Either yaml or php config file
    # is a positive signal.
    if (project_root / "config" / "packages" / "api_platform.yaml").is_file():
        return True
    if (project_root / "config" / "packages" / "api_platform.php").is_file():
        return True
    return False


def collect_api_platform_resources(
    project_root: Path,
    plugin_root: Path,
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> SectionPayload:
    """ApiResource classes — entity FQCN + per-operation security/groups/filters.

    The PHP extractor `api-platform-resources` is not yet implemented. The bag
    shape is fixed here so the extractor can land in a follow-up PR without
    renaming keys. Status semantics:

    * `none`    — API Platform is not in composer / config (no work to do).
    * `unknown` — API Platform is detected but we have no extractor (placeholder).
                  Drives `inventory.status=partial` so the worker is alerted
                  that the bag is intentionally empty pending extractor work.

    Planned bag schema (see `addons/api-platform/_detect.md`):
        items[*]: {
            class: FQCN,
            file: src/...,
            line: int,
            operations: [
                {
                    verb: Get | GetCollection | Post | Patch | Put | Delete,
                    security: <expr> | null,
                    security_post_denormalize: <expr> | null,
                    normalization_groups: [str],
                    denormalization_groups: [str],
                    pagination_max: int | null,
                    filters: [str],
                },
                ...
            ],
            graphql_enabled: bool,
        }

    Until the extractor lands, the checklist works in graceful-fallback mode
    via grep on `#[ApiResource` — see `addons/api-platform/auth.md`.
    """
    # `plugin_root`, `warnings`, and `exclude` are accepted for signature
    # parity with the future implementation (mirroring easyadmin/sonata).
    # They're not used yet — referenced below to keep linters quiet.
    _ = (plugin_root, warnings, exclude)
    # Path helpers imported to stay in lockstep with the easyadmin/sonata
    # collectors — the eventual implementation will use them on extractor
    # output to relativize file paths and apply EXCLUDE_PATHS.
    _ = (EXCLUDE_PATHS, is_excluded, to_relative)
    if not detect_api_platform(project_root):
        return SectionPayload(
            status="none",
            reason="api-platform not detected (composer + config)",
        )
    return SectionPayload(
        status="unknown",
        reason=(
            "api-platform-resources extractor not yet implemented; bag wired "
            "with placeholder. Checklists fall back to grep on #[ApiResource]."
        ),
    )
